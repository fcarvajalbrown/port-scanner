"""Extractor router — reads scan results, dispatches extractors, and re-scans origin IPs if CDN bypass found."""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ExtractorRouter:
    """Routes open ports to their corresponding extractor modules and handles CDN bypass re-scanning."""

    def __init__(self, results: dict, scanner=None):
        """Initialize router with scan results and optional scanner reference for re-scanning.

        Args:
            results (dict): The results dict from PortScanner, keyed by domain_id.
            scanner (PortScanner): Scanner instance used to re-scan discovered origin IPs.
        """
        self.results = results
        self.scanner = scanner

    def run(self):
        """Iterate all targets, run CDN bypass first, then dispatch service extractors."""
        for domain_id, data in list(self.results.items()):
            ip = data['ip']
            host = data['host']
            print(f"\n[ROUTER] Checking extractors for {host} ({ip})")

            # Always run CDN bypass check first
            self._run_cdn_bypass(domain_id, ip, host)

            # Then dispatch per open port
            for port_entry in data['open_ports']:
                port = port_entry['port']
                service = port_entry['service']
                self._dispatch(domain_id, ip, port, service)

    def _run_cdn_bypass(self, domain_id, ip, host):
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

    def _dispatch(self, domain_id, ip, port, service):
        """Call the appropriate extractor based on service name.

        Args:
            domain_id (str): Target identifier.
            ip (str): Target IP.
            port (int): Open port number.
            service (str): Service label from scanner (e.g. 'MySQL').
        """
        from src.utils.extractors.mysql import MySQLExtractor
        from src.utils.extractors.postgres import PostgresExtractor
        from src.utils.extractors.ftp import FTPExtractor

        from src.utils.extractors.ssh import SSHExtractor

        extractors = {
            'MySQL':      MySQLExtractor,
            'PostgreSQL': PostgresExtractor,
            'FTP':        FTPExtractor,
            'SSH':        SSHExtractor,
        }

        extractor_class = extractors.get(service)
        if extractor_class:
            print(f"  [MATCH] Port {port} ({service}) — launching extractor")
            extractor = extractor_class(ip, port)
            extractor.run()
        else:
            print(f"  [SKIP] Port {port} ({service}) — no extractor available")