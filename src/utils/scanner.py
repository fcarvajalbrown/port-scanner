"""Port scanner module — resolves domains to IPs and scans for open ports concurrently."""

import configparser
import json
import os
import socket
import threading
import time
from datetime import datetime

from src.utils.extractors.router import ExtractorRouter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TOP_100_PORTS = [
    21, 22, 2222, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 194, 443, 445,
    465, 587, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2083, 2096, 3306,
    3389, 4333, 4444, 5000, 5432, 5900, 5985, 6379, 6667, 7070, 7443, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211,
    27017, 27018, 27019, 28017, 50000, 50070, 61616
]

PORT_LABELS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
    2222: 'SSH',
    2083: 'cPanel',
}

RISK_LABELS = {
    21: 'HIGH',
    23: 'CRITICAL',
    445: 'CRITICAL',
    1433: 'HIGH',
    1521: 'HIGH',
    3306: 'HIGH',
    3389: 'HIGH',
    5432: 'HIGH',
    5900: 'HIGH',
    6379: 'CRITICAL',
    9200: 'HIGH',
    27017: 'HIGH',
    2083: 'HIGH',
    2222: 'HIGH',
}


class PortScanner:
    """Resolves domains to IPs via DNS and concurrently scans ports, exporting results as JSON."""

    def __init__(self, port_mode='top100'):
        """Initialize scanner with config and port mode.

        Args:
            port_mode (str): 'top100' or 'full' — determines which ports to scan.
        """
        self.config = self._load_config()
        self.domains = self._load_domains()
        self.port_mode = port_mode
        self.timeout = float(self.config['Scanner']['timeout_seconds'])
        self.max_threads = int(self.config['Scanner']['max_threads'])
        self.results = {}
        self.lock = threading.Lock()
        self.scan_delay = float(self.config['Scanner']['scan_delay_seconds'])

    def _load_config(self):
        """Load settings from config/settings.ini."""
        config_path = os.path.join(BASE_DIR, '..', '..', 'config', 'settings.ini')
        config = configparser.ConfigParser()
        config.read(config_path)
        return config

    def _load_domains(self):
        """Load domain list from config/domains.json."""
        domains_path = os.path.join(BASE_DIR, '..', '..', 'config', 'domains.json')
        with open(domains_path, 'r') as f:
            return json.load(f)['domains']

    def _resolve_domain(self, domain):
        """Resolve a domain name to its IP address via DNS.

        Args:
            domain (dict): Domain entry with 'id' and 'host' keys.

        Returns:
            tuple: (domain_id, host, ip) or (domain_id, host, None) if resolution fails.
        """
        try:
            ip = socket.gethostbyname(domain['host'])
            print(f"[DNS] {domain['host']} → {ip}")
            return domain['id'], domain['host'], ip
        except socket.gaierror as e:
            print(f"[DNS] FAILED to resolve {domain['host']}: {e}")
            return domain['id'], domain['host'], None

    def _scan_port(self, ip, port, results_bucket):
        """Attempt TCP connection to a single port and record if open.

        Args:
            ip (str): Target IP address.
            port (int): Port number to scan.
            results_bucket (list): Shared list to append open port info to.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                label = PORT_LABELS.get(port, 'Unknown')
                risk = RISK_LABELS.get(port, 'LOW')
                with self.lock:
                    results_bucket.append({'port': port, 'service': label, 'risk': risk})
                print(f"  [{risk}] Port {port} ({label}) — OPEN")
        except Exception:
            pass

    def _scan_target(self, domain_id, host, ip):
        """Scan all selected ports on a resolved IP using a thread pool.

        Args:
            domain_id (str): Identifier from config.
            host (str): Original domain name.
            ip (str): Resolved IP address.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        ports = TOP_100_PORTS if self.port_mode == 'top100' else list(range(1, 65536))
        mode_label = 'TOP 100' if self.port_mode == 'top100' else 'FULL (1-65535)'
        print(f"\n[SCAN] {host} ({ip}) — {mode_label}")

        open_ports = []

        print(f"[DEBUG] Scanning {len(ports)} ports with {self.max_threads} workers...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, ip, port, open_ports): port for port in ports}
            for future in as_completed(futures):
                future.result()

        print(f"[DEBUG] Done. Open ports: {len(open_ports)}")
        self.results[domain_id] = {
            'host': host,
            'ip': ip,
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'scanned_at': datetime.utcnow().isoformat() + 'Z',
        }

    def _export_json(self):
        """Write scan results to reports/results.json."""
        reports_path = os.path.join(BASE_DIR, '..', '..', 'reports', 'results.json')
        os.makedirs(os.path.dirname(reports_path), exist_ok=True)
        with open(reports_path, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[EXPORT] Results saved to reports/results.json")

    def _export_csv(self):
            """Append scan results to reports/results.csv without overwriting previous runs."""
            import csv

            csv_path = os.path.join(BASE_DIR, '..', '..', 'reports', 'results.csv')
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)

            file_exists = os.path.isfile(csv_path)

            with open(csv_path, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['scan_time', 'domain_id', 'host', 'ip', 'port', 'service', 'risk'])
                for domain_id, data in self.results.items():
                    for entry in data['open_ports']:
                        writer.writerow([
                            data['scanned_at'],
                            domain_id,
                            data['host'],
                            data['ip'],
                            entry['port'],
                            entry['service'],
                            entry['risk'],
                        ])

            print(f"[EXPORT] Results appended to reports/results.csv")

    def _print_summary(self):
        """Print a final summary table of all open ports per target."""
        print("\n===== SCAN SUMMARY =====")
        for domain_id, data in self.results.items():
            print(f"\n[{domain_id}] {data['host']} ({data['ip']})")
            if not data['open_ports']:
                print("  No open ports found.")
            for entry in data['open_ports']:
                print(f"  Port {entry['port']:>5} ({entry['service']:<15}) — {entry['risk']}")

    def run(self):
        """Resolve all domains, scan each, print summary, export JSON and run extractors."""
        print("===== DNS RESOLUTION =====")
        resolved = []
        for domain in self.domains:
            domain_id, host, ip = self._resolve_domain(domain)
            if ip:
                resolved.append((domain_id, host, ip))

        for i, (domain_id, host, ip) in enumerate(resolved):
            self._scan_target(domain_id, host, ip)
            if i < len(resolved) - 1:  # don't delay after last target
                time.sleep(self.scan_delay)

        self._print_summary()
        self._export_json()
        self._export_csv()

        router = ExtractorRouter(self.results, scanner=self)
        router.run()
