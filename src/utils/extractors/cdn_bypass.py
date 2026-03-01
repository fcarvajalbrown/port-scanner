"""CDN bypass detector — identifies Cloudflare-proxied IPs and attempts to find the real origin."""

import socket
import ssl
import re


CLOUDFLARE_RANGES = [
    '103.21.', '103.22.', '103.31.', '104.16.', '104.17.', '104.18.', '104.19.',
    '104.20.', '104.21.', '104.22.', '104.24.', '104.25.', '104.26.', '104.27.',
    '108.162.', '131.0.', '141.101.', '162.158.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.',
    '172.71.', '188.114.', '190.93.', '197.234.', '198.41.',
]

# Common subdomains that may bypass CDN and point to origin
BYPASS_SUBDOMAINS = [
    'direct', 'origin', 'mail', 'ftp', 'smtp', 'pop', 'imap',
    'cpanel', 'whm', 'webmail', 'admin', 'dev', 'staging', 'api',
]


class CDNBypassDetector:
    """Detects if a target is behind Cloudflare and attempts to find the real origin IP."""

    def __init__(self, ip: str, port: int, host: str):
        """Initialize with target IP, port and original hostname.

        Args:
            ip (str): Resolved IP address (possibly Cloudflare).
            port (int): Open port (unused here but kept for router interface consistency).
            host (str): Original domain name.
        """
        self.ip = ip
        self.port = port
        self.host = host

    def run(self):
        """Check if IP is Cloudflare, then attempt origin discovery.

        Returns:
            dict: Detection results including origin IP if found.
        """
        if not self._is_cloudflare(self.ip):
            print(f"  [CDN] {self.host} is not behind Cloudflare — skipping bypass")
            return {'cdn': False}

        print(f"  [CDN] {self.host} ({self.ip}) is behind Cloudflare — attempting bypass")

        origin = None

        # Method 1: SSL certificate subject alternative names
        origin = origin or self._check_ssl_cert()

        # Method 2: subdomain enumeration
        origin = origin or self._check_subdomains()

        # Method 3: HTTP header leaks
        origin = origin or self._check_http_headers()

        # Method 4: MX record / mail subdomain lookup
        origin = origin or self._check_mx()

        if origin:
            print(f"  [CDN] Origin IP found: {origin}")
        else:
            print(f"  [CDN] Could not determine origin IP")

        return {
            'cdn': True,
            'cdn_provider': 'Cloudflare',
            'cdn_ip': self.ip,
            'origin_ip': origin,
        }

    def _is_cloudflare(self, ip: str) -> bool:
        """Check if an IP belongs to a known Cloudflare range.

        Args:
            ip (str): IP address to check.

        Returns:
            bool: True if IP is a Cloudflare address.
        """
        return any(ip.startswith(prefix) for prefix in CLOUDFLARE_RANGES)

    def _check_ssl_cert(self) -> str | None:
        """Attempt TLS connection and extract IPs from the SSL certificate SANs.

        Returns:
            str | None: Origin IP if found in cert, otherwise None.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    sans = cert.get('subjectAltName', [])
                    for san_type, san_value in sans:
                        if san_type == 'IP Address' and not self._is_cloudflare(san_value):
                            print(f"  [CDN] Found non-Cloudflare IP in SSL cert SAN: {san_value}")
                            return san_value
        except Exception as e:
            print(f"  [CDN] SSL cert check failed: {e}")
        return None

    def _check_subdomains(self) -> str | None:
        """Try resolving common subdomains that may bypass CDN proxy.

        Returns:
            str | None: First non-Cloudflare IP found, otherwise None.
        """
        base = self.host.lstrip('www.')
        for sub in BYPASS_SUBDOMAINS:
            candidate = f"{sub}.{base}"
            try:
                ip = socket.gethostbyname(candidate)
                if not self._is_cloudflare(ip):
                    print(f"  [CDN] Subdomain {candidate} resolves to non-Cloudflare IP: {ip}")
                    return ip
            except socket.gaierror:
                pass
        return None

    def _check_http_headers(self) -> str | None:
        """Probe HTTP/HTTPS response headers for origin IP leaks.

        Returns:
            str | None: First leaked non-Cloudflare IP found, otherwise None.
        """
        from src.utils.extractors.http_headers import HTTPHeaderLeakDetector
        detector = HTTPHeaderLeakDetector(host=self.host)
        result = detector.run()
        leaked = result.get('leaked_headers', {})
        if leaked:
            return next(iter(leaked.values()))
        return None

    def _check_mx(self) -> str | None:
        """Probe mail subdomains for non-Cloudflare IPs that may reveal origin.

        Returns:
            str | None: First non-Cloudflare mail IP found, otherwise None.
        """
        from src.utils.extractors.mx_lookup import MXLookup
        lookup = MXLookup(host=self.host)
        result = lookup.run()
        mail_ips = result.get('mail_ips', {})
        if mail_ips:
            return next(iter(mail_ips.values()))
        return None