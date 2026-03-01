"""MX record lookup — resolves mail server IPs which often reveal the real origin behind a CDN."""

import socket


CLOUDFLARE_RANGES = [
    '103.21.', '103.22.', '103.31.', '104.16.', '104.17.', '104.18.', '104.19.',
    '104.20.', '104.21.', '104.22.', '104.24.', '104.25.', '104.26.', '104.27.',
    '108.162.', '131.0.', '141.101.', '162.158.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.',
    '172.71.', '188.114.', '190.93.', '197.234.', '198.41.',
]

# Common mail subdomains to probe when full DNS MX lookup isn't available
MAIL_SUBDOMAINS = [
    'mail', 'mx', 'mx1', 'mx2', 'smtp', 'email',
    'webmail', 'imap', 'pop', 'exchange',
]


class MXLookup:
    """Resolves mail-related subdomains to find non-Cloudflare IPs that may reveal origin."""

    def __init__(self, host: str):
        """Initialize with target hostname.

        Args:
            host (str): Domain name to probe.
        """
        self.host = host

    def run(self):
        """Probe common mail subdomains and return any non-Cloudflare IPs found.

        Returns:
            dict: Mail subdomains and their resolved IPs if not behind Cloudflare.
        """
        print(f"  [MX] Probing mail subdomains for {self.host}")
        base = self.host.lstrip('www.')
        found = {}

        for sub in MAIL_SUBDOMAINS:
            candidate = f"{sub}.{base}"
            try:
                ip = socket.gethostbyname(candidate)
                if not self._is_cloudflare(ip):
                    print(f"  [MX] {candidate} → {ip} (non-Cloudflare)")
                    found[candidate] = ip
                else:
                    print(f"  [MX] {candidate} → {ip} (Cloudflare, skipping)")
            except socket.gaierror:
                pass

        if not found:
            print(f"  [MX] No non-Cloudflare mail IPs found")

        return {'mail_ips': found}

    def _is_cloudflare(self, ip: str) -> bool:
        """Check if an IP belongs to a known Cloudflare range.

        Args:
            ip (str): IP address string.

        Returns:
            bool: True if Cloudflare IP.
        """
        return any(ip.startswith(prefix) for prefix in CLOUDFLARE_RANGES)