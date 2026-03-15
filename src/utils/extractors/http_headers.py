"""HTTP header leak detector — sends requests and inspects response headers for origin IP leaks."""

import socket
import ssl
import re


# Headers that sometimes leak real origin IPs
LEAK_HEADERS = [
    'X-Real-IP',
    'X-Forwarded-For',
    'X-Origin-IP',
    'X-Backend-Server',
    'X-Served-By',
    'X-Server',
    'X-Powered-By',
    'CF-Connecting-IP',
    'True-Client-IP',
    'X-Originating-IP',
    'X-Remote-IP',
    'X-Remote-Addr',
]

CLOUDFLARE_RANGES = [
    '103.21.', '103.22.', '103.31.', '104.16.', '104.17.', '104.18.', '104.19.',
    '104.20.', '104.21.', '104.22.', '104.24.', '104.25.', '104.26.', '104.27.',
    '108.162.', '131.0.', '141.101.', '162.158.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.',
    '172.71.', '188.114.', '190.93.', '197.234.', '198.41.',
]

IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


class HTTPHeaderLeakDetector:
    """Sends HTTP/HTTPS requests and inspects response headers for origin IP leaks."""

    def __init__(self, host: str):
        """Initialize with target hostname.

        Args:
            host (str): Domain name to probe.
        """
        self.host = host

    def run(self):
        """Probe HTTP and HTTPS endpoints and scan headers for IP leaks.

        Returns:
            dict: Any leaked IPs found and which headers contained them.
        """
        print(f"  [HTTP-LEAK] Probing headers for {self.host}")
        leaked = {}

        headers_http = self._fetch_headers(self.host, 80, tls=False)
        headers_https = self._fetch_headers(self.host, 443, tls=True)

        all_headers = {**headers_http, **headers_https}

        for header, value in all_headers.items():
            ips = IP_PATTERN.findall(value)
            for ip in ips:
                if not self._is_cloudflare(ip) and not ip.startswith('127.') and not ip.startswith('10.') and ip not in ('1.0.1.1', '1.1.1.1', '8.8.8.8', '8.8.4.4'):
                    print(f"  [HTTP-LEAK] Found IP in header '{header}': {ip}")
                    leaked[header] = ip

        if not leaked:
            print(f"  [HTTP-LEAK] No IP leaks found in headers")

        return {'leaked_headers': leaked}

    def _fetch_headers(self, host: str, port: int, tls: bool) -> dict:
        """Open a raw TCP connection and send a minimal HTTP request to retrieve response headers.

        Args:
            host (str): Target hostname.
            port (int): Port to connect to.
            tls (bool): Whether to wrap connection in TLS.

        Returns:
            dict: Parsed response headers as key-value pairs.
        """
        try:
            sock = socket.create_connection((host, port), timeout=5)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
                sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.settimeout(5)  # re-apply after TLS wrap

            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\r\n\r\n' in response:
                    break
            sock.close()

            return self._parse_headers(response.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"  [HTTP-LEAK] Connection to {host}:{port} failed: {e}")
            return {}

    def _parse_headers(self, raw: str) -> dict:
        """Parse raw HTTP response into a header dictionary.

        Args:
            raw (str): Raw HTTP response string.

        Returns:
            dict: Header name to value mapping.
        """
        headers = {}
        lines = raw.split('\r\n')
        for line in lines[1:]:  # skip status line
            if ':' in line:
                key, _, value = line.partition(':')
                headers[key.strip()] = value.strip()
            elif line == '':
                break
        return headers

    def _is_cloudflare(self, ip: str) -> bool:
        """Check if an IP belongs to a known Cloudflare range.

        Args:
            ip (str): IP address string.

        Returns:
            bool: True if Cloudflare IP.
        """
        return any(ip.startswith(prefix) for prefix in CLOUDFLARE_RANGES)