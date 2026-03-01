"""MySQL extractor — fingerprints MySQL version and tests default credentials."""

import socket
import struct
import hashlib


# Common default/weak credentials to test
DEFAULT_CREDENTIALS = [
    ('root', ''),
    ('root', 'root'),
    ('root', 'password'),
    ('root', 'mysql'),
    ('root', 'admin'),
    ('admin', 'admin'),
    ('admin', ''),
    ('mysql', 'mysql'),
    ('mysql', ''),
    ('test', 'test'),
    ('test', ''),
]


class MySQLExtractor:
    """Fingerprints MySQL version and attempts login with default credentials."""

    def __init__(self, ip: str, port: int = 3306):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): MySQL port, default 3306.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Attempt TCP connection, read banner, then test default credentials.

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

        except Exception as e:
            print(f"  [MySQL] Banner failed: {e}")
            result['status'] = 'failed'
            return result

        # Test default credentials
        print(f"  [MySQL] Testing {len(DEFAULT_CREDENTIALS)} default credentials...")
        for username, password in DEFAULT_CREDENTIALS:
            cred_result = self._test_credential(username, password, salt)
            display = f"{username}:{password if password else '(empty)'}"
            if cred_result == 'success':
                print(f"  [MySQL] *** VALID CREDENTIAL FOUND: {display} ***")
                result['credentials'].append({'user': username, 'password': password, 'status': 'valid'})
            elif cred_result == 'wrong_password':
                print(f"  [MySQL] Invalid: {display}")
            else:
                print(f"  [MySQL] Error testing {display}: {cred_result}")

        return result

    def _parse_banner(self, banner: bytes):
        """Extract version string and auth salt from MySQL handshake packet.

        Args:
            banner (bytes): Raw bytes from MySQL server greeting.

        Returns:
            tuple: (version_string, salt_bytes)
        """
        try:
            payload = banner[4:]
            if payload[0] == 10:  # protocol v10
                version = payload[1:].split(b'\x00')[0].decode('utf-8', errors='ignore')
                # Salt is split: first 8 bytes after version+null, more after capability flags
                rest = payload[1 + len(version) + 1:]
                salt1 = rest[:8]
                # Skip: salt1(8) + filler(1) + capabilities(2) + charset(1) + status(2) + capabilities2(2) + auth_len(1) + reserved(10)
                salt2_offset = 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
                salt2 = rest[salt2_offset:salt2_offset + 12]
                salt = salt1 + salt2
                return version, salt
        except Exception:
            pass
        return 'unknown', b''

    def _test_credential(self, username: str, password: str, salt: bytes) -> str:
        """Attempt MySQL authentication with given credentials using native password hashing.

        Args:
            username (str): MySQL username to test.
            password (str): Password to test.
            salt (bytes): Auth salt from server handshake.

        Returns:
            str: 'success', 'wrong_password', or error message string.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            raw_banner = sock.recv(1024)

            # Re-parse salt fresh from this connection
            _, live_salt = self._parse_banner(raw_banner)
            if not live_salt:
                sock.close()
                return 'no_salt'

            auth_response = self._mysql_native_password(password, live_salt) if password else b''

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