"""PostgreSQL extractor — attempts connection and reads server banner."""

import socket
import struct


class PostgresExtractor:
    """Attempts to fingerprint an open PostgreSQL port via startup message."""

    def __init__(self, ip: str, port: int = 5432):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): PostgreSQL port, default 5432.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Send a PostgreSQL startup message and read the server response."""
        print(f"  [PostgreSQL] Connecting to {self.ip}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))

            # PostgreSQL startup message: length (4 bytes) + protocol version 3.0 (4 bytes)
            # + "user\0postgres\0\0"
            user_param = b'user\x00postgres\x00\x00'
            protocol = struct.pack('!I', 196608)  # 3.0
            message = protocol + user_param
            length = struct.pack('!I', len(message) + 4)
            sock.send(length + message)

            response = sock.recv(1024)
            sock.close()

            status = self._parse_response(response)
            print(f"  [PostgreSQL] Response: {status}")
            return {'status': 'open', 'response': status}
        except Exception as e:
            print(f"  [PostgreSQL] Failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def _parse_response(self, response: bytes) -> str:
        """Parse the first byte of PostgreSQL response to determine server state.

        Args:
            response (bytes): Raw server response bytes.

        Returns:
            str: Human-readable status string.
        """
        if not response:
            return 'no response'
        first_byte = chr(response[0])
        labels = {
            'R': 'authentication required',
            'E': 'error returned (access denied)',
            'S': 'server parameter status received',
        }
        return labels.get(first_byte, f'unknown response byte: {first_byte}')
