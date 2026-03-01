"""FTP extractor — connects and reads server banner, tests anonymous login."""

import socket


class FTPExtractor:
    """Attempts to fingerprint an open FTP port and test for anonymous access."""

    def __init__(self, ip: str, port: int = 21):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): FTP port, default 21.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Connect to FTP, read banner, and attempt anonymous login.
        
        Returns:
            dict: Status, banner, and whether anonymous login succeeded.
        """
        print(f"  [FTP] Connecting to {self.ip}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            print(f"  [FTP] Banner: {banner}")

            anon = self._try_anonymous(sock)
            sock.close()

            return {'status': 'open', 'banner': banner, 'anonymous_access': anon}
        except Exception as e:
            print(f"  [FTP] Failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def _try_anonymous(self, sock: socket.socket) -> bool:
        """Attempt anonymous FTP login using 'anonymous' / 'anonymous@'.

        Args:
            sock (socket.socket): Already-connected socket.

        Returns:
            bool: True if anonymous login succeeded, False otherwise.
        """
        try:
            sock.send(b'USER anonymous\r\n')
            resp = sock.recv(1024).decode('utf-8', errors='ignore')
            if '331' in resp:  # 331 = password required, anonymous user accepted
                sock.send(b'PASS anonymous@\r\n')
                resp = sock.recv(1024).decode('utf-8', errors='ignore')
                if '230' in resp:  # 230 = login successful
                    print(f"  [FTP] CRITICAL — anonymous login succeeded")
                    return True
            print(f"  [FTP] Anonymous login denied")
            return False
        except Exception:
            return False
