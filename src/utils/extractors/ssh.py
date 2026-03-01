"""SSH brute force extractor — fingerprints SSH server and tests default credentials."""

from datetime import time
import socket


# Common default/weak SSH credentials
DEFAULT_CREDENTIALS = [
    ('root', ''),
    ('root', 'root'),
    ('root', 'password'),
    ('root', 'admin'),
    ('root', 'toor'),
    ('root', '123456'),
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', ''),
    ('ubuntu', 'ubuntu'),
    ('ubuntu', ''),
    ('debian', 'debian'),
    ('user', 'user'),
    ('user', 'password'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('pi', 'raspberry'),
    ('oracle', 'oracle'),
    ('postgres', 'postgres'),
    ('mysql', 'mysql'),
    # cPanel/WHM hosting defaults (common in Chilean shared hosting)
    ('cpanel', 'cpanel'),
    ('cpanel', ''),
    ('whm', 'whm'),
    ('webmaster', 'webmaster'),
    ('webmaster', ''),
    ('ftp', 'ftp'),
    ('ftp', ''),
    ('www', 'www'),
    ('www', ''),
    # Common Spanish-language weak passwords
    ('root', 'clave'),
    ('root', 'contrasena'),
    ('root', 'servidor'),
    ('admin', 'clave'),
    ('admin', '1234'),
    ('root', '1234'),
    ('root', '12345678'),
    ('usuario', 'usuario'),
    ('usuario', '1234'),
    # Common vendor defaults seen in LATAM deployments
    ('support', 'support'),
    ('support', ''),
    ('deploy', 'deploy'),
    ('ansible', 'ansible'),
]


class SSHExtractor:
    """Fingerprints SSH server version and attempts login with default credentials."""

    def __init__(self, ip: str, port: int = 22):
        """Initialize with target IP and port.

        Args:
            ip (str): Target IP address.
            port (int): SSH port, default 22.
        """
        self.ip = ip
        self.port = port

    def run(self):
        """Connect to SSH, read banner, then test default credentials.

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
            print(f"  [SSH] Skipping credential tests")
            result['status'] = 'no_paramiko'
            return result

        print(f"  [SSH] Testing {len(DEFAULT_CREDENTIALS)} default credentials...")
        for username, password in DEFAULT_CREDENTIALS:
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

        Args:
            username (str): SSH username to test.
            password (str): Password to test.

        Returns:
            str: 'success', 'auth_failed', or error message string.
        """
        import paramiko
        import time
        time.sleep(0.5)
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
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            return f'no_connection: {e}'
        except Exception as e:
            return str(e)