"""Gobuster extractor — directory and file bruteforce using gobuster subprocess.

Requires gobuster to be installed:
    apt install gobuster

Called by router.py after WPScan/Nikto recon, before cPanel brute force.
Uses a bundled default wordlist of common paths — no external file needed.
"""

import os
import shutil
import subprocess
import tempfile


# Bundled wordlist — common admin panels, backup files, config paths, APIs
DEFAULT_PATHS = [
    # Admin panels
    'admin', 'admin/', 'administrator', 'administrator/', 'admin.php', 'admin.html',
    'wp-admin', 'wp-login.php', 'login', 'login.php', 'login.html', 'signin',
    'panel', 'panel/', 'cpanel', 'dashboard', 'dashboard/', 'manager', 'manager/',
    'backend', 'backend/', 'console', 'console/', 'adminpanel', 'admin_panel',
    'superadmin', 'webadmin', 'siteadmin', 'adminarea', 'admin_area',
    # Config and environment files
    '.env', '.env.bak', '.env.local', '.env.production', '.env.staging',
    'config.php', 'config.php.bak', 'configuration.php', 'config.yml', 'config.yaml',
    'config.json', 'config.xml', 'settings.php', 'settings.py', 'local_settings.py',
    'database.php', 'database.yml', 'database.json', 'db.php',
    # Backup files
    'backup', 'backup/', 'backups', 'backups/', 'backup.zip', 'backup.tar.gz',
    'backup.sql', 'dump.sql', 'db.sql', 'database.sql', 'data.sql', 'site.sql',
    'backup.php', 'bak', 'old', 'temp', 'tmp',
    # WordPress specific
    'wp-config.php', 'wp-config.php.bak', 'wp-content/', 'wp-includes/',
    'xmlrpc.php', 'wp-json/', 'wp-cron.php',
    # Exposed git / version control
    '.git/', '.git/config', '.git/HEAD', '.gitignore', '.svn/', '.svn/entries',
    '.hg/', '.DS_Store',
    # API endpoints
    'api/', 'api/v1/', 'api/v2/', 'api/v1/users', 'api/v1/admin',
    'rest/', 'rest/api/', 'graphql', 'swagger', 'swagger.json', 'openapi.json',
    'swagger-ui', 'swagger-ui.html', 'api-docs', 'api/docs',
    # PHP info / debug
    'phpinfo.php', 'info.php', 'test.php', 'debug.php', 'status.php',
    'health', 'health/', 'healthcheck', 'ping', 'server-status', 'server-info',
    # Logs
    'error_log', 'error.log', 'access.log', 'logs/', 'log/', 'debug.log',
    # Upload directories
    'uploads/', 'upload/', 'files/', 'file/', 'media/', 'assets/', 'static/',
    'images/', 'img/', 'docs/', 'documents/', 'downloads/',
    # Common CMS paths
    'joomla/', 'drupal/', 'magento/', 'laravel/', 'symfony/',
    'sites/default/settings.php', 'sites/default/files/',
    # cPanel / hosting
    'cpanel/', 'webmail/', 'whm/', 'plesk/', 'directadmin/',
    'public_html/', 'www/', 'htdocs/', 'httpdocs/',
    # Shell / RCE artifacts
    'shell.php', 'cmd.php', 'c99.php', 'r57.php', 'webshell.php',
    'eval.php', 'exec.php', 'passthru.php',
    # Misc
    'robots.txt', 'sitemap.xml', 'sitemap.xml.gz', '.htaccess', '.htpasswd',
    'readme.txt', 'README.md', 'CHANGELOG.md', 'LICENSE.txt', 'VERSION',
    'composer.json', 'package.json', 'Gemfile', 'requirements.txt',
    'Makefile', 'Dockerfile', 'docker-compose.yml',
    'server.key', 'server.crt', 'private.key', 'cert.pem',
]


class GobusterExtractor:
    """Runs gobuster directory bruteforce and returns discovered paths."""

    def __init__(self, host: str, ip: str, port: int = 443):
        """Initialize with target host, IP and port.

        Args:
            host (str): Domain name for URL construction and Host header.
            ip (str): Resolved IP address — connect directly to bypass CDN.
            port (int): Port to target. Determines http vs https scheme.
        """
        self.host = host
        self.ip = ip
        self.port = port
        self.scheme = 'https' if port == 443 else 'http'

    def run(self) -> dict:
        """Write bundled wordlist to temp file, run gobuster, parse results.

        Returns:
            dict: status, found paths, and any interesting findings flagged by category.
        """
        print(f"\n  [Gobuster] Targeting {self.scheme}://{self.host}")

        if not self._is_installed():
            print(f"  [Gobuster] Not installed — skipping (run: apt install gobuster)")
            return {'status': 'not_installed'}

        wordlist_path = self._write_wordlist()
        if not wordlist_path:
            return {'status': 'failed', 'reason': 'could not write wordlist'}

        is_temp = wordlist_path.startswith('/tmp/')
        try:
            raw = self._run_scan(wordlist_path)
        finally:
            if is_temp:
                os.unlink(wordlist_path)

        if raw is None:
            return {'status': 'failed'}

        return self._parse(raw)

    # ─── Private ──────────────────────────────────────────────────────────────

    def _is_installed(self) -> bool:
        """Check if gobuster binary is available on PATH.

        Returns:
            bool: True if gobuster is found.
        """
        return shutil.which('gobuster') is not None

    def _write_wordlist(self) -> str | None:
        """Use SecLists if available, otherwise fall back to bundled wordlist.

        Returns:
            str | None: Path to wordlist file, or None on failure.
        """
        seclists_candidates = [
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt',
            '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
        ]
        for path in seclists_candidates:
            if os.path.isfile(path):
                print(f"  [Gobuster] Using SecLists wordlist: {path}")
                return path

        # Fall back to bundled list
        print(f"  [Gobuster] SecLists not found — using bundled wordlist (install: sudo apt install seclists)")
        try:
            fd, path = tempfile.mkstemp(suffix='.txt', prefix='gobuster_')
            with os.fdopen(fd, 'w') as f:
                f.write('\n'.join(DEFAULT_PATHS))
            return path
        except Exception as e:
            print(f"  [Gobuster] Failed to write wordlist: {e}")
            return None

    def _run_scan(self, wordlist_path: str) -> str | None:
        """Execute gobuster dir scan and return raw stdout.

        Flags used:
            -u      target URL (IP directly, with Host header via -H)
            -w      wordlist path
            -H      Host header to handle virtual hosting / CDN
            -k      skip TLS verification (common on government sites)
            -t      threads (10 — polite, avoids triggering rate limits)
            -o      output file (stdout parsed directly)
            -q      quiet mode — suppress banner, only print findings
            --no-error  suppress connection error spam

        Returns:
            str | None: Raw stdout from gobuster, or None on failure.
        """
        url = f"{self.scheme}://{self.ip}"
        cmd = [
            'gobuster', 'dir',
            '-u', url,
            '-w', wordlist_path,
            '-H', f"Host: {self.host}",
            '-k',
            '-t', '10',
            '-q',
            '--no-error',
            '--timeout', '5s',
        ]

        print(f"  [Gobuster] Running: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            stdout = proc.stdout.strip()
            if not stdout:
                print(f"  [Gobuster] No findings (exit code {proc.returncode})")
                return None

            return stdout

        except subprocess.TimeoutExpired:
            print(f"  [Gobuster] Timed out after 120s")
            return None
        except Exception as e:
            print(f"  [Gobuster] Subprocess error: {e}")
            return None

    def _parse(self, raw: str) -> dict:
        """Parse gobuster output into structured findings bucketed by category.

        Gobuster dir output format per line:
            /path                 (Status: 200) [Size: 1234]
            /path                 (Status: 301) [--> /path/]

        Args:
            raw (str): Raw stdout from gobuster.

        Returns:
            dict: Structured results with paths bucketed by category.
        """
        result = {
            'status': 'success',
            'found': [],
            'admin_panels': [],
            'config_files': [],
            'backup_files': [],
            'interesting': [],
        }

        admin_keywords    = {'admin', 'login', 'panel', 'dashboard', 'manager',
                             'backend', 'console', 'wp-admin', 'wp-login'}
        config_keywords   = {'.env', 'config', 'settings', 'database', '.git',
                             'wp-config', '.htpasswd', '.htaccess'}
        backup_keywords   = {'backup', 'dump', '.sql', '.zip', '.tar', '.bak',
                             '.old', 'backups'}

        import re as _re
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # Parse: "/path   (Status: 200) [Size: 1234]"
            m = _re.match(r'(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', line)
            if not m:
                continue

            path   = m.group(1)
            status = m.group(2)
            size   = m.group(3)

            entry = {'path': path, 'status': status, 'size': size}
            result['found'].append(entry)

            path_lower = path.lower()

            if any(k in path_lower for k in admin_keywords):
                result['admin_panels'].append(entry)
                print(f"  [Gobuster] [ADMIN] {path} (Status: {status})")
            elif any(k in path_lower for k in config_keywords):
                result['config_files'].append(entry)
                print(f"  [Gobuster] [CONFIG] {path} (Status: {status})")
            elif any(k in path_lower for k in backup_keywords):
                result['backup_files'].append(entry)
                print(f"  [Gobuster] [BACKUP] {path} (Status: {status})")
            else:
                result['interesting'].append(entry)
                print(f"  [Gobuster] [FOUND] {path} (Status: {status})")

        total = len(result['found'])
        print(
            f"  [Gobuster] Scan complete — {total} paths found "
            f"({len(result['admin_panels'])} admin, {len(result['config_files'])} config, "
            f"{len(result['backup_files'])} backup)"
        )

        return result