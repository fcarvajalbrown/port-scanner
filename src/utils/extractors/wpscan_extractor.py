"""WPScan extractor — runs WPScan via subprocess and parses its JSON output.

Requires WPScan to be installed on the host system:
    gem install wpscan
    OR
    apt install wpscan

Called by router.py when port 80 or 443 is open and WordPress is detected or assumed.
"""

import json
import shutil
import subprocess


# WPScan exit codes
EXIT_OK = 0
EXIT_NO_WP = 1       # target does not appear to be WordPress
EXIT_CLI_ERROR = 2   # bad arguments or config error
EXIT_INTERRUPTED = 3


class WPScanExtractor:
    """Wraps the WPScan CLI tool and returns parsed vulnerability findings."""

    def __init__(self, host: str, ip: str, port: int = 80, api_token: str = None):
        """Initialize with target host, IP, port and optional WPScan API token.

        Args:
            host (str): Domain name (used as the URL target).
            ip (str): Resolved IP address (unused directly, kept for router interface consistency).
            port (int): Port to target — determines http vs https scheme.
            api_token (str | None): WPScan API token for vulnerability database lookups.
                                    Without a token, plugin/theme CVEs are not returned.
        """
        self.host = host
        self.ip = ip
        self.port = port
        self.api_token = api_token
        self.url = f"{'https' if port == 443 else 'http'}://{host}"

    def run(self) -> dict:
        """Check WPScan availability, run scan, parse and return structured results.

        Returns:
            dict: Structured findings with keys:
                  - status: 'success' | 'not_wordpress' | 'not_installed' | 'failed'
                  - wordpress_version (str | None)
                  - users (list of str)
                  - plugins (dict: name -> {version, vulnerabilities})
                  - themes (dict: name -> {version, vulnerabilities})
                  - vulnerabilities (list of dicts with title, cve, severity, references)
                  - interesting_findings (list of str)
                  - raw (dict): full parsed JSON from WPScan for further processing
        """
        print(f"\n  [WPScan] Targeting {self.url}")

        if not self._is_installed():
            print(f"  [WPScan] Not installed — skipping (run: gem install wpscan)")
            return {'status': 'not_installed'}

        raw = self._run_scan()
        if raw is None:
            return {'status': 'failed'}

        # WPScan sets a flag when the target is not WordPress
        if not raw.get('target_url') or raw.get('scan_aborted'):
            reason = raw.get('scan_aborted', 'target does not appear to be WordPress')
            print(f"  [WPScan] Scan aborted: {reason}")
            return {'status': 'not_wordpress', 'reason': reason}

        return self._parse(raw)

    # ─── Private ──────────────────────────────────────────────────────────────

    def _is_installed(self) -> bool:
        """Check if the wpscan binary is available on PATH.

        Returns:
            bool: True if wpscan is found.
        """
        return shutil.which('wpscan') is not None

    def _run_scan(self) -> dict | None:
        """Execute WPScan with JSON output and return parsed result.

        Flags used:
            --url               target URL
            --format json       machine-readable output
            --no-update         skip DB update (faster; update manually with: wpscan --update)
            --disable-tls-checks  ignore self-signed / expired certs (common on scanned hosts)
            --enumerate u,p,t   users, plugins, themes
            --api-token         optional — enables CVE lookups

        Returns:
            dict | None: Parsed JSON from WPScan stdout, or None on subprocess failure.
        """
        cmd = [
            'wpscan',
            '--url', self.url,
            '--format', 'json',
            '--no-update',
            '--disable-tls-checks',
            '--enumerate', 'u,p,t',  # users, plugins, themes
        ]

        if self.api_token:
            cmd += ['--api-token', self.api_token]

        print(f"  [WPScan] Running: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # WPScan can be slow on large plugin lists
            )

            # WPScan writes valid JSON to stdout even on exit code 1 (not WordPress)
            stdout = proc.stdout.strip()
            if not stdout:
                print(f"  [WPScan] No output (exit code {proc.returncode})")
                if proc.stderr:
                    print(f"  [WPScan] stderr: {proc.stderr[:300]}")
                return None

            return json.loads(stdout)

        except subprocess.TimeoutExpired:
            print(f"  [WPScan] Timed out after 120s")
            return None
        except json.JSONDecodeError as e:
            print(f"  [WPScan] Failed to parse JSON output: {e}")
            return None
        except Exception as e:
            print(f"  [WPScan] Subprocess error: {e}")
            return None

    def _parse(self, raw: dict) -> dict:
        """Extract structured findings from raw WPScan JSON output.

        Args:
            raw (dict): Full parsed WPScan JSON output.

        Returns:
            dict: Normalized findings dict.
        """
        result = {
            'status': 'success',
            'wordpress_version': None,
            'users': [],
            'plugins': {},
            'themes': {},
            'vulnerabilities': [],
            'interesting_findings': [],
            'raw': raw,
        }

        # WordPress version
        wp_version = raw.get('version', {})
        if wp_version:
            result['wordpress_version'] = wp_version.get('number')
            print(f"  [WPScan] WordPress version: {result['wordpress_version']}")

        # Enumerate users
        users_raw = raw.get('users', {})
        result['users'] = list(users_raw.keys())
        if result['users']:
            print(f"  [WPScan] Users found: {result['users']}")

        # Plugins
        plugins_raw = raw.get('plugins', {})
        for name, data in plugins_raw.items():
            vulns = self._extract_vulns(data.get('vulnerabilities', []))
            result['plugins'][name] = {
                'version': data.get('version', {}).get('number'),
                'vulnerabilities': vulns,
            }
            if vulns:
                print(f"  [WPScan] Plugin '{name}' has {len(vulns)} vulnerability(ies)")

        # Themes
        themes_raw = raw.get('themes', {})
        for name, data in themes_raw.items():
            vulns = self._extract_vulns(data.get('vulnerabilities', []))
            result['themes'][name] = {
                'version': data.get('version', {}).get('number'),
                'vulnerabilities': vulns,
            }
            if vulns:
                print(f"  [WPScan] Theme '{name}' has {len(vulns)} vulnerability(ies)")

        # Top-level WordPress core vulnerabilities (requires API token)
        core_vulns = self._extract_vulns(raw.get('version', {}).get('vulnerabilities', []))
        result['vulnerabilities'].extend(core_vulns)
        if core_vulns:
            print(f"  [WPScan] WordPress core has {len(core_vulns)} known vulnerability(ies)")

        # Interesting findings (exposed files, xmlrpc, readme, etc.)
        for finding in raw.get('interesting_findings', []):
            url = finding.get('url', '')
            type_ = finding.get('type', '')
            to_highlight = finding.get('to_s', url)
            result['interesting_findings'].append(to_highlight)
            print(f"  [WPScan] Interesting: [{type_}] {url}")

        total_vulns = (
            len(result['vulnerabilities'])
            + sum(len(p['vulnerabilities']) for p in result['plugins'].values())
            + sum(len(t['vulnerabilities']) for t in result['themes'].values())
        )
        print(f"  [WPScan] Scan complete — {total_vulns} total vulnerabilities found")

        return result

    def _extract_vulns(self, vuln_list: list) -> list:
        """Normalize a list of WPScan vulnerability objects into a flat structure.

        Args:
            vuln_list (list): Raw vulnerability entries from WPScan JSON.

        Returns:
            list: List of dicts with title, cve, severity, cvss, references.
        """
        normalized = []
        for v in vuln_list:
            refs = v.get('references', {})
            normalized.append({
                'title': v.get('title', 'Unknown'),
                'cve': refs.get('cve', []),
                'severity': v.get('cvss', {}).get('severity', 'unknown'),
                'cvss_score': v.get('cvss', {}).get('score'),
                'references': refs.get('url', []),
            })
        return normalized