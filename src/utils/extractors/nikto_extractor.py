"""Nikto extractor — runs Nikto via subprocess and parses its output.

Requires Nikto to be installed on the host system:
    apt install nikto
    OR
    git clone https://github.com/sullo/nikto && cd nikto/program

Called by router.py when port 80 or 443 is open, after WPScan recon.
Nikto is broader than WPScan — it covers any web server regardless of CMS.
"""

import csv
import io
import shutil
import subprocess


# Nikto severity mapping based on OSVDB/message content heuristics
# Nikto doesn't emit structured severity — we infer from keywords
HIGH_KEYWORDS = [
    'sql injection', 'xss', 'rce', 'remote code', 'command injection',
    'file inclusion', 'directory traversal', 'shell', 'backdoor',
    'credentials', 'password', 'admin', 'exposed', 'unrestricted upload',
]
MEDIUM_KEYWORDS = [
    'csrf', 'clickjacking', 'cors', 'cookie', 'session', 'redirect',
    'information disclosure', 'debug', 'phpinfo', 'server version',
    'default page', 'default file', 'backup',
]


class NiktoExtractor:
    """Wraps the Nikto CLI tool and returns parsed web vulnerability findings."""

    def __init__(self, host: str, ip: str, port: int = 80):
        """Initialize with target host, IP and port.

        Args:
            host (str): Domain name for the Host header and URL construction.
            ip (str): Resolved IP address — Nikto connects directly to this.
            port (int): Port to target. Nikto auto-detects SSL on 443.
        """
        self.host = host
        self.ip = ip
        self.port = port

    def run(self) -> dict:
        """Check Nikto availability, run scan, parse and return structured results.

        Returns:
            dict: Structured findings with keys:
                  - status: 'success' | 'not_installed' | 'failed'
                  - server (str | None): Server header value
                  - findings (list of dicts with id, url, msg, severity)
                  - high (list): HIGH severity findings only
                  - medium (list): MEDIUM severity findings only
                  - info (list): Informational findings
        """
        print(f"\n  [Nikto] Targeting {self.host}:{self.port}")

        if not self._is_installed():
            print(f"  [Nikto] Not installed — skipping (run: apt install nikto)")
            return {'status': 'not_installed'}

        raw_csv = self._run_scan()
        if raw_csv is None:
            return {'status': 'failed'}

        return self._parse(raw_csv)

    # ─── Private ──────────────────────────────────────────────────────────────

    def _is_installed(self) -> bool:
        """Check if the nikto binary is available on PATH.

        Returns:
            bool: True if nikto is found.
        """
        return shutil.which('nikto') is not None

    def _run_scan(self) -> str | None:
        """Execute Nikto with CSV output format and return raw stdout.

        Flags used:
            -host       target hostname (for Host header)
            -port       target port
            -Format csv machine-readable, easiest to parse reliably
            -nointeractive  suppress prompts
            -ssl        force SSL if port is 443
            -Tuning x   skip DoS checks (9) — we want recon only, not disruption
            -timeout    per-request timeout in seconds

        Returns:
            str | None: Raw CSV stdout from Nikto, or None on failure.
        """
        cmd = [
            'nikto',
            '-host', f"www.{self.host}" if not self.host.startswith('www.') else self.host,
            '-port', str(self.port),
            '-Format', 'csv',
            '-nointeractive',
            '-Tuning', 'x9',   # exclude DoS (9) and uninteresting info (x)
            '-timeout', '10',
        ]

        if self.port == 443:
            cmd.append('-ssl')

        print(f"  [Nikto] Running: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # Nikto is slower than WPScan on full scans
            )

            stdout = proc.stdout.strip()
            if not stdout:
                print(f"  [Nikto] No output (exit code {proc.returncode})")
                if proc.stderr:
                    print(f"  [Nikto] stderr: {proc.stderr[:300]}")
                return None

            return stdout

        except subprocess.TimeoutExpired:
            print(f"  [Nikto] Timed out after 180s")
            return None
        except Exception as e:
            print(f"  [Nikto] Subprocess error: {e}")
            return None

    def _parse(self, raw_csv: str) -> dict:
        """Parse Nikto CSV output into structured findings.

        Nikto CSV columns (in order):
            nikto_host, ip, port, osvdb_id, server, msg, uri, method

        Header line starts with 'nikto_host' or may be absent — we handle both.

        Args:
            raw_csv (str): Raw CSV text from Nikto stdout.

        Returns:
            dict: Normalized result with findings bucketed by severity.
        """
        result = {
            'status': 'success',
            'server': None,
            'findings': [],
            'high': [],
            'medium': [],
            'info': [],
        }

        # Strip Nikto's banner lines (start with '-') before the CSV data
        csv_lines = [
            line for line in raw_csv.splitlines()
            if line.strip() and not line.startswith('-')
        ]

        if not csv_lines:
            print(f"  [Nikto] No findings in output")
            return result

        reader = csv.DictReader(
            io.StringIO('\n'.join(csv_lines)),
            fieldnames=['nikto_host', 'ip', 'port', 'osvdb_id', 'server', 'msg', 'uri', 'method'],
        )

        for row in reader:
            # Skip the header row if Nikto included it
            if row.get('nikto_host', '').lower() in ('nikto_host', 'host'):
                continue

            server = (row.get('server') or '').strip()
            if server and not result['server']:
                result['server'] = server
                print(f"  [Nikto] Server: {server}")

            msg = (row.get('msg') or '').strip()
            uri = (row.get('uri') or '').strip()
            osvdb = (row.get('osvdb_id') or '').strip()

            if not msg:
                continue

            severity = self._infer_severity(msg)

            finding = {
                'osvdb': osvdb,
                'uri': uri,
                'msg': msg,
                'method': row.get('method', '').strip(),
                'severity': severity,
            }

            result['findings'].append(finding)
            result[severity].append(finding)
            print(f"  [Nikto] [{severity.upper()}] {uri or '/'} — {msg[:120]}")

        total = len(result['findings'])
        print(
            f"  [Nikto] Scan complete — {total} findings "
            f"({len(result['high'])} HIGH, {len(result['medium'])} MEDIUM, {len(result['info'])} INFO)"
        )

        return result

    def _infer_severity(self, msg: str) -> str:
        """Infer severity level from finding message text using keyword matching.

        Nikto does not emit severity natively — this is a best-effort heuristic.
        HIGH covers exploitable classes (injection, RCE, exposed creds).
        MEDIUM covers configuration weaknesses and info disclosure.
        Everything else is INFO.

        Args:
            msg (str): Nikto finding message string.

        Returns:
            str: 'high' | 'medium' | 'info'
        """
        lower = msg.lower()
        if any(kw in lower for kw in HIGH_KEYWORDS):
            return 'high'
        if any(kw in lower for kw in MEDIUM_KEYWORDS):
            return 'medium'
        return 'info'