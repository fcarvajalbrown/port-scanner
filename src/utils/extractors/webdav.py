"""WebDAV extractor — attempts unauthenticated PROPFIND to list files and PUT to test write access.

No credentials required. Targets ports 80, 443, 2077, 2078 (cPanel WebDAV).
A successful PROPFIND on a misconfigured server dumps the full directory tree.
"""

import socket
import ssl
import re
import os


# Paths worth probing with PROPFIND
WEBDAV_PATHS = [
    '/',
    '/webdav/',
    '/dav/',
    '/files/',
    '/uploads/',
    '/public/',
    '/documents/',
    '/backup/',
    '/www/',
    '/public_html/',
]

# Small benign probe file for PUT test
PUT_PROBE_NAME = 'webdav_probe_test.txt'
PUT_PROBE_BODY = b'webdav_write_test'


class WebDAVExtractor:
    """Attempts unauthenticated WebDAV PROPFIND (list) and PUT (write) on open ports."""

    def __init__(self, ip: str, port: int, host: str):
        """Initialize with target connection details.

        Args:
            ip (str): Target IP address.
            port (int): Port to probe (80, 443, 2077, 2078).
            host (str): Domain name for Host header.
        """
        self.ip = ip
        self.port = port
        self.host = host
        self.tls = port in (443, 2078)

    def run(self) -> dict:
        """Run PROPFIND on each candidate path, then attempt a PUT probe.

        Returns:
            dict: status, listed files, writable paths, and any interesting filenames.
        """
        print(f"\n  [WebDAV] Probing {self.host}:{self.port}")
        result = {
            'status': 'no_webdav',
            'listed_files': [],
            'writable_paths': [],
            'interesting_files': [],
        }

        for path in WEBDAV_PATHS:
            files = self._propfind(path)
            if files is not None:
                result['status'] = 'open'
                result['listed_files'].extend(files)
                print(f"  [WebDAV] PROPFIND {path} — {len(files)} entries")
                for f in files:
                    if self._is_interesting(f):
                        print(f"  [WebDAV] *** Interesting file: {f}")
                        result['interesting_files'].append(f)

                # Test write access on first responsive path
                if self._put_probe(path):
                    print(f"  [WebDAV] *** WRITE ACCESS on {path} — PUT succeeded")
                    result['writable_paths'].append(path)

        if result['status'] == 'no_webdav':
            print(f"  [WebDAV] No WebDAV response on {self.host}:{self.port}")

        return result

    def _propfind(self, path: str) -> list | None:
        """Send a Depth:1 PROPFIND request and parse the XML response for file hrefs.

        Args:
            path (str): URL path to probe.

        Returns:
            list | None: List of href strings if WebDAV responded, None otherwise.
        """
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<propfind xmlns="DAV:">'
            '<prop><resourcetype/><getcontentlength/><getlastmodified/></prop>'
            '</propfind>'
        )
        headers = (
            f"PROPFIND {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Depth: 1\r\n"
            f"Content-Type: application/xml\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        raw = self._send(headers.encode() + body.encode())
        if raw is None:
            return None

        # WebDAV responds 207 Multi-Status on success
        if b'207' not in raw[:50] and b'HTTP/1.1 2' not in raw[:20]:
            return None

        # Extract all href values from the XML response
        decoded = raw.decode('utf-8', errors='ignore')
        hrefs = re.findall(r'<[Dd]:?href>(.*?)</[Dd]:?href>', decoded)
        return hrefs if hrefs else []

    def _put_probe(self, path: str) -> bool:
        """Attempt a PUT request to test write access. Cleans up with DELETE if successful.

        Args:
            path (str): Directory path to attempt upload into.

        Returns:
            bool: True if PUT returned 2xx (write access confirmed).
        """
        target = f"{path.rstrip('/')}/{PUT_PROBE_NAME}"
        headers = (
            f"PUT {target} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(PUT_PROBE_BODY)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        raw = self._send(headers.encode() + PUT_PROBE_BODY)
        if raw is None:
            return False

        success = any(code in raw[:50] for code in [b'201', b'204', b'200'])
        if success:
            # Clean up — attempt DELETE
            self._delete_probe(target)
        return success

    def _delete_probe(self, path: str):
        """Send DELETE to clean up the PUT probe file.

        Args:
            path (str): Full path of the file to delete.
        """
        headers = (
            f"DELETE {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        self._send(headers.encode())

    def _send(self, request: bytes) -> bytes | None:
        """Open a raw TCP (or TLS) connection and send a request, returning the response.

        Args:
            request (bytes): Full HTTP request bytes to send.

        Returns:
            bytes | None: Raw response bytes, or None on failure.
        """
        try:
            sock = socket.create_connection((self.ip, self.port), timeout=5)
            if self.tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
                sock.settimeout(5)

            sock.sendall(request)

            response = b''
            while len(response) < 200_000:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except (socket.timeout, OSError):
                    break
            sock.close()
            return response if response else None
        except Exception as e:
            print(f"  [WebDAV] Connection error on port {self.port}: {e}")
            return None

    def _is_interesting(self, href: str) -> bool:
        """Check if a file href matches known sensitive file patterns.

        Args:
            href (str): File path or URL from PROPFIND response.

        Returns:
            bool: True if filename matches a sensitive pattern.
        """
        keywords = [
            'config', '.env', 'backup', '.sql', 'dump', 'password',
            'credentials', 'wp-config', '.htpasswd', 'secret', 'key',
            'private', 'token', 'database', 'settings',
        ]
        lower = href.lower()
        return any(kw in lower for kw in keywords)