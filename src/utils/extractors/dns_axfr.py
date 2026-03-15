"""DNS zone transfer extractor — attempts AXFR against port 53 to dump all DNS records.

No credentials required. A misconfigured DNS server will return every subdomain,
IP address, MX record, and internal hostname for the target domain.
This is one of the highest-value unauthenticated findings possible.
"""

import socket
import struct


class DNSZoneTransfer:
    """Attempts a DNS AXFR (zone transfer) request against a target nameserver.

    A successful zone transfer dumps all DNS records for the domain —
    subdomains, internal IPs, mail servers, and more.
    """

    def __init__(self, ip: str, port: int, host: str):
        """Initialize with target nameserver details.

        Args:
            ip (str): Target IP address (the nameserver to query).
            port (int): DNS port, default 53.
            host (str): Domain name to request zone transfer for.
        """
        self.ip = ip
        self.port = port
        self.host = host

    def run(self) -> dict:
        """Attempt AXFR zone transfer via TCP and parse returned records.

        DNS zone transfers use TCP (not UDP) and require a valid AXFR query.
        Most modern servers reject these — but misconfigured ones dump everything.

        Returns:
            dict: status, records list, subdomains found, and raw response size.
        """
        print(f"\n  [DNS-AXFR] Attempting zone transfer for {self.host} via {self.ip}:{self.port}")
        result = {
            'status': 'refused',
            'records': [],
            'subdomains': [],
            'ips_found': [],
        }

        raw = self._send_axfr()
        if raw is None:
            print(f"  [DNS-AXFR] No response from {self.ip}:{self.port}")
            result['status'] = 'no_response'
            return result

        if len(raw) < 12:
            print(f"  [DNS-AXFR] Response too short — likely refused")
            return result

        records = self._parse_response(raw)
        if not records:
            print(f"  [DNS-AXFR] Zone transfer refused or empty")
            return result

        result['status'] = 'success'
        result['records'] = records

        for rec in records:
            rtype = rec.get('type')
            name = rec.get('name', '')
            data = rec.get('data', '')

            if rtype in ('A', 'AAAA'):
                subdomain = name.rstrip('.')
                if subdomain and subdomain not in result['subdomains']:
                    result['subdomains'].append(subdomain)
                if data and data not in result['ips_found']:
                    result['ips_found'].append(data)
                print(f"  [DNS-AXFR] {rtype:6} {name:<40} → {data}")
            else:
                print(f"  [DNS-AXFR] {rtype:6} {name:<40} → {data}")

        print(
            f"  [DNS-AXFR] *** ZONE TRANSFER SUCCESS — "
            f"{len(records)} records, {len(result['subdomains'])} subdomains, "
            f"{len(result['ips_found'])} IPs ***"
        )
        self._save_zone(records)
        return result

    def _send_axfr(self) -> bytes | None:
        """Build and send a DNS AXFR query over TCP, return raw response bytes.

        DNS over TCP: 2-byte length prefix + DNS message.
        AXFR query type = 252 (0xFC).

        Returns:
            bytes | None: Raw TCP response (may contain multiple DNS messages), or None.
        """
        try:
            # Build DNS AXFR query packet
            transaction_id = b'\xAB\xCD'
            flags = b'\x00\x00'          # standard query
            qdcount = b'\x00\x01'        # 1 question
            ancount = b'\x00\x00'
            nscount = b'\x00\x00'
            arcount = b'\x00\x00'

            # Encode domain name as DNS labels
            qname = self._encode_domain(self.host)
            qtype = b'\x00\xFC'          # AXFR
            qclass = b'\x00\x01'         # IN

            query = (
                transaction_id + flags + qdcount + ancount + nscount + arcount +
                qname + qtype + qclass
            )

            # TCP DNS: 2-byte big-endian length prefix
            tcp_query = struct.pack('!H', len(query)) + query

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((self.ip, self.port))
            sock.sendall(tcp_query)

            # Read all response data — zone transfers can be large
            response = b''
            while True:
                try:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            sock.close()
            return response if response else None

        except Exception as e:
            print(f"  [DNS-AXFR] Send error: {e}")
            return None

    def _encode_domain(self, domain: str) -> bytes:
        """Encode a domain name into DNS wire format labels.

        Args:
            domain (str): Domain name string (e.g. 'defensa.cl').

        Returns:
            bytes: DNS label-encoded domain name ending with null byte.
        """
        encoded = b''
        for label in domain.rstrip('.').split('.'):
            encoded += bytes([len(label)]) + label.encode()
        return encoded + b'\x00'

    def _parse_response(self, raw: bytes) -> list:
        """Parse DNS response bytes into a list of record dicts.

        Handles the TCP 2-byte length prefix and basic A/AAAA/MX/NS/CNAME/TXT records.
        Zone transfers may contain multiple concatenated DNS messages — we parse all.

        Args:
            raw (bytes): Raw TCP response bytes.

        Returns:
            list: List of dicts with keys: name, type, ttl, data.
        """
        records = []
        offset = 0

        while offset < len(raw) - 2:
            try:
                msg_len = struct.unpack('!H', raw[offset:offset+2])[0]
                offset += 2
                if msg_len == 0 or offset + msg_len > len(raw):
                    break

                msg = raw[offset:offset + msg_len]
                offset += msg_len

                parsed = self._parse_dns_message(msg)
                records.extend(parsed)
            except Exception:
                break

        return records

    def _parse_dns_message(self, msg: bytes) -> list:
        """Parse a single DNS message and extract answer records.

        Args:
            msg (bytes): A single DNS message (without TCP length prefix).

        Returns:
            list: Parsed records from the answer section.
        """
        records = []
        if len(msg) < 12:
            return records

        # Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
        ancount = struct.unpack('!H', msg[4:6])[0]
        if ancount == 0:
            return records

        # Skip header (12 bytes) and question section
        pos = 12
        try:
            # Skip question name
            pos = self._skip_name(msg, pos)
            pos += 4  # skip qtype + qclass
        except Exception:
            return records

        # Parse answer records
        for _ in range(ancount):
            try:
                name, pos = self._read_name(msg, pos)
                if pos + 10 > len(msg):
                    break

                rtype_int = struct.unpack('!H', msg[pos:pos+2])[0]
                pos += 2
                pos += 2  # class
                ttl = struct.unpack('!I', msg[pos:pos+4])[0]
                pos += 4
                rdlength = struct.unpack('!H', msg[pos:pos+2])[0]
                pos += 2
                rdata = msg[pos:pos + rdlength]
                pos += rdlength

                rtype_map = {
                    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
                    15: 'MX', 16: 'TXT', 28: 'AAAA', 252: 'AXFR',
                }
                rtype = rtype_map.get(rtype_int, str(rtype_int))
                data = self._parse_rdata(rtype, rdata, msg)

                records.append({'name': name, 'type': rtype, 'ttl': ttl, 'data': data})
            except Exception:
                break

        return records

    def _parse_rdata(self, rtype: str, rdata: bytes, msg: bytes) -> str:
        """Parse record data based on record type.

        Args:
            rtype (str): Record type string (A, AAAA, MX, etc.).
            rdata (bytes): Raw record data bytes.
            msg (bytes): Full DNS message (for name pointer resolution).

        Returns:
            str: Human-readable record data.
        """
        try:
            if rtype == 'A' and len(rdata) == 4:
                return '.'.join(str(b) for b in rdata)
            elif rtype == 'AAAA' and len(rdata) == 16:
                parts = [f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2)]
                return ':'.join(parts)
            elif rtype in ('NS', 'CNAME'):
                name, _ = self._read_name(msg, msg.index(rdata) if rdata in msg else 0)
                return name
            elif rtype == 'MX' and len(rdata) > 2:
                name, _ = self._read_name(msg, msg.index(rdata[2:]) if rdata[2:] in msg else 2)
                return f"priority={struct.unpack('!H', rdata[:2])[0]} {name}"
            elif rtype == 'TXT':
                return rdata[1:].decode('utf-8', errors='ignore')
            else:
                return rdata.hex()
        except Exception:
            return rdata.hex()

    def _read_name(self, msg: bytes, pos: int) -> tuple:
        """Read a DNS compressed name starting at pos.

        Args:
            msg (bytes): Full DNS message.
            pos (int): Starting position in message.

        Returns:
            tuple: (name_string, new_position)
        """
        labels = []
        visited = set()
        jumped = False
        original_pos = pos

        while pos < len(msg):
            length = msg[pos]
            if length == 0:
                pos += 1
                break
            elif (length & 0xC0) == 0xC0:
                # Pointer
                if pos + 1 >= len(msg):
                    break
                pointer = struct.unpack('!H', msg[pos:pos+2])[0] & 0x3FFF
                if pointer in visited:
                    break
                visited.add(pointer)
                if not jumped:
                    original_pos = pos + 2
                    jumped = True
                pos = pointer
            else:
                pos += 1
                labels.append(msg[pos:pos+length].decode('utf-8', errors='ignore'))
                pos += length

        return '.'.join(labels) + '.', (original_pos if jumped else pos)

    def _skip_name(self, msg: bytes, pos: int) -> int:
        """Skip over a DNS name at pos and return the position after it.

        Args:
            msg (bytes): Full DNS message.
            pos (int): Starting position.

        Returns:
            int: Position after the name.
        """
        while pos < len(msg):
            length = msg[pos]
            if length == 0:
                return pos + 1
            elif (length & 0xC0) == 0xC0:
                return pos + 2
            pos += length + 1
        return pos

    def _save_zone(self, records: list):
        """Save zone transfer results to reports/zone_transfers/.

        Args:
            records (list): Parsed DNS records.
        """
        import json
        import os
        out_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', '..', '..', 'reports', 'zone_transfers'
        )
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{self.host}_axfr.json")
        with open(out_path, 'w') as f:
            json.dump({'domain': self.host, 'nameserver': self.ip, 'records': records}, f, indent=4)
        print(f"  [DNS-AXFR] Saved to reports/zone_transfers/{self.host}_axfr.json")