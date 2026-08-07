"""
daemon/parser/packet_parser.py — Network packet parser for Warden Phase 2.

CONTRACT: PacketParser.parse(raw_bytes: bytes) -> ParsedNetworkAction
  Returns one ParsedNetworkAction per packet. The caller (sidecar/interceptor.py)
  passes in the raw bytes from a netfilterqueue packet.get_payload() call.

ParsedNetworkAction is a subtype of ParsedAction so it satisfies the Inspector
interface contract: NetworkInspector.inspect(action: ParsedAction) -> Verdict
works without any changes to the Inspector ABC or the core loop.

WHY Scapy for layer parsing (IP/TCP/UDP) but NOT for TLS/SNI:
  Scapy's TLS dissector (from scapy.layers.tls) requires an explicit
  load_layer("tls") call and has had API changes across versions. Depending on
  it would make the sidecar fragile to scapy version upgrades. TLS ClientHello
  SNI is a fixed-offset, well-specified structure — parsing it manually from the
  TCP payload is ~30 lines and far more stable.

WHY direction field:
  NFQUEUE can intercept both outbound packets from the jail AND inbound responses.
  In Phase 2 we enforce only on outbound. The field is present so the inspector
  can filter by direction without needing the caller to pre-filter.

WHY hostname_or_sni is Optional[str]:
  Not all packets carry a resolvable hostname. Plain TCP to a raw IP has no SNI.
  UDP to port 53 has a query name. The inspector falls back to dst_ip matching
  when hostname_or_sni is None.

RISK: SNI extraction assumes the first bytes of the TCP payload are a TLS record.
  A server using TLS on a non-443 port, or a non-TLS protocol on 443, will either
  not match the ClientHello record type or produce no SNI. In both cases we return
  None for hostname_or_sni — the inspector falls back to IP-level matching.
  TODO(phase3): detect non-TLS-on-443 explicitly and log it as anomalous.

RISK: DNS query parsing handles only the first question in the DNS query section.
  Multiple-question DNS messages are legal but rare in practice.
  TODO(phase3): parse all questions if needed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scapy.all import IP, TCP, UDP

# Import the parent dataclass from the shell parser.
# ParsedNetworkAction must be a subtype of ParsedAction so it passes the
# Inspector.inspect(action: ParsedAction) -> Verdict type contract.
from daemon.parser.shell_parser import ParsedAction


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class ParsedNetworkAction(ParsedAction):
    """
    Structured representation of a single intercepted network packet.

    CONTRACT: Satisfies the ParsedAction interface so NetworkInspector can
    receive it via inspect(action: ParsedAction) without any changes to the
    Inspector ABC. The inspector downcasts (isinstance check) to access the
    network-specific fields when needed.

    Fields (network-specific, in addition to ParsedAction's fields):
      src_ip          — source IP address as a dotted-decimal string
      src_port        — source TCP/UDP port (0 for non-TCP/UDP packets)
      dst_ip          — destination IP address as a dotted-decimal string
      dst_port        — destination TCP/UDP port (0 for non-TCP/UDP packets)
      protocol        — "TCP", "UDP", or "OTHER"
      hostname_or_sni — extracted hostname: TLS SNI for port 443, DNS query
                        name for port 53, None for all other packets
      raw_bytes       — the original packet bytes from the NFQUEUE callback
      direction       — "outbound" (jail→outside) or "inbound" (outside→jail)

    ParsedAction fields used/overridden:
      binary      — set to "<network>" (not a shell binary; marker for log display)
      args        — empty list (unused for network actions)
      flags       — empty list (unused for network actions)
      target_paths— empty list (filesystem paths not relevant for network actions)
      raw_input   — human-readable summary: "TCP 1.2.3.4:443"
      sub_commands— empty list (no shell substitution for network events)
    """

    # Network-specific fields.
    # WHY defaults here: @dataclass inheritance requires that fields with
    # defaults come AFTER fields without defaults. ParsedAction's fields all
    # have defaults (via field(default_factory=...)), so we can safely add
    # new fields with defaults here.
    src_ip: str = ""             # WHY: needed for true 4-tuple conn_key in conntrack
    src_port: int = 0            # WHY: needed for true 4-tuple conn_key in conntrack
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "OTHER"          # "TCP" | "UDP" | "OTHER"
    hostname_or_sni: Optional[str] = None
    raw_bytes: bytes = b""
    direction: str = "outbound"      # "outbound" | "inbound"
    seq: int = 0
    ack: int = 0

    def __repr__(self) -> str:
        host_part = f" ({self.hostname_or_sni})" if self.hostname_or_sni else ""
        return (
            f"ParsedNetworkAction({self.protocol} {self.src_ip}:{self.src_port}"
            f" → {self.dst_ip}:{self.dst_port}"
            f"{host_part}, direction={self.direction!r})"
        )


# ── Parser ────────────────────────────────────────────────────────────────────

class PacketParser:
    """
    CONTRACT: PacketParser.parse(raw_bytes) -> ParsedNetworkAction

    Stateless — no constructor arguments required. All methods are class-level
    so the caller can do PacketParser.parse(data) without instantiation.

    The jail's IP on the docker bridge is used to determine direction. In Phase 2
    the interceptor operates in the jail's network namespace (network_mode:
    "service:jail" in docker-compose), so src_ip == jail's IP means outbound.
    We detect outbound conservatively: if the packet's source IP is a private/
    loopback address (RFC1918 + loopback), we treat it as outbound. This is
    correct for the Phase 2 use case where the jail has a private bridge IP.
    TODO(phase5): thread the actual jail IP through from the interceptor for
    a more precise direction check.
    """

    @classmethod
    def parse(cls, raw_bytes: bytes) -> ParsedNetworkAction:
        """Parse raw packet bytes into a ParsedNetworkAction.

        Returns a ParsedNetworkAction with protocol="OTHER" and dst_ip="unknown"
        if the bytes cannot be parsed as a valid IP packet. Never raises.
        """
        try:
            return cls._parse_inner(raw_bytes)
        except Exception as exc:
            # WHY never raise: a parse failure must not crash the NFQUEUE callback.
            # An unparseable packet gets logged with protocol=OTHER, then blocked
            # by the default-deny network policy.
            return ParsedNetworkAction(
                binary="<network>",
                raw_input="<unparseable packet>",
                src_ip="unknown",
                src_port=0,
                dst_ip="unknown",
                dst_port=0,
                protocol="OTHER",
                hostname_or_sni=None,
                raw_bytes=raw_bytes,
                direction="outbound",
            )

    @classmethod
    def _parse_inner(cls, raw_bytes: bytes) -> ParsedNetworkAction:
        """Internal parser — may raise; wrapped by parse()."""
        pkt = IP(raw_bytes)

        src_ip: str = pkt[IP].src
        dst_ip: str = pkt[IP].dst
        direction = cls._infer_direction(src_ip)

        if TCP in pkt:
            src_port: int = pkt[TCP].sport
            dst_port: int = pkt[TCP].dport
            seq: int = pkt[TCP].seq
            ack: int = pkt[TCP].ack
            protocol = "TCP"
            # Extract TLS SNI from the TCP payload if this looks like a
            # TLS ClientHello (port 443 or payload starts with TLS record).
            tcp_payload: bytes = bytes(pkt[TCP].payload)
            hostname_or_sni = cls._extract_sni(tcp_payload) if tcp_payload else None

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
            udp_payload: bytes = bytes(pkt[UDP].payload)
            # Extract DNS query name from UDP port 53 traffic.
            hostname_or_sni = (
                cls._extract_dns_query(udp_payload)
                if udp_payload and dst_port == 53
                else None
            )
            seq = 0
            ack = 0
        else:
            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            hostname_or_sni = None
            seq = 0
            ack = 0

        raw_input = f"{protocol} {dst_ip}:{dst_port}"

        return ParsedNetworkAction(
            binary="<network>",
            raw_input=raw_input,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            hostname_or_sni=hostname_or_sni,
            raw_bytes=raw_bytes,
            direction=direction,
            seq=seq,
            ack=ack,
        )

    # ── Direction inference ────────────────────────────────────────────────────

    @staticmethod
    def _infer_direction(src_ip: str) -> str:
        """Infer packet direction from the source IP.

        WHY private-IP heuristic: in the Phase 2 docker-compose setup, the jail
        has a private RFC1918 IP on the warden_bridge network. Any packet whose
        source is a private or loopback IP is almost certainly originating from
        the jail (outbound). Packets from public IPs are inbound responses.

        This is a heuristic — see the class-level TODO(phase5) for the precise fix.
        """
        # Loopback
        if src_ip.startswith("127."):
            return "outbound"
        parts = src_ip.split(".")
        if len(parts) != 4:
            return "outbound"  # Fail-safe: treat unparseable src as outbound
        try:
            first = int(parts[0])
            second = int(parts[1])
        except ValueError:
            return "outbound"

        # RFC 1918 private ranges
        if first == 10:
            return "outbound"
        if first == 172 and 16 <= second <= 31:
            return "outbound"
        if first == 192 and second == 168:
            return "outbound"

        return "inbound"

    # ── TLS SNI extraction ─────────────────────────────────────────────────────

    @staticmethod
    def _extract_sni(tcp_payload: bytes) -> Optional[str]:
        """Extract the TLS SNI hostname from a TLS ClientHello payload.

        WHY manual parsing (not Scapy's TLS layer):
          Scapy's TLS dissector requires load_layer("tls") and has changed its
          API between versions. The ClientHello structure is a fixed-offset
          binary format defined in RFC 5246 / RFC 8446 — parsing it manually
          is ~40 lines and immune to library churn.

        TLS record layout (from RFC 5246 §6.2):
          Byte 0:     Content Type (0x16 = Handshake)
          Bytes 1-2:  Protocol Version (e.g. 0x0303 = TLS 1.2)
          Bytes 3-4:  Record Length (big-endian uint16)
          Byte 5:     Handshake Type (0x01 = ClientHello)
          Bytes 6-8:  Handshake Length (big-endian uint24)
          Bytes 9-10: Client Version
          Bytes 11-42:Random (32 bytes)
          Byte 43:    Session ID Length
          ...variable fields follow...

        SNI extension layout (RFC 6066 §3):
          Extension Type:  0x0000
          Extension Length: uint16
          List Length:      uint16
          Name Type:        0x00 (host_name)
          Name Length:      uint16
          Name:             ASCII hostname bytes

        Returns the SNI hostname string, or None if not found or malformed.
        """
        # Minimum viable TLS record: 5 bytes header + 4 bytes handshake header
        if len(tcp_payload) < 9:
            return None

        # Check TLS Handshake record type (0x16) and ClientHello (0x01)
        if tcp_payload[0] != 0x16:
            return None
        if tcp_payload[5] != 0x01:
            return None

        try:
            pos = 9  # Start after: record header (5) + handshake type (1) + length (3)

            # Client Version (2 bytes) — skip
            pos += 2
            # Random (32 bytes) — skip
            pos += 32

            if pos >= len(tcp_payload):
                return None

            # Session ID Length (1 byte) + Session ID (variable)
            session_id_len = tcp_payload[pos]
            pos += 1 + session_id_len

            if pos + 2 > len(tcp_payload):
                return None

            # Cipher Suites Length (2 bytes) + Cipher Suites (variable)
            cipher_suites_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
            pos += 2 + cipher_suites_len

            if pos + 1 > len(tcp_payload):
                return None

            # Compression Methods Length (1 byte) + Compression Methods (variable)
            compression_methods_len = tcp_payload[pos]
            pos += 1 + compression_methods_len

            if pos + 2 > len(tcp_payload):
                return None

            # Extensions Length (2 bytes)
            extensions_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
            pos += 2

            extensions_end = pos + extensions_len

            # Walk extensions looking for SNI (type 0x0000)
            while pos + 4 <= extensions_end and pos + 4 <= len(tcp_payload):
                ext_type = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
                ext_len = struct.unpack("!H", tcp_payload[pos + 2:pos + 4])[0]
                pos += 4

                if ext_type == 0x0000:  # SNI extension
                    # SNI list length (2 bytes)
                    if pos + 2 > len(tcp_payload):
                        return None
                    # sni_list_len = struct.unpack("!H", tcp_payload[pos:pos+2])[0]
                    pos += 2
                    # Name type (1 byte): 0x00 = host_name
                    if pos >= len(tcp_payload) or tcp_payload[pos] != 0x00:
                        return None
                    pos += 1
                    # Name length (2 bytes)
                    if pos + 2 > len(tcp_payload):
                        return None
                    name_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
                    pos += 2
                    if pos + name_len > len(tcp_payload):
                        return None
                    return tcp_payload[pos:pos + name_len].decode("ascii")

                pos += ext_len

        except (struct.error, IndexError, UnicodeDecodeError):
            return None

        return None

    # ── DNS query extraction ───────────────────────────────────────────────────

    @staticmethod
    def _extract_dns_query(udp_payload: bytes) -> Optional[str]:
        """Extract the first DNS query name from a DNS message payload.

        DNS message layout (RFC 1035 §4.1):
          Bytes 0-1:  Transaction ID
          Bytes 2-3:  Flags (QR bit at 0x8000 — 0=query, 1=response)
          Bytes 4-5:  QDCOUNT (number of questions)
          Bytes 6-11: ANCOUNT, NSCOUNT, ARCOUNT (answer/authority/additional counts)
          Byte 12+:   Question section

        DNS name encoding: labels separated by length-prefixed bytes, terminated
        by a zero-length label (0x00). E.g. "api.example.com" is encoded as:
          \x03api\x07example\x03com\x00

        Returns the first query name as a dotted string, or None if malformed
        or if this is a DNS response (not a query).

        WHY only the first question: multiple questions in one DNS message are
        technically legal but effectively never used in practice. Parsing all of
        them would add complexity with zero real-world benefit for Phase 2.
        """
        # Minimum DNS header is 12 bytes
        if len(udp_payload) < 12:
            return None

        try:
            flags = struct.unpack("!H", udp_payload[2:4])[0]
            # QR bit (bit 15): 0=query, 1=response. Skip responses.
            if flags & 0x8000:
                return None

            qdcount = struct.unpack("!H", udp_payload[4:6])[0]
            if qdcount == 0:
                return None

            # Parse the first question name starting at byte 12
            pos = 12
            labels: list[str] = []

            while pos < len(udp_payload):
                length = udp_payload[pos]
                pos += 1

                if length == 0:
                    break  # Root label — end of name

                # WHY check for compression pointer (top 2 bits == 11):
                # DNS messages can use name compression (pointer to earlier offset).
                # In a UDP DNS query from the jail, the question section typically
                # does NOT use compression (there's nothing earlier to point to),
                # but we handle it gracefully rather than crashing.
                if (length & 0xC0) == 0xC0:
                    # Compression pointer — not expected in queries, skip it
                    return ".".join(labels) if labels else None

                if pos + length > len(udp_payload):
                    return None

                label = udp_payload[pos:pos + length].decode("ascii")
                labels.append(label)
                pos += length

            return ".".join(labels) if labels else None

        except (struct.error, UnicodeDecodeError, IndexError):
            return None
