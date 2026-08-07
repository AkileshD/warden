"""
tests/test_packet_parser.py — Unit tests for daemon/parser/packet_parser.py

Tests construct synthetic packets with Scapy (bytes(pkt)), pass them through
PacketParser.parse(), and assert the returned ParsedNetworkAction fields.

WHY Scapy for test packet construction (not raw bytes written by hand):
  Scapy computes IP header checksums, lengths, and other derived fields correctly.
  Hand-crafting valid raw IP/TCP/UDP bytes is error-prone and brittle across
  platforms. Scapy gives us a clean API and produces real, valid packets.

WHY TLS ClientHello bytes are constructed manually in the SNI test:
  Scapy's TLS layer requires load_layer("tls") and crafting a full ClientHello
  via Scapy's API is verbose and version-sensitive. Since PacketParser._extract_sni()
  parses the binary format directly, the test constructs the minimal binary
  representation of a ClientHello by hand — this also proves that the parser is
  exercising its own byte-level logic, not some Scapy round-trip.

Coverage:
  1. Plain TCP packet (no TLS payload) → protocol=TCP, no SNI
  2. UDP DNS query → protocol=UDP, hostname_or_sni=query name
  3. TLS ClientHello with SNI → protocol=TCP, hostname_or_sni=SNI hostname
  4. Non-IP bytes (garbage) → graceful fallback, never raises
  5. Direction inference: private src IP → outbound, public src IP → inbound
  6. ParsedNetworkAction is a subtype of ParsedAction (Inspector contract)
  7. DNS response (QR=1) → hostname_or_sni=None (responses not parsed)
  8. TCP on port 443 with no TLS payload → hostname_or_sni=None
"""

import struct
import pytest

from scapy.all import IP, TCP, UDP, Raw

from daemon.parser.packet_parser import PacketParser, ParsedNetworkAction
from daemon.parser.shell_parser import ParsedAction


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_tcp_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "93.184.216.34",
    sport: int = 54321,
    dport: int = 80,
    seq: int = 0,
    ack: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build a raw TCP packet using Scapy."""
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack)
    if payload:
        pkt = pkt / Raw(load=payload)
    return bytes(pkt)


def make_udp_packet(
    src_ip: str = "172.17.0.2",
    dst_ip: str = "8.8.8.8",
    sport: int = 53422,
    dport: int = 53,
    payload: bytes = b"",
) -> bytes:
    """Build a raw UDP packet using Scapy."""
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / Raw(load=payload)
    return bytes(pkt)


def make_dns_query_payload(qname: str) -> bytes:
    """
    Construct a minimal valid DNS query payload for qname.

    Layout (RFC 1035):
      Transaction ID: 0x1234
      Flags:          0x0100  (standard query, recursion desired)
      QDCOUNT:        1
      ANCOUNT:        0
      NSCOUNT:        0
      ARCOUNT:        0
      Question:       encoded qname + QTYPE (A=1) + QCLASS (IN=1)
    """
    # Encode the domain name as length-prefixed labels + null terminator
    encoded_name = b""
    for label in qname.rstrip(".").split("."):
        label_bytes = label.encode("ascii")
        encoded_name += bytes([len(label_bytes)]) + label_bytes
    encoded_name += b"\x00"  # root label (end of name)

    header = struct.pack("!HHHHH",
        0x1234,  # transaction ID
        0x0100,  # flags: standard query, RD=1
        1,       # QDCOUNT
        0,       # ANCOUNT
        0,       # NSCOUNT
    ) + struct.pack("!H", 0)  # ARCOUNT

    question = encoded_name + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN

    return header + question


def make_tls_client_hello_payload(sni: str) -> bytes:
    """
    Construct a minimal TLS 1.2 ClientHello payload with a single SNI extension.

    This is a hand-crafted binary representation of the TLS record. It contains
    only the fields that PacketParser._extract_sni() reads, padded minimally.
    It would not be accepted by a real TLS server (incomplete cipher suite list etc.)
    but is sufficient to exercise the parser.

    Structure:
      TLS Record Header (5 bytes):
        Content Type:  0x16 (Handshake)
        Version:       0x03 0x03 (TLS 1.2)
        Record Length: uint16

      Handshake Header (4 bytes):
        Handshake Type:   0x01 (ClientHello)
        Length:           uint24

      ClientHello body:
        Client Version:   2 bytes (0x03 0x03)
        Random:           32 bytes (zeros)
        Session ID Len:   1 byte  (0 = no session)
        Cipher Suites Len:2 bytes
        Cipher Suites:    2 bytes (one suite: TLS_RSA_WITH_AES_128_CBC_SHA)
        Compression Len:  1 byte
        Compression:      1 byte  (0 = null)
        Extensions Len:   2 bytes
        SNI Extension:
          Type:           0x00 0x00
          Ext Length:     uint16
          List Length:    uint16
          Name Type:      0x00 (host_name)
          Name Length:    uint16
          Name:           ASCII bytes
    """
    sni_bytes = sni.encode("ascii")
    sni_name_len = len(sni_bytes)

    # SNI extension data body (after extension type + ext length)
    sni_ext_body = (
        struct.pack("!H", sni_name_len + 3)  # SNI list length
        + b"\x00"                             # name type: host_name
        + struct.pack("!H", sni_name_len)     # name length
        + sni_bytes                           # the hostname
    )

    # Full extension (type + length + body)
    sni_extension = (
        struct.pack("!HH", 0x0000, len(sni_ext_body))  # type=SNI, ext_length
        + sni_ext_body
    )

    # ClientHello body (before extensions)
    client_version = b"\x03\x03"          # TLS 1.2
    random_bytes = b"\x00" * 32           # 32-byte random
    session_id = b"\x00"                  # session ID length = 0
    cipher_suites = b"\x00\x02\x00\x2F"  # length=2, one suite (0x002F)
    compression = b"\x01\x00"            # length=1, null compression

    extensions_len = struct.pack("!H", len(sni_extension))
    hello_body = (
        client_version
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_len
        + sni_extension
    )

    # Handshake header: type=ClientHello (0x01) + uint24 length
    hello_len = len(hello_body)
    handshake_header = bytes([0x01]) + struct.pack("!I", hello_len)[1:]  # uint24

    # TLS record header
    handshake_message = handshake_header + hello_body
    record_header = (
        b"\x16"                                        # Content Type: Handshake
        + b"\x03\x03"                                  # Version: TLS 1.2
        + struct.pack("!H", len(handshake_message))    # Record Length
    )

    return record_header + handshake_message


# ── Test: ParsedNetworkAction is a subtype of ParsedAction ────────────────────

class TestParsedNetworkActionInheritance:
    """Verify the Inspector contract: ParsedNetworkAction IS-A ParsedAction."""

    def test_isinstance_of_parsed_action(self):
        raw = make_tcp_packet()
        result = PacketParser.parse(raw)
        assert isinstance(result, ParsedAction), (
            "ParsedNetworkAction must be a subtype of ParsedAction — "
            "otherwise NetworkInspector cannot satisfy the Inspector interface contract."
        )

    def test_isinstance_of_parsed_network_action(self):
        raw = make_tcp_packet()
        result = PacketParser.parse(raw)
        assert isinstance(result, ParsedNetworkAction)

    def test_has_binary_field(self):
        """ParsedAction.binary must be present (used by Inspector chain and logger)."""
        raw = make_tcp_packet()
        result = PacketParser.parse(raw)
        assert result.binary == "<network>"

    def test_has_raw_input_field(self):
        """ParsedAction.raw_input must be a human-readable summary, not empty."""
        raw = make_tcp_packet(dport=443)
        result = PacketParser.parse(raw)
        assert result.raw_input != ""
        assert "TCP" in result.raw_input


# ── Test: Plain TCP packet ─────────────────────────────────────────────────────

class TestPlainTCPPacket:
    """Parse a plain TCP packet with no application payload."""

    def test_protocol_is_tcp(self):
        raw = make_tcp_packet(dst_ip="1.2.3.4", dport=80)
        result = PacketParser.parse(raw)
        assert result.protocol == "TCP"

    def test_dst_ip_correct(self):
        raw = make_tcp_packet(dst_ip="93.184.216.34", dport=80)
        result = PacketParser.parse(raw)
        assert result.dst_ip == "93.184.216.34"

    def test_dst_port_correct(self):
        raw = make_tcp_packet(dport=8080)
        result = PacketParser.parse(raw)
        assert result.dst_port == 8080

    def test_seq_correct(self):
        raw = make_tcp_packet(seq=12345678)
        result = PacketParser.parse(raw)
        assert result.seq == 12345678

    def test_ack_correct(self):
        raw = make_tcp_packet(ack=87654321)
        result = PacketParser.parse(raw)
        assert result.ack == 87654321

    def test_no_sni_for_plain_tcp(self):
        """Plain TCP with no payload → no SNI extracted."""
        raw = make_tcp_packet(dport=443)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni is None

    def test_raw_bytes_preserved(self):
        raw = make_tcp_packet(dst_ip="10.0.0.1", dport=22)
        result = PacketParser.parse(raw)
        assert result.raw_bytes == raw

    def test_direction_outbound_for_private_src(self):
        """Source IP in 192.168.x.x range → outbound (from jail)."""
        raw = make_tcp_packet(src_ip="192.168.1.10", dst_ip="8.8.8.8", dport=443)
        result = PacketParser.parse(raw)
        assert result.direction == "outbound"

    def test_direction_outbound_for_172_16_range(self):
        """Source IP in 172.16.x.x range (Docker default bridge) → outbound."""
        raw = make_tcp_packet(src_ip="172.17.0.2", dst_ip="8.8.8.8", dport=443)
        result = PacketParser.parse(raw)
        assert result.direction == "outbound"

    def test_direction_inbound_for_public_src(self):
        """Source IP is a public address → inbound (response from internet)."""
        raw = make_tcp_packet(src_ip="93.184.216.34", dst_ip="172.17.0.2", dport=54321)
        result = PacketParser.parse(raw)
        assert result.direction == "inbound"

    def test_src_ip_populated(self):
        """src_ip is populated from the IP layer source address."""
        raw = make_tcp_packet(src_ip="192.168.1.10", dst_ip="93.184.216.34", dport=80)
        result = PacketParser.parse(raw)
        assert result.src_ip == "192.168.1.10"

    def test_src_port_populated(self):
        """src_port is populated from the TCP source port."""
        raw = make_tcp_packet(sport=54321, dport=80)
        result = PacketParser.parse(raw)
        assert result.src_port == 54321

    def test_src_and_dst_are_distinct(self):
        """src_ip/src_port must not equal dst_ip/dst_port for a realistic packet."""
        raw = make_tcp_packet(
            src_ip="192.168.1.10", sport=54321,
            dst_ip="93.184.216.34",  dport=443,
        )
        result = PacketParser.parse(raw)
        assert result.src_ip != result.dst_ip
        assert result.src_port != result.dst_port


# ── Test: UDP DNS query ────────────────────────────────────────────────────────

class TestUDPDNSQuery:
    """Parse a UDP packet containing a DNS query."""

    def test_protocol_is_udp(self):
        payload = make_dns_query_payload("api.example.com")
        raw = make_udp_packet(dst_ip="8.8.8.8", dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.protocol == "UDP"

    def test_dst_ip_correct(self):
        payload = make_dns_query_payload("example.com")
        raw = make_udp_packet(dst_ip="8.8.8.8", dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.dst_ip == "8.8.8.8"

    def test_dst_port_is_53(self):
        payload = make_dns_query_payload("example.com")
        raw = make_udp_packet(dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.dst_port == 53

    def test_dns_query_name_extracted(self):
        payload = make_dns_query_payload("api.example.com")
        raw = make_udp_packet(dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "api.example.com"

    def test_single_label_domain(self):
        payload = make_dns_query_payload("localhost")
        raw = make_udp_packet(dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "localhost"

    def test_deep_subdomain(self):
        payload = make_dns_query_payload("a.b.c.d.example.com")
        raw = make_udp_packet(dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "a.b.c.d.example.com"

    def test_udp_non_dns_port_has_no_hostname(self):
        """UDP on a non-53 port should not attempt DNS parsing."""
        raw = make_udp_packet(dport=1234, payload=b"\x00\x01\x02\x03")
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni is None

    def test_dns_response_ignored(self):
        """DNS responses (QR=1) should not extract a query name."""
        # Construct a DNS response: flags with QR=1 (0x8180 = standard response)
        response_payload = struct.pack("!HHHHHH",
            0x1234,   # transaction ID
            0x8180,   # flags: QR=1 (response), AA=0, TC=0, RD=1, RA=1
            1,        # QDCOUNT
            1,        # ANCOUNT
            0, 0,     # NSCOUNT, ARCOUNT
        )
        # Add a minimal question section
        response_payload += b"\x03api\x07example\x03com\x00"
        response_payload += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
        raw = make_udp_packet(dport=53, payload=response_payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni is None, (
            "DNS responses should not be parsed for query names — "
            "we only care about what the agent is ASKING for, not what it received."
        )

    def test_src_ip_populated_udp(self):
        """src_ip is populated for UDP packets."""
        payload = make_dns_query_payload("example.com")
        raw = make_udp_packet(src_ip="172.17.0.2", dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.src_ip == "172.17.0.2"

    def test_src_port_populated_udp(self):
        """src_port is populated from the UDP source port."""
        payload = make_dns_query_payload("example.com")
        raw = make_udp_packet(sport=53422, dport=53, payload=payload)
        result = PacketParser.parse(raw)
        assert result.src_port == 53422


# ── Test: TLS ClientHello with SNI ────────────────────────────────────────────

class TestTLSClientHelloSNI:
    """Parse a TCP packet containing a TLS ClientHello with an SNI extension."""

    def test_sni_extracted(self):
        tls_payload = make_tls_client_hello_payload("api.openai.com")
        raw = make_tcp_packet(dst_ip="104.18.7.192", dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "api.openai.com"

    def test_protocol_is_tcp(self):
        tls_payload = make_tls_client_hello_payload("api.openai.com")
        raw = make_tcp_packet(dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.protocol == "TCP"

    def test_dst_port_443(self):
        tls_payload = make_tls_client_hello_payload("api.openai.com")
        raw = make_tcp_packet(dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.dst_port == 443

    def test_sni_with_subdomain(self):
        tls_payload = make_tls_client_hello_payload("sub.domain.example.com")
        raw = make_tcp_packet(dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "sub.domain.example.com"

    def test_sni_on_non_443_port(self):
        """SNI extraction is attempted on any TCP payload that looks like a ClientHello,
        regardless of port — some servers use TLS on non-standard ports."""
        tls_payload = make_tls_client_hello_payload("internal.service.example")
        raw = make_tcp_packet(dport=8443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni == "internal.service.example"

    def test_non_tls_payload_on_443_returns_no_sni(self):
        """Plain HTTP (or garbage) on port 443 should not produce a false SNI."""
        http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        raw = make_tcp_packet(dport=443, payload=http_payload)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni is None

    def test_truncated_tls_payload_returns_no_sni(self):
        """A valid-looking TLS record header with truncated body → no SNI, no crash."""
        truncated = b"\x16\x03\x03\x00\x50\x01\x00\x00\x4C"  # valid header, body missing
        raw = make_tcp_packet(dport=443, payload=truncated)
        result = PacketParser.parse(raw)
        assert result.hostname_or_sni is None

    def test_src_ip_populated_tls(self):
        """src_ip is populated for TLS ClientHello packets."""
        tls_payload = make_tls_client_hello_payload("api.openai.com")
        raw = make_tcp_packet(src_ip="192.168.1.10", dst_ip="104.18.7.192", dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.src_ip == "192.168.1.10"

    def test_src_port_populated_tls(self):
        """src_port is populated for TLS ClientHello packets."""
        tls_payload = make_tls_client_hello_payload("api.openai.com")
        raw = make_tcp_packet(sport=55000, dport=443, payload=tls_payload)
        result = PacketParser.parse(raw)
        assert result.src_port == 55000


# ── Test: Graceful fallback on garbage input ──────────────────────────────────

class TestGracefulFallback:
    """PacketParser.parse() must never raise, even on completely invalid input."""

    def test_empty_bytes(self):
        result = PacketParser.parse(b"")
        assert isinstance(result, ParsedNetworkAction)
        assert result.protocol == "OTHER"

    def test_random_garbage(self):
        result = PacketParser.parse(b"\xff\xfe\xfd\xfc" * 20)
        assert isinstance(result, ParsedNetworkAction)
        assert result.protocol == "OTHER"

    def test_raw_bytes_preserved_on_fallback(self):
        garbage = b"\xde\xad\xbe\xef"
        result = PacketParser.parse(garbage)
        assert result.raw_bytes == garbage

    def test_direction_defaults_to_outbound_on_fallback(self):
        result = PacketParser.parse(b"\x00" * 10)
        assert result.direction == "outbound"

    def test_src_ip_is_unknown_on_fallback(self):
        """Unparseable input falls back to src_ip='unknown'."""
        result = PacketParser.parse(b"\xff" * 4)
        assert result.src_ip == "unknown"

    def test_src_port_is_zero_on_fallback(self):
        """Unparseable input falls back to src_port=0."""
        result = PacketParser.parse(b"\xff" * 4)
        assert result.src_port == 0
