import sys
import socket
from scapy.all import IP, TCP

def build_rst_packet(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    seq: int,
    ack: int,
) -> bytes:
    """
    Constructs a raw TCP RST packet to tear down a connection cleanly.

    The arguments provided must be from the OBSERVED packet (the packet that was
    intercepted and dropped, typically the client's packet to the server).
    This function will automatically swap the source and destination fields to
    craft a spoofed response FROM the server back TO the client.
    """
    # WHY seq/ack mapping:
    # We are dropping a packet from the client (Jail) to the server (External).
    # The client's packet has seq=X, ack=Y.
    # We want to tear down the client's socket so it doesn't hang.
    # To do this, we must spoof a packet FROM the server TO the client.
    # The client expects the server's next sequence number to be the exact
    # value the client just acknowledged (Y).
    # Therefore, the spoofed RST packet's `seq` must be the observed `ack`.
    # We also set the spoofed `ack` to the observed `seq` (plus payload length
    # ideally, but for an RST, simply sending the correct seq is enough to kill
    # the connection; we use the observed seq for consistency).
    spoofed_src_ip = dst_ip
    spoofed_dst_ip = src_ip
    spoofed_src_port = dst_port
    spoofed_dst_port = src_port
    
    spoofed_seq = ack
    spoofed_ack = seq
    
    # Flags "R" = RST, "A" = ACK. Setting RST|ACK ensures it's accepted.
    pkt = IP(src=spoofed_src_ip, dst=spoofed_dst_ip) / TCP(
        sport=spoofed_src_port,
        dport=spoofed_dst_port,
        flags="RA",
        seq=spoofed_seq,
        ack=spoofed_ack
    )
    
    return bytes(pkt)


def send_rst(packet_bytes: bytes, dst_ip: str) -> bool:
    """
    Opens a raw socket and sends the crafted RST packet bytes.
    
    This is the ONLY place in the codebase where a raw socket is opened.
    It requires the NET_RAW capability (granted in docker-compose.yml).
    Errors are swallowed and logged to stderr to prevent crashing the
    NFQUEUE packet processing loop.
    """
    try:
        # We need an AF_INET SOCK_RAW socket with IPPROTO_RAW to send a
        # complete IP packet (including the IP header we constructed).
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            # IP_HDRINCL is needed on some platforms to tell the kernel we
            # provide the IP header, though IPPROTO_RAW often implies it on Linux.
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(packet_bytes, (dst_ip, 0))
        return True
    except Exception as e:
        print(f"[warden-sidecar] Warning: failed to send RST packet to {dst_ip}: {e}", file=sys.stderr)
        return False
