"""
tests/test_rst_injector.py — Unit tests for Phase 2.5 Step 3 TCP RST injection.
"""

from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP
import pytest

from sidecar.rst_injector import build_rst_packet, send_rst


class TestBuildRstPacket:
    def test_builds_correct_packet(self):
        """
        build_rst_packet produces correct IP src/dst, TCP src/dst port, RST
        flag set, and the seq/ack values reasoned through.
        """
        # Simulated observed packet fields (e.g. from jail to external)
        obs_src_ip = "192.168.1.10"
        obs_dst_ip = "93.184.216.34"
        obs_src_port = 54321
        obs_dst_port = 443
        obs_seq = 1000
        obs_ack = 5000

        # Build RST
        rst_bytes = build_rst_packet(
            src_ip=obs_src_ip,
            src_port=obs_src_port,
            dst_ip=obs_dst_ip,
            dst_port=obs_dst_port,
            seq=obs_seq,
            ack=obs_ack
        )

        # Parse with Scapy
        pkt = IP(rst_bytes)
        assert TCP in pkt

        # Spoofed packet should be FROM server TO client
        assert pkt[IP].src == obs_dst_ip
        assert pkt[IP].dst == obs_src_ip
        assert pkt[TCP].sport == obs_dst_port
        assert pkt[TCP].dport == obs_src_port

        # Seq should be what the client acknowledged (obs_ack)
        assert pkt[TCP].seq == obs_ack
        # Ack should be what the client sent (obs_seq)
        assert pkt[TCP].ack == obs_seq

        # Flags must include RST (R) and ACK (A)
        assert "R" in pkt[TCP].flags
        assert "A" in pkt[TCP].flags


class TestSendRst:
    def test_send_rst_success(self):
        """send_rst success path: mock the socket, assert sendto was called."""
        dummy_bytes = b"dummy_packet_bytes"
        dst_ip = "192.168.1.10"

        mock_sock_instance = MagicMock()
        mock_sock_instance.__enter__.return_value = mock_sock_instance

        with patch("socket.socket", return_value=mock_sock_instance) as mock_socket:
            result = send_rst(dummy_bytes, dst_ip)

        assert result is True
        mock_socket.assert_called_once()
        mock_sock_instance.sendto.assert_called_once_with(dummy_bytes, (dst_ip, 0))

    def test_send_rst_failure(self):
        """
        send_rst failure path: mock the socket to raise, assert send_rst
        returns False and does not raise.
        """
        dummy_bytes = b"dummy_packet_bytes"
        dst_ip = "192.168.1.10"

        mock_sock_instance = MagicMock()
        mock_sock_instance.__enter__.return_value = mock_sock_instance
        mock_sock_instance.sendto.side_effect = PermissionError("Operation not permitted")

        with patch("socket.socket", return_value=mock_sock_instance):
            result = send_rst(dummy_bytes, dst_ip)

        # Must not raise, must return False
        assert result is False
