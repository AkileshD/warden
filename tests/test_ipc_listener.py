import json
import socket
import time
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from daemon.ipc_listener import IPCListener
from daemon.inspectors.base import Decision
from daemon.ledger.logger import Logger, LedgerEvent


import tempfile

def test_ipc_listener_receives_and_logs():
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        socket_path = Path(d) / "warden.sock"
        mock_logger = MagicMock(spec=Logger)
        
        # Setup mock to return an action_id when resolve_pending_action is called
        mock_logger.resolve_pending_action.return_value = "fake-action-id"

        listener = IPCListener(logger=mock_logger, socket_path=str(socket_path))
        listener.start()
        
        # Wait for the socket to be bound
        time.sleep(0.1)
        assert socket_path.exists()
        
        # Send a JSON network event via socket
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        
        payload = {
            "timestamp": 123456.78,
            "verdict": {
                "decision": "BLOCK",
                "reason": "blocked by rule",
                "source_inspector": "NetworkInspector"
            },
            "parsed_action": {
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "protocol": "TCP",
                "hostname_or_sni": "example.com",
                "direction": "outbound",
                "raw_input": "TCP 1.2.3.4:443"
            }
        }
        
        client_sock.sendto(json.dumps(payload).encode("utf-8"), str(socket_path))
        client_sock.close()
        
        # Wait for processing
        time.sleep(0.1)
        
        # Verify the logger was called correctly
        mock_logger.cleanup_pending_actions.assert_called_once()
        mock_logger.resolve_pending_action.assert_called_once_with(123456.78)
        
        assert mock_logger.record.call_count == 1
        event: LedgerEvent = mock_logger.record.call_args[0][0]
        
        assert event.action_id == "fake-action-id"
        assert event.event_type == "network"
        assert event.verdict.decision == Decision.BLOCK
        assert event.verdict.reason == "blocked by rule"
        assert event.verdict.source_inspector == "NetworkInspector"
        
        # Verify parsed action fields
        assert event.parsed_action.binary == "<network>"
        assert event.parsed_action.dst_ip == "1.2.3.4"
        assert event.parsed_action.dst_port == 443
        assert event.parsed_action.hostname_or_sni == "example.com"
        assert event.parsed_action.raw_input == "TCP 1.2.3.4:443"
        
        # Stop the listener
        listener.stop()
        assert not socket_path.exists()

def test_ipc_listener_survives_garbage_input():
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        socket_path = Path(d) / "warden_garbage.sock"
        mock_logger = MagicMock(spec=Logger)
        
        listener = IPCListener(logger=mock_logger, socket_path=str(socket_path))
        listener.start()
        
        time.sleep(0.1)
        assert socket_path.exists()
        
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        
        # 1. Send completely invalid JSON
        client_sock.sendto(b"not json at all { { [", str(socket_path))
        
        # 2. Send valid JSON but not a dict
        client_sock.sendto(b'["just", "an", "array"]', str(socket_path))
        
        # 3. Send JSON dict with missing/bad fields
        client_sock.sendto(b'{"verdict": {"decision": "NOT_AN_ENUM_VALUE"}}', str(socket_path))
        
        client_sock.close()
        time.sleep(0.1)
        
        # The thread should still be running and not crashed
        assert listener._thread is not None
        assert listener._thread.is_alive()
        
        # Logger should not have recorded anything for the garbage
        assert mock_logger.record.call_count == 0
        
        listener.stop()
