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
        token_path = Path(d) / "token.txt"
        mock_logger = MagicMock(spec=Logger)
        
        # Setup mock to return an action_id when resolve_pending_action is called
        mock_logger.resolve_pending_action.return_value = "fake-action-id"

        # Use an ephemeral port for testing
        listener = IPCListener(logger=mock_logger, host="127.0.0.1", port=0, token_path=str(token_path))
        listener.start()
        
        # Wait for the socket to be bound
        time.sleep(0.1)
        assert token_path.exists()
        
        # Get the actual port it bound to
        bound_port = listener._sock.getsockname()[1]
        
        # Read the generated token
        token = token_path.read_text()
        
        # Send a JSON network event via UDP
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        payload = {
            "timestamp": 123456.78,
            "token": token,
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
        
        client_sock.sendto(json.dumps(payload).encode("utf-8"), ("127.0.0.1", bound_port))
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
        assert not token_path.exists()

def test_ipc_listener_survives_garbage_input():
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        token_path = Path(d) / "token.txt"
        mock_logger = MagicMock(spec=Logger)
        
        listener = IPCListener(logger=mock_logger, host="127.0.0.1", port=0, token_path=str(token_path))
        listener.start()
        
        time.sleep(0.1)
        assert token_path.exists()
        
        bound_port = listener._sock.getsockname()[1]
        token = token_path.read_text()
        
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 1. Send completely invalid JSON
        client_sock.sendto(b"not json at all { { [", ("127.0.0.1", bound_port))
        
        # 2. Send valid JSON but not a dict
        client_sock.sendto(b'["just", "an", "array"]', ("127.0.0.1", bound_port))
        
        # 3. Send JSON dict with missing/bad fields
        client_sock.sendto(json.dumps({"token": token, "verdict": {"decision": "NOT_AN_ENUM_VALUE"}}).encode(), ("127.0.0.1", bound_port))
        
        # 4. Send valid JSON but missing/wrong token
        client_sock.sendto(json.dumps({"token": "wrong_token", "timestamp": 123}).encode(), ("127.0.0.1", bound_port))
        
        client_sock.close()
        time.sleep(0.1)
        
        # The thread should still be running and not crashed
        assert listener._thread is not None
        assert listener._thread.is_alive()
        
        # Logger should not have recorded anything for the garbage
        assert mock_logger.record.call_count == 0
        
        listener.stop()
