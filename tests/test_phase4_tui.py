import json
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from clients.tui.app import WardenTUI, format_action, SummaryRow

def test_format_action_shell_command():
    blob = json.dumps({"binary": "ls", "args": ["-l", "/tmp"]})
    res = format_action("shell_command", blob)
    assert res == "ls -l /tmp"

def test_format_action_shell_no_args():
    blob = json.dumps({"binary": "pwd"})
    res = format_action("shell_command", blob)
    assert res == "pwd"

def test_format_action_network_event():
    blob = json.dumps({"dst_ip": "1.1.1.1", "dst_port": 443, "protocol": "TCP", "hostname_or_sni": "cloudflare-dns.com"})
    res = format_action("network", blob)
    assert res == "net \u2192 cloudflare-dns.com:443"

def test_format_action_network_unknown_source():
    # If binary was 'unknown source', the event itself is still a network event
    blob = json.dumps({"dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP"})
    res = format_action("network", blob)
    assert res == "net \u2192 8.8.8.8:53"

def test_format_action_malformed_json():
    res = format_action("shell_command", "not json {")
    assert res == "<malformed json>"

def test_db_connection_is_read_only():
    """Ensure that the database connection enforces read-only mode."""
    app = WardenTUI()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("sqlite3.connect") as mock_connect:
            app._get_db_connection()
            # Assert sqlite3.connect was called with the ro URI
            mock_connect.assert_called_once()
            args, kwargs = mock_connect.call_args
            assert args[0].endswith("?mode=ro")
            assert kwargs.get("uri") is True

@pytest.mark.asyncio
@patch("clients.tui.app.subprocess.run")
@patch("clients.tui.app.os.access")
@patch("pathlib.Path.exists")
async def test_update_status(mock_sock_exists, mock_access, mock_run):
    """Test passive status detection logic."""
    app = WardenTUI()
    
    # Mock socket to be up
    mock_sock_exists.return_value = True
    mock_access.return_value = True
    
    # Mock docker compose ps to return jail and warden-sidecar
    mock_proc = MagicMock()
    mock_proc.stdout = "jail\nwarden-sidecar\n"
    mock_run.return_value = mock_proc
    
    async with app.run_test() as pilot:
        # Give it a moment to mount
        await pilot.pause(0.1)
        header = app.query_one("#header")
        assert "jail: [#639922]up" in header.status_text
        assert "sidecar: [#639922]up" in header.status_text
        assert "socket: [#639922]connected" in header.status_text
        
        # Test down state
        mock_sock_exists.return_value = False
        mock_proc.stdout = ""
        app.update_status()
        
        assert "jail: [#E24B4A]down" in header.status_text
        assert "sidecar: [#E24B4A]down" in header.status_text
        assert "socket: [#E24B4A]disconnected" in header.status_text

@pytest.mark.asyncio
@patch("pathlib.Path.exists", return_value=False)
async def test_verdict_rendering(mock_exists):
    """Test that events render in correct columns with correct colors/borders."""
    app = WardenTUI()
    
    events = [
        {"verdict": "ALLOW", "timestamp": "2024-01-01T00:00:00Z", "event_type": "shell_command", "parsed_action": '{"binary":"ls"}', "reason": ""},
        {"verdict": "BLOCK", "timestamp": "2024-01-01T00:01:00Z", "event_type": "shell_command", "parsed_action": '{"binary":"rm"}', "reason": "blocked"},
        {"verdict": "FLAG", "timestamp": "2024-01-01T00:02:00Z", "event_type": "shell_command", "parsed_action": '{"binary":"cat"}', "reason": "flagged"},
    ]
    
    counts = {"ALLOW": 1, "BLOCK": 1, "FLAG": 1}
    
    async with app.run_test() as pilot:
        await app._update_events_ui(events, counts)
        await pilot.pause()
        
        allowed_content = app.query_one("#allowed-content")
        intercepted_content = app.query_one("#intercepted-content")
        
        allowed_render = str(allowed_content.render())
        assert "2024-01-01T00:00:00Z" in allowed_render
        assert "ls" in allowed_render
        
        intercepted_render = str(intercepted_content.render())
        assert "2024-01-01T00:01:00Z" in intercepted_render
        assert "blocked" in intercepted_render
        
        assert "2024-01-01T00:02:00Z" in intercepted_render
        assert "flagged" in intercepted_render
        
        summary = app.query_one("#summary", SummaryRow)
        assert summary.allowed == 1
        assert summary.blocked == 1
        assert summary.flagged == 1

@pytest.mark.asyncio
@patch("pathlib.Path.exists", return_value=False)
async def test_proposal_rendering(mock_exists):
    """Test that proposals render with correct action badge."""
    app = WardenTUI()
    
    proposals = [
        # ALLOW proposal
        {"permissive_change": 1, "detection_axis": "ip", "matched_binary": "curl", "matched_destination": "1.1.1.1", "reasoning_text": "reason 1"},
        # BLOCK proposal
        {"permissive_change": 0, "detection_axis": "hostname", "matched_binary": "wget", "matched_destination": "evil.com", "reasoning_text": "reason 2"}
    ]
    
    async with app.run_test() as pilot:
        await app._update_proposals_ui(proposals)
        await pilot.pause()
        
        content = app.query_one("#proposals-content")
        render = str(content.render())
        
        assert "1.1.1.1" in render
        assert "ALLOW" in render
        assert "evil.com" in render
        assert "BLOCK" in render

@pytest.mark.asyncio
@patch("pathlib.Path.exists", return_value=False)
async def test_empty_states(mock_exists):
    """Test empty state fallback text."""
    app = WardenTUI()
    async with app.run_test() as pilot:
        await app._update_events_ui([], {})
        await app._update_proposals_ui([])
        await pilot.pause()
        
        allowed_content = app.query_one("#allowed-content")
        intercepted_content = app.query_one("#intercepted-content")
        proposals_content = app.query_one("#proposals-content")
        
        assert "No events recorded yet." in str(allowed_content.render())
        assert "No events recorded yet." in str(intercepted_content.render())
        assert "No pending proposals." in str(proposals_content.render())
