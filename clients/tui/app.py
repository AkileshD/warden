import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Header as TextualHeader, Footer, Static, TabbedContent, TabPane


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = REPO_ROOT / "warden_demo.db"
SOCKET_PATH = Path("/tmp/warden_ipc/warden_control.sock")


def format_action(event_type: str, parsed_action_str: str) -> str:
    """Safely parse the JSON blob and format it for display."""
    try:
        data = json.loads(parsed_action_str)
    except Exception:
        return "<malformed json>"

    if event_type == "shell_command":
        # Attempt to reconstruct the command from binary + args
        binary = data.get("binary", "unknown")
        args = data.get("args", [])
        if not isinstance(args, list):
            args = []
        return f"{binary} {' '.join(str(a) for a in args)}".strip()
    
    elif event_type == "network":
        # Network event shape: dst_ip, dst_port, protocol, hostname_or_sni
        dst_ip = data.get("dst_ip")
        dst_port = data.get("dst_port", "*")
        hostname = data.get("hostname_or_sni")
        
        target = hostname if hostname else dst_ip
        if not target:
            target = "unknown"
            
        return f"net \u2192 {target}:{dst_port}"

    return "<unknown event type>"


class SummaryRow(Static):
    """Displays counts of ALLOWED, BLOCKED, FLAGGED events."""
    
    allowed = reactive(0)
    blocked = reactive(0)
    flagged = reactive(0)

    def render(self) -> str:
        return (
            f"[#639922]\u25cf Allowed: {self.allowed}[/]    "
            f"[#E24B4A]\u25cf Blocked: {self.blocked}[/]    "
            f"[#BA7517]\u25cf Flagged: {self.flagged}[/]"
        )


class Header(Static):
    """Custom header with wordmark and status line."""
    
    status_text = reactive("Checking status...")

    def render(self) -> str:
        return f"[bold]WARDEN[/bold] | {self.status_text}"


# Removed InterceptCard and ProposalCard as they are now formatted directly as Rich text strings to avoid DOM manipulation bugs.


class WardenTUI(App):
    
    CSS = """
    Screen {
        background: #111411;
    }
    
    Header {
        background: #1a1d1a;
        padding: 1;
        text-align: center;
        border-bottom: solid #2a2e2a;
    }
    
    SummaryRow {
        padding: 1;
        text-align: center;
        border-bottom: solid #2a2e2a;
    }
    
    #events-container {
        height: 1fr;
    }
    
    #allowed-column {
        width: 50%;
        border-right: solid #2a2e2a;
        padding: 1;
        height: 1fr;
    }
    
    #intercepted-column {
        width: 50%;
        padding: 1;
        height: 1fr;
    }
    
    #proposals-column {
        padding: 1;
        height: 1fr;
    }
    
    .empty-state {
        color: #777777;
        text-align: center;
        margin-top: 2;
    }
    
    TabbedContent, TabPane {
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(id="header")
        yield SummaryRow(id="summary")
        with TabbedContent():
            with TabPane("Events"):
                with Horizontal(id="events-container"):
                    with VerticalScroll(id="allowed-column"):
                        yield Static("No events recorded yet.", classes="empty-state", id="allowed-content")
                    with VerticalScroll(id="intercepted-column"):
                        yield Static("No events recorded yet.", classes="empty-state", id="intercepted-content")
            with TabPane("Proposals"):
                with VerticalScroll(id="proposals-column"):
                    yield Static("No pending proposals.", classes="empty-state", id="proposals-content")

    async def on_mount(self) -> None:
        await self.update_data()
        self.update_status()
        self.set_interval(2.0, self.update_data)
        self.set_interval(5.0, self.update_status)

    def _get_db_connection(self):
        """Get a structural read-only SQLite connection."""
        if not DB_PATH.exists():
            return None
        uri = f"file:{DB_PATH}?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def update_status(self) -> None:
        # Check socket
        socket_up = SOCKET_PATH.exists() and os.access(SOCKET_PATH, os.R_OK)
        
        # Check docker
        jail_up = False
        sidecar_up = False
        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "--services", "--filter", "status=running"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False
            )
            out = result.stdout
            jail_up = "jail" in out.splitlines()
            sidecar_up = "warden-sidecar" in out.splitlines()
        except Exception:
            pass

        jail_color = "#639922" if jail_up else "#E24B4A"
        sidecar_color = "#639922" if sidecar_up else "#E24B4A"
        socket_color = "#639922" if socket_up else "#E24B4A"
        
        jail_str = "up" if jail_up else "down"
        sidecar_str = "up" if sidecar_up else "down"
        socket_str = "connected" if socket_up else "disconnected"

        header = self.query_one("#header", Header)
        header.status_text = (
            f"jail: [{jail_color}]{jail_str}[/] \u00b7 "
            f"sidecar: [{sidecar_color}]{sidecar_str}[/] \u00b7 "
            f"socket: [{socket_color}]{socket_str}[/]"
        )

    async def update_data(self) -> None:
        conn = self._get_db_connection()
        if not conn:
            return
            
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch events
            cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")
            events = cursor.fetchall()
            
            # Fetch true counts
            cursor.execute("SELECT verdict, COUNT(*) as count FROM events GROUP BY verdict")
            counts = {row["verdict"]: row["count"] for row in cursor.fetchall()}
            
            # Fetch proposals
            cursor.execute("SELECT * FROM proposed_rules WHERE status = 'pending' ORDER BY created_at DESC")
            proposals = cursor.fetchall()
            
            await self._update_events_ui(events, counts)
            await self._update_proposals_ui(proposals)
            
        except sqlite3.Error:
            pass
        finally:
            conn.close()
            
    async def _update_events_ui(self, events, counts) -> None:
        allowed_content = self.query_one("#allowed-content", Static)
        intercepted_content = self.query_one("#intercepted-content", Static)
        summary = self.query_one("#summary", SummaryRow)
        
        allowed_lines = []
        intercepted_lines = []
        
        for row in events:
            verdict = row["verdict"]
            timestamp = row["timestamp"]
            event_type = row["event_type"]
            parsed_str = row["parsed_action"]
            action_text = format_action(event_type, parsed_str)
            
            if verdict == "ALLOW":
                allowed_lines.append(f"[#639922]{timestamp}[/] {action_text}")
            else:
                # FLAG or BLOCK
                color = "#E24B4A" if verdict == "BLOCK" else "#BA7517"
                intercepted_lines.append(f"[{color}]\u2503[/] [bold]{timestamp}[/bold]")
                intercepted_lines.append(f"[{color}]\u2503[/] {action_text}")
                intercepted_lines.append(f"[{color}]\u2503[/] [#777777]{row['reason']}[/]")
                intercepted_lines.append("")
                
        summary.allowed = counts.get("ALLOW", 0)
        summary.blocked = counts.get("BLOCK", 0)
        summary.flagged = counts.get("FLAG", 0)
        
        if allowed_lines:
            text_str = "\n".join(allowed_lines)
            allowed_content.update(text_str)
            allowed_content.remove_class("empty-state")
        elif events:
            allowed_content.update("No allowed events.")
            allowed_content.add_class("empty-state")
            
        if intercepted_lines:
            intercepted_content.update("\n".join(intercepted_lines))
            intercepted_content.remove_class("empty-state")
        elif events:
            intercepted_content.update("No intercepted events.")
            intercepted_content.add_class("empty-state")

    async def _update_proposals_ui(self, proposals) -> None:
        proposals_content = self.query_one("#proposals-content", Static)
        
        if not proposals:
            proposals_content.update("No pending proposals.")
            proposals_content.add_class("empty-state")
            return
            
        lines = []
        for row in proposals:
            is_allow = bool(row["permissive_change"])
            action_badge = "ALLOW" if is_allow else "BLOCK"
            color = "#639922" if is_allow else "#E24B4A"
            
            lines.append(f"[{color}]\u2503[/] [bold]Pattern:[/] {row['matched_binary']} \u2192 {row['matched_destination']} (Axis: {row['detection_axis']})")
            lines.append(f"[{color}]\u2503[/] [bold]Proposed Action:[/] [{color}]{action_badge}[/]")
            lines.append(f"[{color}]\u2503[/] [#777777]{row['reasoning_text']}[/]")
            lines.append("")
            
        proposals_content.update("\n".join(lines))
        proposals_content.remove_class("empty-state")


if __name__ == "__main__":
    app = WardenTUI()
    app.run()
