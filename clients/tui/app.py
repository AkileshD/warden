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


class InterceptCard(Static):
    """A card displaying an intercepted (blocked/flagged) event."""
    
    def __init__(self, timestamp: str, action: str, reason: str, verdict: str, **kwargs):
        super().__init__(**kwargs)
        self.timestamp = timestamp
        self.action = action
        self.reason = reason
        self.verdict = verdict
        
        if self.verdict == "BLOCK":
            self.border_class = "border-blocked"
        elif self.verdict == "FLAG":
            self.border_class = "border-flagged"
        else:
            self.border_class = "border-default"
            
        self.classes = f"intercept-card {self.border_class}"

    def render(self) -> str:
        return (
            f"[bold]{self.timestamp}[/bold]\n"
            f"{self.action}\n"
            f"[#777777]{self.reason}[/]"
        )


class ProposalCard(Static):
    """A card displaying a pending proposal."""
    
    def __init__(self, detection_axis: str, binary: str, destination: str, action: str, reasoning: str, **kwargs):
        super().__init__(**kwargs)
        self.detection_axis = detection_axis
        self.binary = binary
        self.destination = destination
        self.action = action
        self.reasoning = reasoning
        self.classes = "proposal-card"

    def render(self) -> str:
        color = "#639922" if self.action == "ALLOW" else "#E24B4A"
        return (
            f"[bold]Pattern:[/] {self.binary} \u2192 {self.destination} (Axis: {self.detection_axis})\n"
            f"[bold]Proposed Action:[/] [{color}]{self.action}[/]\n"
            f"[#777777]{self.reasoning}[/]"
        )


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
        height: 100%;
    }
    
    #allowed-column {
        width: 50%;
        border-right: solid #2a2e2a;
        padding: 1;
    }
    
    #intercepted-column {
        width: 50%;
        padding: 1;
    }
    
    .intercept-card {
        padding: 1;
        margin-bottom: 1;
        background: #1a1d1a;
    }
    
    .border-blocked {
        border-left: solid #E24B4A;
    }
    
    .border-flagged {
        border-left: solid #BA7517;
    }
    
    .border-default {
        border-left: solid #2a2e2a;
    }
    
    .proposal-card {
        padding: 1;
        margin: 1;
        background: #1a1d1a;
        border-left: solid #2a2e2a;
    }
    
    .empty-state {
        color: #777777;
        text-align: center;
        margin-top: 2;
    }
    
    TabbedContent {
        height: 100%;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(id="header")
        yield SummaryRow(id="summary")
        with TabbedContent():
            with TabPane("Events"):
                with Horizontal(id="events-container"):
                    with VerticalScroll(id="allowed-column"):
                        yield Static("No events recorded yet.", classes="empty-state", id="allowed-empty")
                    with VerticalScroll(id="intercepted-column"):
                        yield Static("No events recorded yet.", classes="empty-state", id="intercepted-empty")
            with TabPane("Proposals"):
                with VerticalScroll(id="proposals-column"):
                    yield Static("No pending proposals.", classes="empty-state", id="proposals-empty")

    def on_mount(self) -> None:
        self.update_data()
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

    def update_data(self) -> None:
        conn = self._get_db_connection()
        if not conn:
            return
            
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch events
            cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")
            events = cursor.fetchall()
            
            # Fetch proposals
            cursor.execute("SELECT * FROM proposed_rules WHERE status = 'pending' ORDER BY created_at DESC")
            proposals = cursor.fetchall()
            
            self._update_events_ui(events)
            self._update_proposals_ui(proposals)
            
        except sqlite3.Error:
            pass
        finally:
            conn.close()
            
    def _update_events_ui(self, events) -> None:
        allowed_col = self.query_one("#allowed-column")
        intercepted_col = self.query_one("#intercepted-column")
        summary = self.query_one("#summary", SummaryRow)
        
        allowed_widgets = []
        intercepted_widgets = []
        
        a_count = 0
        b_count = 0
        f_count = 0
        
        for row in events:
            verdict = row["verdict"]
            timestamp = row["timestamp"]
            event_type = row["event_type"]
            parsed_str = row["parsed_action"]
            
            if verdict == "ALLOW":
                a_count += 1
                action_text = format_action(event_type, parsed_str)
                allowed_widgets.append(Static(f"[#639922]{timestamp}[/] {action_text}"))
            elif verdict == "BLOCK":
                b_count += 1
                action_text = format_action(event_type, parsed_str)
                intercepted_widgets.append(InterceptCard(timestamp, action_text, row["reason"], verdict))
            elif verdict == "FLAG":
                f_count += 1
                action_text = format_action(event_type, parsed_str)
                intercepted_widgets.append(InterceptCard(timestamp, action_text, row["reason"], verdict))
                
        summary.allowed = a_count
        summary.blocked = b_count
        summary.flagged = f_count
        
        if allowed_widgets:
            allowed_col.remove_children()
            allowed_col.mount(*allowed_widgets)
        elif events:
            # Clear if there are events but none are allowed
            allowed_col.remove_children()
            allowed_col.mount(Static("No allowed events.", classes="empty-state", id="allowed-empty"))
            
        if intercepted_widgets:
            intercepted_col.remove_children()
            intercepted_col.mount(*intercepted_widgets)
        elif events:
            # Clear if there are events but none are intercepted
            intercepted_col.remove_children()
            intercepted_col.mount(Static("No intercepted events.", classes="empty-state", id="intercepted-empty"))

    def _update_proposals_ui(self, proposals) -> None:
        proposals_col = self.query_one("#proposals-column")
        
        if not proposals:
            if len(proposals_col.children) == 0 or not isinstance(proposals_col.children[0], Static) or "empty-state" not in proposals_col.children[0].classes:
                proposals_col.remove_children()
                proposals_col.mount(Static("No pending proposals.", classes="empty-state", id="proposals-empty"))
            return
            
        proposals_col.remove_children()
        cards = []
        for row in proposals:
            is_allow = bool(row["permissive_change"])
            action_badge = "ALLOW" if is_allow else "BLOCK"
            
            cards.append(ProposalCard(
                detection_axis=row["detection_axis"],
                binary=row["matched_binary"],
                destination=row["matched_destination"],
                action=action_badge,
                reasoning=row["reasoning_text"]
            ))
        proposals_col.mount(*cards)


if __name__ == "__main__":
    app = WardenTUI()
    app.run()
