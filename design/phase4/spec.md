# Phase 4 Minimalist UI — Textual TUI Spec

## 1. Design Constraints & Data Source

**Data Source:** The TUI operates via a direct, **read-only** SQLite connection to `daemon/ledger/warden_demo.db`. It queries the `events` and `proposed_rules` tables natively. 
**Constraint:** This application is strictly **DISPLAY ONLY**. There is no new daemon API endpoint, no control socket client, and zero write paths. The TUI cannot approve, reject, or modify rules, nor can it mutate the ledger. Approval remains exclusively the responsibility of `approval_cli.py`. This is a hard design invariant per `WARDEN_SPEC.md §3`.

## 2. Refresh Strategy

The application will use simple interval-based polling. Textual's `set_interval` will trigger a DB read (e.g., every 1-2 seconds) to fetch the latest rows from `events` and `proposed_rules`. 
Since it's a single-agent local tool, polling the SQLite file directly is efficient and requires no pub/sub overhead or file-watching dependencies. 
State updates will be diffed or efficiently appended to the reactive properties of the relevant widgets to prevent UI stutter.

## 3. Widget & Layout Breakdown

The TUI will use a standard `App` with a CSS-styled grid layout.

- **Global Layout:** A vertical container with three main layers: `Header` at the top, a `SummaryRow` (custom `Static` widget), and a `TabbedContent` area for switching between the main event streams and the new proposals view.
- **Header:** A custom `Static` widget displaying the "WARDEN" wordmark and a secondary `Static` label for the status line ("jail: up · sidecar: up · socket: connected").
- **Summary Row:** A `Horizontal` container containing three `Static` widgets for the counts: `AllowedCount`, `BlockedCount`, and `FlaggedCount`. Each will use Textual's rich text (Rich) to render the colored dot indicators.
- **Main Body (Tab 1: "Events"):** 
  - A `Horizontal` container splitting the screen into two columns, visually separated by a vertical CSS `border: solid #2a2e2a;`.
  - **Left Column ("ALLOWED"):** A `VerticalScroll` container holding simple `Static` label widgets. Each label displays the timestamp and action text in a neutral color.
  - **Right Column ("INTERCEPTED"):** A `VerticalScroll` container holding custom `InterceptCard` widgets. Each `InterceptCard` will be a `Static` or `Vertical` container with a left border (`border-left`) color-coded red or amber, containing the timestamp, command, and a dimmed secondary text line for the `reason`.
- **Proposals Panel (Tab 2: "Proposals"):**
  - A `VerticalScroll` container showing a list of pending `proposed_rules` (status = 'pending').
  - Each item is a `ProposalCard` widget displaying the `detection_axis`, the matched pattern (binary + destination/hostname), the proposed action (ALLOW/BLOCK), and the `reasoning_text`.

## 4. Color Mapping & Textual CSS

Colors will be mapped directly in the App's `.tcss` file or `DEFAULT_CSS` attributes using Textual's styling engine.

- **Background:** `background: #111411;` (applied to `Screen` and containers).
- **Dividers/Borders:** `border: solid #2a2e2a;` (used for column separation and subtle panel outlines).
- **Allowed (Green):** `color: #639922;` (used for the allowed dot indicator).
- **Blocked (Red):** `color: #E24B4A;` (used for the blocked dot indicator, and the `border-left: solid #E24B4A;` on blocked intercept cards).
- **Flagged (Amber):** `color: #BA7517;` (used for the flagged dot indicator, and `border-left: solid #BA7517;` on flagged intercept cards).
- **Dimmed Text:** `color: $text-muted;` or a specific dark grey like `#777777` for the secondary reason strings.
- **Typography:** `text-style: none;` leveraging the terminal's native monospace font.

## 5. Empty State & Down State Behavior

- **Empty State (No Events):** If the SQLite DB is empty or doesn't exist, the `VerticalScroll` containers will yield a single, centrally aligned `Static` widget stating "No events recorded yet." or "No pending proposals." in a dimmed color.
- **Daemon/Sidecar Down State:** Since the TUI cannot connect to the socket or run shell commands, "up/down" status will be inferred passively. 
  - **Socket/Daemon:** Checked via `os.path.exists()` and `os.access()` on the daemon's Unix socket file path. If missing/stale, status shows "daemon: down · socket: disconnected" (in red).
  - **Sidecar/Jail:** Can be inferred if there are recent events in the ledger, or by optionally executing a lightweight, read-only `docker ps --filter name=warden-sidecar --format '{{.Status}}'` subprocess check on interval, since Docker is local. If the containers are not running, the header reflects "jail: down · sidecar: down" in red.

## 6. Out of Scope

- **No Write Actions:** The UI will not have any buttons or shortcuts to approve rules, delete rules, or alter configuration.
- **No Mutating Keybinds:** Keybinds will be strictly limited to navigation (e.g., `ctrl+c` to quit, `tab` to switch panes, arrow keys for scrolling).
- **No Complex Dashboards:** No charts, graphs, or historical metric aggregations beyond the simple summary counters derived directly from the current view.
