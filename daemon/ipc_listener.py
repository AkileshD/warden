import json
import socket
import threading
from pathlib import Path
from typing import Optional

from daemon.ledger.logger import Logger, LedgerEvent
from daemon.inspectors.base import Verdict, Decision
from daemon.parser.packet_parser import ParsedNetworkAction
from daemon.executors.base import ExecutionResult


class IPCListener:
    """
    Background thread that listens on a Unix Domain Socket for network events
    from the sidecar. It correlates the event with pending actions and writes
    it directly to the ledger.
    """
    def __init__(self, logger: Logger, socket_path: str = "/tmp/warden_ipc/warden.sock"):
        self._logger = logger
        self._socket_path = Path(socket_path)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="IPCListener")
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._sock:
            try:
                # Send a dummy packet to wake up recvfrom if it's blocking
                s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                s.sendto(b"{}", str(self._socket_path))
                s.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def _run(self) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except OSError:
                pass

        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self._sock.bind(str(self._socket_path))
            # Ensure the sidecar container can write to this socket if bind mounted
            self._socket_path.chmod(0o666)
        except Exception as e:
            import sys
            print(f"[IPCListener] Failed to bind socket {self._socket_path}: {e}", file=sys.stderr)
            self._running = False
            return

        while self._running:
            try:
                data, _ = self._sock.recvfrom(65535)
                if not data or not self._running:
                    continue
                
                event_dict = json.loads(data.decode("utf-8"))
                if not isinstance(event_dict, dict):
                    import sys
                    print(f"[IPCListener] Error parsing network event: Expected dict, got {type(event_dict).__name__}", file=sys.stderr)
                    continue

                # 1. GC old pending actions
                self._logger.cleanup_pending_actions()

                # 2. Extract timestamp and resolve action_id
                packet_ts = event_dict.get("timestamp", 0.0)
                action_id = self._logger.resolve_pending_action(packet_ts)

                # 3. Reconstruct the LedgerEvent pieces
                v_dict = event_dict.get("verdict", {})
                verdict = Verdict(
                    decision=Decision(v_dict.get("decision", "BLOCK")),
                    reason=v_dict.get("reason", "unknown"),
                    source_inspector=v_dict.get("source_inspector", "NetworkInspector"),
                    confidence=v_dict.get("confidence", None)
                )

                p_dict = event_dict.get("parsed_action", {})
                parsed_action = ParsedNetworkAction(
                    binary="<network>",
                    args=[],
                    flags=[],
                    target_paths=[],
                    raw_input=p_dict.get("raw_input", ""),
                    sub_commands=[],
                    dst_ip=p_dict.get("dst_ip", ""),
                    dst_port=p_dict.get("dst_port", 0),
                    protocol=p_dict.get("protocol", "OTHER"),
                    hostname_or_sni=p_dict.get("hostname_or_sni", None),
                    direction=p_dict.get("direction", "outbound"),
                    raw_bytes=b""
                )

                result = ExecutionResult(
                    stdout="",
                    stderr="",
                    exit_code=1 if verdict.decision == Decision.BLOCK else 0,
                    was_real=False,
                    was_fabricated=False,
                    pid=None
                )

                ledger_event = LedgerEvent(
                    raw_input=p_dict.get("raw_input", ""),
                    parsed_action=parsed_action,
                    verdict=verdict,
                    result=result,
                    event_type="network",
                    session_id=event_dict.get("session_id", None),
                    risk=event_dict.get("risk", None),
                    action_id=action_id
                )

                # 4. Write to the sole writer DB connection
                self._logger.record(ledger_event)

            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                import sys
                print(f"[IPCListener] Error parsing network event: {e}", file=sys.stderr)
            except Exception as e:
                import sys
                print(f"[IPCListener] Unexpected error processing network event: {e}", file=sys.stderr)
            except OSError:
                if not self._running:
                    break

        if self._sock:
            self._sock.close()
            self._sock = None
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except OSError:
                pass
