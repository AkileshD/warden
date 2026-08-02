import json
import socket
import threading
import sys
import os
from pathlib import Path
from typing import Optional

from daemon.executors.real_executor import RealExecutor
from daemon.executors.docker_jail_executor import DockerJailExecutor

# TODO(phase5): If/when this needs to be exposed beyond local processes, 
# adopt the token-auth precedent already established by the sidecar's UDP IPC listener (ipc_listener.py).

class ControlSocket:
    """
    Background thread that listens on a Unix domain socket for CLI/Agent control requests.
    Routes execution to either DockerJailExecutor (default) or host RealExecutor.
    """
    def __init__(
        self, 
        daemon, 
        socket_path: str = "/tmp/warden_ipc/warden_control.sock",
    ):
        self.daemon = daemon
        self.socket_path = Path(socket_path)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        
        # Initialize the executors for the switchboard
        # The daemon's work_dir is mapped as the repo root. 
        # The jail executor needs host_repo_root and an initial work_dir of repo_root/project.
        self._host_executor = RealExecutor(work_dir=self.daemon._work_dir)
        self._jail_executor = DockerJailExecutor(
            host_repo_root=self.daemon._work_dir,
            work_dir=self.daemon._work_dir / "project"
        )
        self._executor_lock = threading.Lock()

    def start(self) -> None:
        if self._running:
            return
            
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError as e:
                print(f"[ControlSocket] Warning: could not unlink {self.socket_path}: {e}", file=sys.stderr)
                
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="ControlSocket")
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        
        # Connect to socket to wake up accept()
        try:
            if self.socket_path.exists():
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(str(self.socket_path))
                s.close()
        except Exception:
            pass
            
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
            
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def _run(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.bind(str(self.socket_path))
            # OS-level permissions are the only access control for now
            self.socket_path.chmod(0o666) 
            self._sock.listen(5)
        except Exception as e:
            print(f"[ControlSocket] Failed to bind Unix socket {self.socket_path}: {e}", file=sys.stderr)
            self._running = False
            return

        while self._running:
            try:
                conn, _ = self._sock.accept()
                if not self._running:
                    conn.close()
                    break
                
                # Handle each connection in the same thread (simple 1-by-1 for now)
                self._handle_connection(conn)
            except OSError:
                if not self._running:
                    break
            except Exception as e:
                print(f"[ControlSocket] Error accepting connection: {e}", file=sys.stderr)

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            file_obj = conn.makefile('rw', encoding='utf-8')
            line = file_obj.readline()
            if not line:
                conn.close()
                return
                
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(file_obj, "Invalid JSON format")
                conn.close()
                return
                
            cmd = req.get("cmd")
            if not isinstance(cmd, str):
                self._send_error(file_obj, "Missing or invalid 'cmd' field")
                conn.close()
                return
                
            executor_type = req.get("executor", "docker_jail")
            req_cwd = req.get("cwd")
            
            # Switchboard
            # Temporarily replace the daemon's _real_executor for this request
            # We use a lock to ensure that if connection handling is ever parallelized,
            # concurrent requests don't cross-contaminate the executor selection.
            with self._executor_lock:
                original_executor = self.daemon._real_executor
                
                if executor_type == "host":
                    self.daemon._real_executor = self._host_executor
                else:
                    self.daemon._real_executor = self._jail_executor
                    
                # If cwd is requested, we could update the daemon/executor's work_dir.
                # But normally we preserve the stateful cwd of the daemon unless specified.
                if req_cwd:
                    pass
                    
                try:
                    # Call the single pipeline entrypoint
                    result = self.daemon.process(cmd)
                    
                    resp = {
                        "stdout": result.stdout,
                        "exit_code": result.exit_code,
                        "stderr": "".join(o.execution_result.stderr for o in result.outcomes) if result.outcomes else "",
                        "was_real": result.outcomes[-1].execution_result.was_real if result.outcomes else False,
                        "was_fabricated": result.outcomes[-1].execution_result.was_fabricated if result.outcomes else False,
                    }
                    file_obj.write(json.dumps(resp) + "\n")
                    file_obj.flush()
                except Exception as e:
                    self._send_error(file_obj, f"Daemon execution error: {e}")
                finally:
                    # Restore the original executor
                    self.daemon._real_executor = original_executor
                
        except Exception as e:
            print(f"[ControlSocket] Connection handling error: {e}", file=sys.stderr)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send_error(self, file_obj, message: str) -> None:
        try:
            resp = {
                "stdout": "",
                "stderr": message,
                "exit_code": 1,
                "was_real": False,
                "was_fabricated": False
            }
            file_obj.write(json.dumps(resp) + "\n")
            file_obj.flush()
        except Exception:
            pass
