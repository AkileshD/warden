import json
import socket
import threading
import time
import pytest
from pathlib import Path

from daemon.core import WardenDaemon
from daemon.executors.real_executor import RealExecutor
from daemon.executors.docker_jail_executor import DockerJailExecutor

@pytest.fixture
def temp_warden(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""
rules:
  - id: 1
    type: shell_command
    verdict: ALLOW
    condition:
      binaries: ["mkdir", "echo"]
      path_scope: ["./project/**"]
  - id: 2
    type: shell_command
    verdict: BLOCK
    condition:
      binaries: ["rm"]
      flags: ["-rf"]
""")
    
    ledger_path = tmp_path / "warden.db"
    
    # Needs to be absolute for Daemon logic
    work_dir = tmp_path.resolve()
    (work_dir / "project").mkdir()
    
    daemon = WardenDaemon(
        policy_path=policy_path,
        ledger_path=ledger_path,
        work_dir=work_dir,
    )
    # Wait for socket to be ready
    sock_path = Path("/tmp/warden_ipc/warden_control.sock")
    for _ in range(10):
        if sock_path.exists():
            break
        time.sleep(0.1)
        
    yield daemon
    daemon.close()

def _send_request(cmd: str, executor: str = "docker_jail") -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(20):
        try:
            s.connect("/tmp/warden_ipc/warden_control.sock")
            break
        except ConnectionRefusedError:
            time.sleep(0.1)
    else:
        s.connect("/tmp/warden_ipc/warden_control.sock") # final attempt/raise
        
    req = {"cmd": cmd, "executor": executor}
    s.sendall((json.dumps(req) + "\n").encode("utf-8"))
    
    f = s.makefile('r', encoding='utf-8')
    line = f.readline()
    s.close()
    return json.loads(line)

def test_control_socket_transparent_wrapper(temp_warden):
    # We want to prove that sending via socket gives the exact same result as daemon.process()
    # To avoid real execution side-effects, we will mock the executors
    
    # Mock RealExecutor and DockerJailExecutor run methods
    def mock_run(action, verdict):
        from daemon.executors.base import ExecutionResult
        return ExecutionResult(stdout="MOCKED_OUTPUT", stderr="", exit_code=0, was_real=True, was_fabricated=False)
        
    temp_warden._control_socket._jail_executor.run = mock_run
    
    # 1. ALLOW command
    cmd_allow = "echo hello > ./project/test.txt"
    resp_allow = _send_request(cmd_allow)
    
    direct_allow = temp_warden.process(cmd_allow)
    assert resp_allow["exit_code"] == direct_allow.exit_code
    
    # 2. BLOCK command
    cmd_block = "rm -rf /"
    resp_block = _send_request(cmd_block)
    
    direct_block = temp_warden.process(cmd_block)
    assert resp_block["exit_code"] == direct_block.exit_code
    assert resp_block["was_fabricated"] == True

def test_control_socket_executor_switchboard(temp_warden):
    """Confirm 'docker_jail' and 'host' route to the correct executor."""
    
    executed_on = []
    
    def mock_host_run(action, verdict):
        from daemon.executors.base import ExecutionResult
        executed_on.append("host")
        return ExecutionResult(stdout="", stderr="", exit_code=0, was_real=True, was_fabricated=False)

    def mock_jail_run(action, verdict):
        from daemon.executors.base import ExecutionResult
        executed_on.append("jail")
        return ExecutionResult(stdout="", stderr="", exit_code=0, was_real=True, was_fabricated=False)
        
    temp_warden._control_socket._host_executor.run = mock_host_run
    temp_warden._control_socket._jail_executor.run = mock_jail_run
    
    def mock_evaluate(action, verdicts):
        from daemon.inspectors.base import Verdict, Decision
        return Verdict(decision=Decision.ALLOW, reason="mocked", source_inspector="mock")
    
    temp_warden._rule_engine.evaluate = mock_evaluate

    # Test host routing
    resp = _send_request("mkdir ./project/test1", executor="host")
    assert executed_on == ["host"]
    
    executed_on.clear()
    
    # Test docker_jail routing (default)
    _send_request("mkdir ./project/test2", executor="docker_jail")
    assert executed_on == ["jail"]
