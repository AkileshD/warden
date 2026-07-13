"""
tests/test_core.py — Unit tests for WardenDaemon core loop (Phase 1).
"""
import tempfile
from pathlib import Path
import pytest
import yaml

from daemon.core import WardenDaemon

@pytest.fixture
def temp_env():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        policy_path = tdp / "policy.yaml"
        ledger_path = tdp / "warden.db"
        work_dir = tdp / "workspace"
        work_dir.mkdir()
        
        # Create a policy that allows 'cd' anywhere
        policy = {
            "default_action": "flag",
            "rules": [
                {
                    "action": "allow",
                    "binary": "cd",
                    "target_path": "**"
                }
            ]
        }
        with open(policy_path, "w") as f:
            yaml.dump(policy, f)
            
        yield tdp, policy_path, ledger_path, work_dir

def test_daemon_cd_success_updates_state(temp_env):
    tdp, policy_path, ledger_path, work_dir = temp_env
    daemon = WardenDaemon(policy_path=policy_path, ledger_path=ledger_path, work_dir=work_dir)
    
    # Create a real subdirectory
    target_dir = work_dir / "test_dir"
    target_dir.mkdir()
    
    res = daemon.process("cd test_dir")
    
    assert res.exit_code == 0
    # Internal state should be updated
    assert daemon._work_dir == target_dir.resolve()
    assert daemon._parser.work_dir == target_dir.resolve()
    assert daemon._real_executor._work_dir == target_dir.resolve()
    
    daemon.close()

def test_daemon_cd_nonexistent_directory(temp_env):
    tdp, policy_path, ledger_path, work_dir = temp_env
    daemon = WardenDaemon(policy_path=policy_path, ledger_path=ledger_path, work_dir=work_dir)
    
    res = daemon.process("cd does_not_exist")
    
    # ProcessResult returns the exit_code of the last command
    assert res.exit_code == 1
    assert "cd: does_not_exist: No such file or directory" in res.outcomes[0].execution_result.stderr
    
    # State should remain unchanged
    assert daemon._work_dir == work_dir
    
    daemon.close()
