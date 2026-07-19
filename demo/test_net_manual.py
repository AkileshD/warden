import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from daemon.core import WardenDaemon
from demo.run_agent_test import DockerJailExecutor
daemon = WardenDaemon(policy_path=Path("daemon/rules/policy.yaml"), ledger_path=Path("ledger_data/warden.db"))
daemon._real_executor = DockerJailExecutor(host_repo_root=PROJECT_ROOT)
print(daemon.process("cd project/demo && python3 test_net.py"))
daemon.close()
