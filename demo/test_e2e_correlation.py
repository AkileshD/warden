#!/usr/bin/env python3
import time
import subprocess
import sqlite3
import json
import os
import sys
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from daemon.core import WardenDaemon
from demo.run_agent_test import DockerJailExecutor

def clean_environment():
    print("[*] Cleaning up environment...")
    subprocess.run(["docker-compose", "down", "-v"], cwd=str(PROJECT_ROOT), capture_output=True)
    
    ledger_db = PROJECT_ROOT / "ledger_data" / "warden_demo.db"
    if ledger_db.exists():
        ledger_db.unlink()
        
    ipc_dir = PROJECT_ROOT / "ipc_data"
    if ipc_dir.exists():
        for f in ipc_dir.iterdir():
            try:
                if f.is_socket():
                    f.unlink()
            except Exception:
                pass

def main():
    clean_environment()
    
    # 1. Bring up containers (jail + sidecar)
    print("[*] Starting Warden sidecar via docker-compose...")
    res = subprocess.run(["docker-compose", "up", "-d"], cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print("Failed to start docker-compose")
        sys.exit(1)
        
    print("[*] Waiting for sidecar to initialize (3s)...")
    time.sleep(3)
    
    daemon = WardenDaemon(
        policy_path=Path(PROJECT_ROOT / "daemon" / "rules" / "policy.yaml"),
        ledger_path=Path(PROJECT_ROOT / "ledger_data" / "warden_demo.db")
    )
    # Bridge execution to the jail
    daemon._real_executor = DockerJailExecutor(host_repo_root=PROJECT_ROOT)
    
    # 3. Setup allowed script inside project/
    demo_dir = PROJECT_ROOT / "project" / "demo"
    demo_dir.mkdir(exist_ok=True, parents=True)
    test_script = demo_dir / "test_net.py"
    with open(test_script, "w") as f:
        f.write("import urllib.request; urllib.request.urlopen('http://104.20.23.154', timeout=3)")
        
    print("[*] Dispatching allowed command via daemon...")
    # Change dir first so the DockerJailExecutor maps it to /workspace/demo correctly
    cmd = "cd project/demo && python3 test_net.py"
    daemon.process(cmd)
    
    # Wait a bit for network event to arrive via IPC
    time.sleep(2)
    
    # 4. Verify Ledger
    print("[*] Verifying correlation in ledger...")
    rows = daemon.read_ledger()
    daemon.close()
    
    if len(rows) < 2:
        print(f"FAIL: Expected at least 2 events (shell + network), got {len(rows)}")
        sys.exit(1)
        
    shell_event = None
    network_event = None
    
    for row in rows:
        if row["event_type"] == "shell_command" and "python3" in row["raw_input"]:
            shell_event = row
        elif row["event_type"] == "network":
            network_event = row
            
    if not shell_event:
        print("FAIL: Missing shell event for python3")
        sys.exit(1)
    if not network_event:
        print("FAIL: Missing network event")
        sys.exit(1)
        
    shell_action_id = shell_event["action_id"]
    network_action_id = network_event["action_id"]
    
    print(f"Shell Action ID:   {shell_action_id}")
    print(f"Network Action ID: {network_action_id}")
    
    if shell_action_id is None:
        print("FAIL: Shell event has NULL action_id")
        sys.exit(1)
        
    if shell_action_id != network_action_id:
        print("FAIL: Correlation mismatch!")
        sys.exit(1)
        
    print("PASS: Run completed successfully")
    sys.exit(0)

if __name__ == "__main__":
    main()
