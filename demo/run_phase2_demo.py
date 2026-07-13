#!/usr/bin/env python3
import subprocess
import time
import sqlite3
import json
import os

def run_cmd(cmd):
    print(f"\n> {cmd}")
    subprocess.run(cmd, shell=True)

def main():
    print("--- Phase 2 Network Interception Demo ---")
    
    # 1. Bring up containers
    run_cmd("docker-compose up -d")
    
    print("\nWaiting 2 seconds for sidecar to initialize iptables rules...")
    time.sleep(2)
    
    # Helper script to execute HTTP requests inside the jail without needing curl
    py_script = """
import urllib.request
from urllib.error import URLError, HTTPError
import sys
url = sys.argv[1]
try:
    print(f"Attempting {url}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    urllib.request.urlopen(req, timeout=3)
    print("Success! Connection established.")
except HTTPError as e:
    print(f"Connected successfully! Server returned HTTP {e.code} (this proves we reached the host)")
except URLError as e:
    print(f"Connection failed/timed out: {e.reason} (this proves packets were dropped)")
except Exception as e:
    print(f"Error: {e}")
"""
    # Write the helper script to the mounted project directory
    os.makedirs("project/demo", exist_ok=True)
    with open("project/demo/http_test.py", "w") as f:
        f.write(py_script.strip())

    # 2. Allowed request (example.com by IP)
    print("\n[TEST 1] Making allowed outbound request to example.com (104.20.23.154)")
    run_cmd("docker-compose exec -T jail python3 /workspace/demo/http_test.py http://104.20.23.154")

    # 3. Blocked request 1 (api.openai.com)
    # Blocked because stateless SNI filtering drops the initial TCP SYN packet!
    print("\n[TEST 2] Making blocked outbound request to api.openai.com:443")
    run_cmd("docker-compose exec -T jail python3 /workspace/demo/http_test.py https://api.openai.com/v1/models")
            
    # 4. Blocked request 2 (1.1.1.1)
    print("\n[TEST 3] Making blocked outbound request to Cloudflare DNS (1.1.1.1:443)")
    run_cmd("docker-compose exec -T jail python3 /workspace/demo/http_test.py https://1.1.1.1")

    print("\nWaiting 2 seconds for ledger to sync...")
    time.sleep(2)

    # 5. Query Ledger (from inside the sidecar container!)
    print("\n--- Ledger Network Events ---")
    query_script = """
import sqlite3, json
try:
    conn = sqlite3.connect('/data/ledger/warden.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, verdict, parsed_action FROM events WHERE event_type = 'network' ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    print(f"{'ID':<4} | {'TIMESTAMP':<20} | {'VERDICT':<7} | {'DESTINATION':<25} | {'PROTOCOL'}")
    print("-" * 75)
    for row in reversed(rows):
        r_id, ts, verdict, action_blob = row
        action = json.loads(action_blob)
        dest = action.get('hostname_or_sni') or f"{action.get('dst_ip')}:{action.get('dst_port')}"
        proto = action.get('protocol', 'UNKNOWN')
        print(f"{r_id:<4} | {ts[:19]:<20} | {verdict:<7} | {dest:<25} | {proto}")
except Exception as e:
    print(f"Error: {e}")
"""
    with open("project/demo/query.py", "w") as f:
        f.write(query_script.strip())
    # Run the query script inside the sidecar via the /app mount
    run_cmd("docker-compose exec -T warden-sidecar python3 /app/project/demo/query.py")
    
    print("\n--- Sidecar Logs ---")
    run_cmd("docker-compose logs warden-sidecar")

    # 6. Tear down
    print("\nShutting down containers...")
    run_cmd("docker-compose down")
    
    # Cleanup the helper scripts
    try:
        os.remove("project/demo/http_test.py")
        os.remove("project/demo/query.py")
        os.rmdir("project/demo")
    except OSError:
        pass

if __name__ == '__main__':
    main()
