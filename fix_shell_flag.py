import re

with open("tests/test_phase3_advisor.py", "r") as f:
    content = f.read()

content = content.replace("    if ts is None:\n        ts = time.time()\n    action_dict = {", "    if ts is None:\n        ts = time.time()\n    from datetime import datetime, timezone\n    ts_str = datetime.fromtimestamp(ts, timezone.utc).strftime(\"%Y-%m-%dT%H:%M:%S.%f\")[:-3] + \"Z\"\n    action_dict = {")

content = content.replace("(str(ts), binary, parsed_action, action_id),", "(ts_str, binary, parsed_action, action_id),")

with open("tests/test_phase3_advisor.py", "w") as f:
    f.write(content)
