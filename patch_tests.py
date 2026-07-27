import re

with open("tests/test_phase3_advisor.py", "r") as f:
    content = f.read()

# Update _insert_network_flag
content = re.sub(
    r'def _insert_network_flag\(logger: Logger, binary: str, destination: str,\n                          is_hostname_dest: bool = True, ts: float \| None = None,\n                          pure_hostname: bool = False,\n                          custom_ip: str \| None = None\) -> None:',
    r'''def _insert_network_flag(logger: Logger, binary: str, destination: str,
                          is_hostname_dest: bool = True, ts: float | None = None,
                          pure_hostname: bool = False,
                          custom_ip: str | None = None,
                          action_id: str | None = None) -> None:''',
    content
)

content = re.sub(
    r'            INSERT INTO events\n            \(timestamp, session_id, raw_input, event_type, verdict, risk, execution, parsed_action\)\n            VALUES \(\?, \?, \?, \'network\', \'FLAG\', \'test\', \'none\', \?\)\n            \"\"\",\n            \(ts_str, \"test-session\", \"raw\", parsed_action\)',
    r'''            INSERT INTO events
            (timestamp, session_id, raw_input, event_type, verdict, risk, execution, parsed_action, action_id)
            VALUES (?, ?, ?, 'network', 'FLAG', 'test', 'none', ?, ?)
            """,
            (ts_str, "test-session", "raw", parsed_action, action_id)''',
    content
)


# Update _insert_shell_flag
content = re.sub(
    r'def _insert_shell_flag\(logger: Logger, binary: str, destination: str,\n                        ts: float \| None = None\) -> None:',
    r'''def _insert_shell_flag(logger: Logger, binary: str, destination: str,
                        ts: float | None = None, action_id: str | None = None,
                        is_hostname_dest: bool = False) -> None:''',
    content
)

content = re.sub(
    r'    parsed_action = json.dumps\({\n        "binary": binary,\n        "args": \[\],\n        "flags": \[\],\n        "target_paths": \[\],\n        "raw_input": binary,\n        "sub_commands": \[\],\n    }\)',
    r'''    action_dict = {
        "binary": binary,
        "args": [],
        "flags": [],
        "target_paths": [],
        "raw_input": binary,
        "sub_commands": [],
    }
    if destination:
        if is_hostname_dest:
            action_dict["hostname_or_sni"] = destination
        else:
            action_dict["dst_ip"] = destination
    parsed_action = json.dumps(action_dict)''',
    content
)

content = re.sub(
    r'            INSERT INTO events\n                \(timestamp, raw_input, parsed_action, event_type, verdict, reason, execution, output\)\n            VALUES \(\?, \?, \?, \'shell_command\', \'FLAG\', \'test\', \'none\', \'{}\'\)\n            \"\"\",\n            \(str\(ts\), binary, parsed_action\),',
    r'''            INSERT INTO events
                (timestamp, raw_input, parsed_action, event_type, verdict, reason, execution, output, action_id)
            VALUES (?, ?, ?, 'shell_command', 'FLAG', 'test', 'none', '{}', ?)
            """,
            (str(ts), binary, parsed_action, action_id),''',
    content
)


with open("tests/test_phase3_advisor.py", "w") as f:
    f.write(content)

