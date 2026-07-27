import sqlite3
import json
conn = sqlite3.connect(':memory:')
conn.execute("CREATE TABLE events (action_id TEXT, event_type TEXT, parsed_action TEXT, verdict TEXT, timestamp TEXT)")
conn.execute("INSERT INTO events VALUES ('a1', 'shell_command', '{\"binary\": \"curl\"}', 'ALLOW', '2026-07-26T10:25:22.183Z')")
conn.execute("INSERT INTO events VALUES ('a1', 'network', '{\"dst_ip\": \"1.1.1.1\"}', 'FLAG', '2026-07-26T10:25:22.183Z')")
conn.execute("INSERT INTO events VALUES ('a2', 'shell_command', '{\"binary\": \"wget\"}', 'ALLOW', '2026-07-26T10:25:22.183Z')")
conn.execute("INSERT INTO events VALUES ('a2', 'network', '{\"dst_ip\": \"1.1.1.1\"}', 'FLAG', '2026-07-26T10:25:22.183Z')")

cur = conn.execute("""
    SELECT DISTINCT json_extract(e2.parsed_action, '$.binary')
    FROM events e1
    JOIN events e2 ON e1.action_id = e2.action_id
    WHERE e1.event_type = 'network'
      AND json_extract(e1.parsed_action, '$.dst_ip') = ?
      AND e1.verdict = 'FLAG'
      AND e2.event_type = 'shell_command'
""", ("1.1.1.1",))
print(cur.fetchall())
