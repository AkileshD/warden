with open("tests/test_phase3_advisor.py", "r") as f:
    content = f.read()

content = content.replace(
    '    def test_shell_events_excluded(self, tmp_db):\n        """10 shell FLAG events for same binary must not trigger detection (network only)."""\n        for _ in range(10):\n            _insert_shell_flag(tmp_db, "curl", "evil.example.com")',
    '    def test_shell_events_without_dest_excluded(self, tmp_db):\n        """10 shell FLAG events without a destination must not trigger detection."""\n        for _ in range(10):\n            _insert_shell_flag(tmp_db, "curl", "")'
)

with open("tests/test_phase3_advisor.py", "w") as f:
    f.write(content)
