import re

with open("tests/test_phase3_advisor.py", "r") as f:
    content = f.read()

# Replace test_two_distinct_pairs_two_candidates
old_test = """    def test_two_distinct_pairs_two_candidates(self, tmp_db):
        \"\"\"Two different (binary, destination) pairs each at threshold → two candidates.\"\"\"
        for _ in range(10):
            _insert_network_flag(tmp_db, "curl", "evil.example.com", pure_hostname=True)
        for _ in range(12):
            _insert_network_flag(tmp_db, "python3", "1.2.3.4", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 2
        
        # We expect: (curl, hostname axis), (python3, IP axis)
        axes = {c.detection_axis for c in candidates}
        assert axes == {"hostname", "ip"}
        binaries = {c.binary for c in candidates}
        assert binaries == {"curl", "python3"}"""

new_tests = """    def test_shell_grouping_respects_binary(self, tmp_db):
        \"\"\"Two different shell-origin (binary, destination) pairs each at threshold → two candidates.\"\"\"
        for _ in range(10):
            _insert_shell_flag(tmp_db, "curl", "evil.example.com", is_hostname_dest=True)
        for _ in range(12):
            _insert_shell_flag(tmp_db, "python3", "1.2.3.4", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 2
        
        # We expect: (curl, hostname axis), (python3, IP axis)
        axes = {c.detection_axis for c in candidates}
        assert axes == {"hostname", "ip"}
        binaries = {c.binary for c in candidates}
        assert binaries == {"curl", "python3"}

    def test_network_grouping_ignores_binary(self, tmp_db):
        \"\"\"6 FLAG network events for 'curl' and 6 for 'wget' to same dst_ip -> ONE candidate with 12 counts.\"\"\"
        for _ in range(6):
            _insert_network_flag(tmp_db, "placeholder", "1.2.3.4", is_hostname_dest=False, action_id="a1")
            _insert_shell_flag(tmp_db, "curl", "", action_id="a1")
        for _ in range(6):
            _insert_network_flag(tmp_db, "placeholder", "1.2.3.4", is_hostname_dest=False, action_id="a2")
            _insert_shell_flag(tmp_db, "wget", "", action_id="a2")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].occurrence_count == 12
        assert candidates[0].binary == "multiple sources"
        assert candidates[0].destination == "1.2.3.4"

    def test_network_binary_resolution(self, tmp_db):
        \"\"\"Test binary resolution branches: single, multiple (covered above), unknown.\"\"\"
        # Single source
        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "8.8.8.8", is_hostname_dest=False, action_id="a3")
        _insert_shell_flag(tmp_db, "nmap", "", action_id="a3")

        # Unknown source (no shell correlation)
        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "9.9.9.9", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        # Should find 8.8.8.8 and 9.9.9.9
        assert len(candidates) == 2
        c_nmap = next(c for c in candidates if c.destination == "8.8.8.8")
        assert c_nmap.binary == "nmap"
        c_unknown = next(c for c in candidates if c.destination == "9.9.9.9")
        assert c_unknown.binary == "unknown source"

    def test_resolve_network_binary_failure_isolation(self, tmp_db, monkeypatch):
        \"\"\"Monkeypatch resolution to fail, confirm candidate still returned as unknown source.\"\"\"
        def fail_resolve(*args, **kwargs):
            raise RuntimeError("Database error")
        monkeypatch.setattr("daemon.advisor.detection_scanner._resolve_network_binary", fail_resolve)

        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "4.4.4.4", is_hostname_dest=False, action_id="a4")
        _insert_shell_flag(tmp_db, "nmap", "", action_id="a4")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].binary == "unknown source"
        assert candidates[0].destination == "4.4.4.4\"\"\"

content = content.replace(old_test, new_tests)

with open("tests/test_phase3_advisor.py", "w") as f:
    f.write(content)
