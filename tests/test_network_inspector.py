"""
tests/test_network_inspector.py — Unit tests for daemon/inspectors/network_inspector.py

Tests construct ParsedNetworkAction objects directly (no packet bytes needed —
that's PacketParser's job, already tested). They inject network_rules inline so
tests are independent of the current contents of policy.yaml.

Coverage (per the Step 3 prompt requirements):
  1.  Allowlisted host → ALLOW
  2.  Blocked IP (exact) → BLOCK
  3.  CIDR block matching → BLOCK
  4.  Wildcard hostname matching (*.domain.com) → ALLOW
  5.  Default-deny fires when no rule matches → BLOCK
  6.  Non-network action (plain ParsedAction) → None (inspector has no opinion)
  7.  Hostname wildcard does NOT match the bare domain (*.openai.com ≠ openai.com)
  8.  Hostname wildcard does NOT match two-label prefix (a.b.example.com ≠ *.example.com)
  9.  Exact hostname match
  10. Port wildcard "*" matches any port
  11. Port integer match — correct port → ALLOW, wrong port → next rule or default-deny
  12. CIDR "0.0.0.0/0" (the catch-all rule) matches any IP
  13. dst_ip "unknown" (unparseable packet fallback) → BLOCK via catch-all
  14. hostname=None does not match a named hostname pattern
  15. Multiple rules: first-match wins
  16. Rule with no match dimensions → matches everything (wildcard all)
  17. source_inspector field is "NetworkInspector" on every returned Verdict
"""

from __future__ import annotations

import pytest
from typing import Any

from daemon.inspectors.network_inspector import NetworkInspector
from daemon.inspectors.base import Decision, Verdict
from daemon.parser.packet_parser import ParsedNetworkAction
from daemon.parser.shell_parser import ParsedAction


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_action(
    dst_ip: str = "8.8.8.8",
    dst_port: int = 443,
    protocol: str = "TCP",
    hostname_or_sni: str | None = None,
    direction: str = "outbound",
) -> ParsedNetworkAction:
    """Construct a ParsedNetworkAction with sensible defaults for testing."""
    return ParsedNetworkAction(
        binary="<network>",
        raw_input=f"{protocol} {dst_ip}:{dst_port}",
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        hostname_or_sni=hostname_or_sni,
        raw_bytes=b"",
        direction=direction,
    )


def make_inspector(rules: list[dict[str, Any]]) -> NetworkInspector:
    """Construct a NetworkInspector with the given rules."""
    return NetworkInspector(network_rules=rules)


# Sample rules used across multiple tests
ALLOW_OPENAI_RULE = {
    "match": {"hostname": ["api.openai.com", "*.openai.com"], "dst_port": [443]},
    "action": "allow",
    "risk": "low",
    "reason": "OpenAI API",
}

BLOCK_IP_RULE = {
    "match": {"dst_ip": ["1.2.3.4"]},
    "action": "block",
    "risk": "high",
    "reason": "known bad IP",
}

BLOCK_CIDR_RULE = {
    "match": {"dst_ip": ["192.168.0.0/16"]},
    "action": "block",
    "risk": "medium",
    "reason": "private range",
}

DEFAULT_DENY_RULE = {
    "match": {"dst_ip": ["0.0.0.0/0"]},
    "action": "block",
    "risk": "high",
    "reason": "default-deny",
}


# ── Test: Inspector contract ──────────────────────────────────────────────────

class TestInspectorContract:
    """NetworkInspector must satisfy the Inspector ABC contract."""

    def test_returns_verdict_for_network_action(self):
        inspector = make_inspector([DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action())
        assert isinstance(result, Verdict)

    def test_returns_none_for_plain_parsed_action(self):
        """Non-network ParsedAction → None. Inspector has no opinion on shell commands."""
        inspector = make_inspector([DEFAULT_DENY_RULE])
        shell_action = ParsedAction(binary="rm", args=["/tmp/foo"], raw_input="rm /tmp/foo")
        result = inspector.inspect(shell_action)
        assert result is None, (
            "NetworkInspector must return None for non-network actions — "
            "it must be a silent no-op in the shell command path."
        )

    def test_source_inspector_name(self):
        inspector = make_inspector([DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action())
        assert result.source_inspector == "NetworkInspector"

    def test_source_inspector_name_on_allow(self):
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(hostname_or_sni="api.openai.com", dst_port=443))
        assert result.source_inspector == "NetworkInspector"


# ── Test: Allowlisted host ────────────────────────────────────────────────────

class TestAllowlistedHost:
    """Exact and wildcard hostname allowlist rules."""

    def test_exact_hostname_allow(self):
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(dst_ip="104.18.7.192", dst_port=443, hostname_or_sni="api.openai.com")
        )
        assert result.decision == Decision.ALLOW

    def test_wildcard_subdomain_allow(self):
        """*.openai.com matches sub.openai.com."""
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(hostname_or_sni="sub.openai.com", dst_port=443)
        )
        assert result.decision == Decision.ALLOW

    def test_wildcard_does_not_match_bare_domain(self):
        """*.openai.com must NOT match openai.com (no subdomain label)."""
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(hostname_or_sni="openai.com", dst_port=443)
        )
        # openai.com is not on the allowlist — falls through to default-deny
        assert result.decision == Decision.BLOCK

    def test_wildcard_does_not_match_two_label_prefix(self):
        """*.openai.com must NOT match a.b.openai.com (two prefix labels)."""
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(hostname_or_sni="a.b.openai.com", dst_port=443)
        )
        assert result.decision == Decision.BLOCK

    def test_wrong_port_does_not_match_allowlist(self):
        """Allowlist rule specifies port 443 — same hostname on port 80 should NOT match."""
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(hostname_or_sni="api.openai.com", dst_port=80)
        )
        assert result.decision == Decision.BLOCK


# ── Test: Blocked IP (exact) ──────────────────────────────────────────────────

class TestBlockedIPExact:

    def test_exact_ip_blocked(self):
        inspector = make_inspector([BLOCK_IP_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="1.2.3.4", dst_port=80))
        assert result.decision == Decision.BLOCK

    def test_different_ip_not_blocked_by_exact_rule(self):
        """1.2.3.5 is not 1.2.3.4 — falls through to default-deny, still BLOCK."""
        inspector = make_inspector([BLOCK_IP_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="1.2.3.5", dst_port=80))
        # Still blocked, but by default-deny, not by the specific IP rule.
        assert result.decision == Decision.BLOCK
        assert "default-deny" in result.reason


# ── Test: CIDR block matching ─────────────────────────────────────────────────

class TestCIDRMatching:

    def test_ip_in_cidr_range_blocked(self):
        """192.168.1.50 is in 192.168.0.0/16."""
        inspector = make_inspector([BLOCK_CIDR_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="192.168.1.50"))
        assert result.decision == Decision.BLOCK

    def test_ip_at_cidr_boundary_blocked(self):
        """192.168.0.1 is in 192.168.0.0/16."""
        inspector = make_inspector([BLOCK_CIDR_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="192.168.0.1"))
        assert result.decision == Decision.BLOCK

    def test_ip_outside_cidr_not_matched(self):
        """10.0.0.1 is NOT in 192.168.0.0/16 — falls to default-deny."""
        inspector = make_inspector([BLOCK_CIDR_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="10.0.0.1"))
        assert result.decision == Decision.BLOCK
        assert "default-deny" in result.reason

    def test_catchall_cidr_0_0_0_0_matches_any_ip(self):
        """0.0.0.0/0 is the universal CIDR — matches every IPv4 address."""
        inspector = make_inspector([DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="203.0.113.42"))
        assert result.decision == Decision.BLOCK

    def test_cidr_with_host_bits_set_tolerated(self):
        """10.0.0.1/8 should work (strict=False) — tolerates host bits in the network addr."""
        rule = {"match": {"dst_ip": ["10.0.0.1/8"]}, "action": "block", "risk": "high"}
        inspector = make_inspector([rule, DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="10.5.6.7"))
        assert result.decision == Decision.BLOCK


# ── Test: Default-deny ────────────────────────────────────────────────────────

class TestDefaultDeny:

    def test_no_matching_rule_returns_block(self):
        """With an empty rule list, the inspector's internal default-deny fires."""
        inspector = make_inspector([])
        result = inspector.inspect(make_action(dst_ip="8.8.8.8", dst_port=53))
        assert result.decision == Decision.BLOCK

    def test_default_deny_reason_mentions_destination(self):
        inspector = make_inspector([])
        result = inspector.inspect(make_action(dst_ip="8.8.8.8", dst_port=53))
        assert "8.8.8.8" in result.reason
        assert "default-deny" in result.reason

    def test_default_deny_with_hostname_in_reason(self):
        inspector = make_inspector([])
        result = inspector.inspect(
            make_action(dst_ip="8.8.8.8", dst_port=443, hostname_or_sni="evil.com")
        )
        assert "evil.com" in result.reason

    def test_explicit_catch_all_rule_fires_as_expected(self):
        """The explicit 0.0.0.0/0 catch-all rule produces a reason with 'default-deny'."""
        inspector = make_inspector([DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="203.0.113.1", dst_port=80))
        assert result.decision == Decision.BLOCK
        assert "default-deny" in result.reason

    def test_custom_default_decision_flag(self):
        """Default decision can be overridden to FLAG at construction."""
        inspector = NetworkInspector(network_rules=[], default_decision=Decision.FLAG)
        result = inspector.inspect(make_action())
        assert result.decision == Decision.FLAG


# ── Test: Wildcard hostname matching (detailed) ───────────────────────────────

class TestWildcardHostname:

    def test_single_label_wildcard(self):
        rule = {
            "match": {"hostname": ["*.example.com"], "dst_port": ["*"]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule, DEFAULT_DENY_RULE])
        assert inspector.inspect(
            make_action(hostname_or_sni="sub.example.com")
        ).decision == Decision.ALLOW

    def test_wildcard_star_matches_any_hostname(self):
        rule = {
            "match": {"hostname": ["*"]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule])
        assert inspector.inspect(
            make_action(hostname_or_sni="anything.at.all.example.com")
        ).decision == Decision.ALLOW

    def test_none_hostname_does_not_match_named_pattern(self):
        """A packet with no extractable hostname (None) must not match a hostname pattern."""
        inspector = make_inspector([ALLOW_OPENAI_RULE, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(dst_ip="104.18.7.192", dst_port=443, hostname_or_sni=None)
        )
        # No hostname → hostname rule doesn't match → falls to default-deny
        assert result.decision == Decision.BLOCK

    def test_none_hostname_can_still_match_ip_rule(self):
        """Even with hostname=None, an IP-based allowlist rule should still match."""
        allow_ip_rule = {
            "match": {"dst_ip": ["104.18.7.192"]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([allow_ip_rule, DEFAULT_DENY_RULE])
        result = inspector.inspect(
            make_action(dst_ip="104.18.7.192", dst_port=443, hostname_or_sni=None)
        )
        assert result.decision == Decision.ALLOW


# ── Test: Port matching ───────────────────────────────────────────────────────

class TestPortMatching:

    def test_port_wildcard_matches_any(self):
        rule = {
            "match": {"dst_ip": ["8.8.8.8"], "dst_port": ["*"]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule])
        for port in [53, 80, 443, 8080]:
            result = inspector.inspect(make_action(dst_ip="8.8.8.8", dst_port=port))
            assert result.decision == Decision.ALLOW, f"Expected ALLOW for port {port}"

    def test_port_integer_match(self):
        rule = {
            "match": {"dst_ip": ["8.8.8.8"], "dst_port": [53]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule, DEFAULT_DENY_RULE])
        assert inspector.inspect(
            make_action(dst_ip="8.8.8.8", dst_port=53)
        ).decision == Decision.ALLOW

    def test_port_string_integer_match(self):
        """dst_port can be specified as "443" (string) in policy.yaml — must still match."""
        rule = {
            "match": {"dst_ip": ["8.8.8.8"], "dst_port": ["443"]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule, DEFAULT_DENY_RULE])
        assert inspector.inspect(
            make_action(dst_ip="8.8.8.8", dst_port=443)
        ).decision == Decision.ALLOW

    def test_wrong_port_misses_rule(self):
        rule = {
            "match": {"dst_ip": ["8.8.8.8"], "dst_port": [53]},
            "action": "allow",
            "risk": "low",
        }
        inspector = make_inspector([rule, DEFAULT_DENY_RULE])
        # Port 80 doesn't match port 53 rule → falls to default-deny
        assert inspector.inspect(
            make_action(dst_ip="8.8.8.8", dst_port=80)
        ).decision == Decision.BLOCK


# ── Test: First-match wins ────────────────────────────────────────────────────

class TestFirstMatchWins:

    def test_allow_before_deny_wins(self):
        """If ALLOW rule precedes BLOCK rule, ALLOW fires first."""
        rules = [
            {"match": {"dst_ip": ["1.2.3.4"]}, "action": "allow", "risk": "low"},
            {"match": {"dst_ip": ["1.2.3.4"]}, "action": "block", "risk": "high"},
        ]
        inspector = make_inspector(rules)
        assert inspector.inspect(make_action(dst_ip="1.2.3.4")).decision == Decision.ALLOW

    def test_deny_before_allow_wins(self):
        """If BLOCK rule precedes ALLOW rule, BLOCK fires first."""
        rules = [
            {"match": {"dst_ip": ["1.2.3.4"]}, "action": "block", "risk": "high"},
            {"match": {"dst_ip": ["1.2.3.4"]}, "action": "allow", "risk": "low"},
        ]
        inspector = make_inspector(rules)
        assert inspector.inspect(make_action(dst_ip="1.2.3.4")).decision == Decision.BLOCK

    def test_specific_allow_before_catchall_deny(self):
        """Realistic policy: specific allow above catch-all deny."""
        rules = [
            ALLOW_OPENAI_RULE,
            DEFAULT_DENY_RULE,
        ]
        inspector = make_inspector(rules)
        # Allowlisted → ALLOW
        assert inspector.inspect(
            make_action(dst_ip="1.2.3.4", dst_port=443, hostname_or_sni="api.openai.com")
        ).decision == Decision.ALLOW
        # Non-allowlisted → BLOCK
        assert inspector.inspect(
            make_action(dst_ip="9.9.9.9", dst_port=443, hostname_or_sni="evil.com")
        ).decision == Decision.BLOCK


# ── Test: Rule with no match dimensions ──────────────────────────────────────

class TestOpenRule:

    def test_empty_match_dict_matches_everything(self):
        """A rule with an empty match: {} has no constraints — matches any packet."""
        rule = {"match": {}, "action": "allow", "risk": "low"}
        inspector = make_inspector([rule])
        result = inspector.inspect(make_action(dst_ip="203.0.113.1", dst_port=9999))
        assert result.decision == Decision.ALLOW

    def test_unknown_ip_fallback_blocked_by_catchall(self):
        """dst_ip='unknown' (PacketParser fallback) is blocked by 0.0.0.0/0 catch-all."""
        inspector = make_inspector([DEFAULT_DENY_RULE])
        result = inspector.inspect(make_action(dst_ip="unknown"))
        # 'unknown' is not a valid IP so _ip_matches raises ValueError internally,
        # skip that pattern, fall to next rule or default-deny.
        assert result.decision == Decision.BLOCK
