"""
daemon/inspectors/network_inspector.py — Network packet inspector for Warden Phase 2.

CONTRACT: implements Inspector.inspect() — see daemon/inspectors/base.py

Evaluates a ParsedNetworkAction's (dst_ip, dst_port, hostname_or_sni) against a list
of pre-parsed network_rules. Does NOT load policy.yaml — that is the Rule Engine's job.
Rules are injected at construction time, matching the pattern established by CommandInspector.

WHY default-deny (BLOCK when no rule matches), not FLAG:
  CommandInspector uses FLAG as the default because unknown shell commands are merely
  unusual — they might be legitimate agent work. Network egress is the opposite: an agent
  has no legitimate reason to reach an arbitrary external host. BLOCK as default makes
  the allowlist model explicit: if you haven't said yes, the answer is no.
  This is documented in WARDEN_SPEC.md §7.4 and matches the Phase 2 demo design.

WHY ipaddress module for IP matching (not string comparison):
  String comparison of "10.0.0.1" against CIDR "10.0.0.0/8" would require manual
  bit arithmetic and is a common source of subtle bugs. Python's ipaddress module
  provides ip_address(dst_ip) in ip_network(cidr, strict=False) which is correct,
  readable, and handles edge cases (IPv4-mapped IPv6, etc.) properly.

WHY hostname matching supports only wildcard prefix (*.domain.com), not full glob:
  SNI hostnames follow a strict hierarchical structure. Wildcard certificates cover
  exactly one label: *.example.com matches sub.example.com but not example.com and
  not a.b.example.com. This is the semantics an operator expects when writing a rule
  with "*.openai.com". Supporting arbitrary glob (e.g. *ai*) on hostnames would be
  surprising and error-prone. If broader matching is needed, add an explicit rule.

Rule matching order: top-down, first-match wins. Same as the command policy and
the CommandInspector. This is documented in policy.yaml and engine.py. Network rules
follow the same contract.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from .base import Decision, Inspector, Verdict
from ..parser.shell_parser import ParsedAction

# Import ParsedNetworkAction for the isinstance downcast.
# WHY downcast instead of a separate interface: ParsedNetworkAction IS-A ParsedAction
# (see packet_parser.py). The inspector contract takes ParsedAction; we downcast to
# access network-specific fields. This keeps the Inspector ABC unchanged and avoids
# creating a parallel type hierarchy for a single inspector.
from ..parser.packet_parser import ParsedNetworkAction


class NetworkInspector(Inspector):
    """
    CONTRACT: implements Inspector.inspect() — see daemon/inspectors/base.py

    Evaluates a ParsedNetworkAction against a list of network_rules from policy.yaml.
    Returns a Verdict on match, or None if the action is not a network action (so the
    inspector is a no-op when the core loop runs it against a shell command).

    Args:
        network_rules: List of rule dicts from the network_rules section of policy.yaml.
                       Each rule has keys: match.dst_ip (list[str]), match.dst_port
                       (list[str|int]), match.hostname (list[str]), action (str), risk (str).
                       All match keys are optional — omitting a key means "match anything"
                       for that dimension.
        default_decision: Decision to return when no network_rule matches.
                          Defaults to BLOCK (default-deny for outbound traffic).
    """

    NAME = "NetworkInspector"

    def __init__(
        self,
        network_rules: list[dict[str, Any]],
        default_decision: Decision = Decision.BLOCK,
    ) -> None:
        self._rules = network_rules
        self._default_decision = default_decision

    def inspect(self, action: ParsedAction) -> Optional[Verdict]:
        """Evaluate dst_ip, dst_port, and hostname_or_sni against injected network rules.

        Returns None (no opinion) if action is not a ParsedNetworkAction — so this
        inspector is silently skipped when the core loop runs it against a shell command.

        WHY None for non-network actions: the Inspector chain in the core loop runs ALL
        inspectors against every action. NetworkInspector has nothing to say about
        `rm -rf /` — returning None signals that cleanly, rather than returning a
        spurious ALLOW that would incorrectly influence the Rule Engine's aggregation.
        """
        if not isinstance(action, ParsedNetworkAction):
            return None

        dst_ip = action.dst_ip
        dst_port = action.dst_port
        hostname = action.hostname_or_sni  # may be None

        for rule in self._rules:
            match_cfg = rule.get("match", {})

            # Each dimension is independently optional.
            # If a dimension key is absent, it matches anything (open).
            # All present dimensions must ALL match for the rule to fire (AND semantics).
            if "dst_ip" in match_cfg:
                if not self._ip_matches(dst_ip, match_cfg["dst_ip"]):
                    continue

            if "dst_port" in match_cfg:
                if not self._port_matches(dst_port, match_cfg["dst_port"]):
                    continue

            if "hostname" in match_cfg:
                if not self._hostname_matches(hostname, match_cfg["hostname"]):
                    continue

            # All present dimensions matched — this rule fires
            action_str: str = rule.get("action", "block").upper()
            risk: str = rule.get("risk", "unknown")
            reason_note: str = rule.get("reason", "")

            try:
                decision = Decision[action_str]
            except KeyError:
                decision = Decision.FLAG

            reason_parts = [
                f"network_rule matched: {dst_ip}:{dst_port}",
            ]
            if hostname:
                reason_parts.append(f"hostname={hostname!r}")
            reason_parts.append(f"→ {action_str} (risk={risk})")
            if reason_note:
                reason_parts.append(f"[{reason_note}]")

            return Verdict(
                decision=decision,
                reason=" ".join(reason_parts),
                source_inspector=self.NAME,
            )

        # No rule matched — apply the default decision.
        # For Phase 2 outbound enforcement, default is BLOCK (default-deny).
        return Verdict(
            decision=self._default_decision,
            reason=(
                f"no network_rule matched {dst_ip}:{dst_port}"
                + (f" ({hostname})" if hostname else "")
                + f" → {self._default_decision.value} (default-deny)"
            ),
            source_inspector=self.NAME,
        )

    # ── Matching helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _ip_matches(dst_ip: str, patterns: list[str]) -> bool:
        """Return True if dst_ip matches any pattern in the list.

        Patterns can be:
          - A specific IP address:  "8.8.8.8"
          - A CIDR block:           "10.0.0.0/8", "0.0.0.0/0"
          - The wildcard string:    "*"

        WHY strict=False on ip_network: "10.0.0.1/8" with strict=True would raise
        ValueError (host bits set). Operators writing CIDR rules will naturally write
        "10.0.0.0/8" but we tolerate "10.0.0.1/8" as well — the intent is clear.
        """
        for pattern in patterns:
            if pattern == "*":
                return True
            try:
                dst = ipaddress.ip_address(dst_ip)
                network = ipaddress.ip_network(pattern, strict=False)
                if dst in network:
                    return True
            except ValueError:
                # pattern is not a valid IP or CIDR — skip silently.
                # RISK: a typo in policy.yaml silently becomes a non-matching rule.
                # TODO(phase3): validate all rules at load time and raise on bad patterns.
                continue
        return False

    @staticmethod
    def _port_matches(dst_port: int, patterns: list[str | int]) -> bool:
        """Return True if dst_port matches any pattern in the list.

        Patterns can be:
          - An integer:     443
          - A string int:   "443"
          - A wildcard:     "*"
        """
        for pattern in patterns:
            if pattern == "*":
                return True
            try:
                if int(pattern) == dst_port:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    @staticmethod
    def _hostname_matches(hostname: Optional[str], patterns: list[str]) -> bool:
        """Return True if hostname matches any pattern in the list.

        Patterns can be:
          - An exact hostname:       "api.openai.com"
          - A wildcard-prefix:       "*.openai.com"
            Matches "sub.openai.com" but NOT "openai.com" (no label) and
            NOT "a.b.openai.com" (two labels — same semantics as TLS wildcards).
          - The wildcard:            "*"

        WHY hostname=None does not match named patterns:
          If we couldn't extract a hostname (plain TCP to a raw IP, or malformed TLS),
          we return False for any named hostname pattern. The packet may still match on
          dst_ip or dst_port dimensions. If the caller wants to allow packets with no
          hostname, they should write an ip-based rule, not a hostname rule.

        WHY NOT match two-label wildcards (a.b.example.com against *.example.com):
          This mirrors RFC 6125 / TLS wildcard cert semantics. An operator who writes
          *.openai.com expects exactly that — one sublabel. If they want to allow all
          subdomains at any depth, they should write two rules or use a broader pattern.
        """
        if hostname is None:
            # An absent hostname never matches a named pattern.
            return False

        for pattern in patterns:
            if pattern == "*":
                return True

            if pattern.startswith("*."):
                # Wildcard prefix: *.domain.com
                # The hostname must end with .domain.com and have exactly one extra label.
                suffix = pattern[1:]  # ".domain.com"
                if hostname.endswith(suffix):
                    # Ensure there's exactly one label before the suffix (no dots in prefix).
                    prefix = hostname[: -len(suffix)]
                    if prefix and "." not in prefix:
                        return True
            else:
                # Exact match
                if hostname == pattern:
                    return True

        return False
