"""
daemon/inspectors/command_inspector.py — Shell command inspector for Warden.

CONTRACT: implements Inspector.inspect() — see daemon/inspectors/base.py

This inspector evaluates a ParsedAction's binary name and target_paths against
a list of pre-parsed policy rules. It does NOT load policy.yaml — that is the
Rule Engine's job. Rules are injected at construction time.

WHY inject rules instead of loading policy.yaml here: the Rule Engine is the
single source of truth for policy. If the inspector loaded its own copy, any
hot-reload or policy change would need to notify every inspector separately.
Injecting means a single reload in the Rule Engine propagates automatically.

WHY this inspector only looks at binary + target_paths: those are the two
dimensions that matter for shell command policy. Other inspectors (rate-limit,
network, etc.) will handle their own dimensions. See WARDEN_SPEC.md §4.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Optional

from .base import Decision, Inspector, Verdict
from ..parser.shell_parser import ParsedAction


class CommandInspector(Inspector):
    """
    CONTRACT: implements Inspector.inspect() — see daemon/inspectors/base.py

    Evaluates a ParsedAction against a list of policy rules (binary + path_scope
    patterns) and returns a Verdict. Does not make a final enforcement decision —
    that is the Rule Engine's responsibility after all inspectors have reported.

    Args:
        rules: List of rule dicts as returned by RuleEngine.rules (already parsed
               from policy.yaml). Each rule has keys: match.binary (list[str]),
               match.path_scope (list[str]), action (str), risk (str).
        default_decision: What to return when no rule matches. Defaults to FLAG.
        work_dir: Used to resolve relative path patterns (e.g. ./project/**)
                  against an absolute base. Should match the daemon's work_dir.
    """

    NAME = "CommandInspector"

    def __init__(
        self,
        rules: list[dict[str, Any]],
        work_dir: Optional[Path] = None,
    ) -> None:
        self._rules = rules
        self._work_dir = Path(work_dir).resolve() if work_dir else Path.cwd().resolve()

    def inspect(self, action: ParsedAction) -> Optional[Verdict]:
        """Evaluate binary + target_paths against injected rules.

        Rule evaluation is top-down, first-match wins. This matches the Rule
        Engine's own evaluation order so verdicts are consistent.

        WHY first-match (not most-specific): see WARDEN_BUILD_CONTEXT.md §5
        and engine.py for the documented rationale. Consistency between inspector
        and engine is critical — they must agree on which rule fires.
        """
        binary = action.binary
        paths = action.target_paths

        for rule in self._rules:
            match_cfg = rule.get("match", {})
            binary_patterns: list[str] = match_cfg.get("binary", ["*"])
            path_scope: list[str] = match_cfg.get("path_scope", ["*"])

            if not self._binary_matches(binary, binary_patterns):
                continue

            if not self._paths_match_scope(paths, path_scope, binary, self._work_dir):
                continue

            # This rule fires
            action_str: str = rule.get("action", "flag").upper()
            risk: str = rule.get("risk", "unknown")
            try:
                decision = Decision[action_str]
            except KeyError:
                decision = Decision.FLAG

            return Verdict(
                decision=decision,
                reason=(
                    f"Rule matched: binary={binary!r} with path_scope={path_scope} "
                    f"→ {action_str} (risk={risk})"
                ),
                source_inspector=self.NAME,
            )

        # No rule matched — return None to indicate no opinion
        return None

    # ------------------------------------------------------------------
    # Internal matching helpers
    # ------------------------------------------------------------------

    def _binary_matches(self, binary: str, patterns: list[str]) -> bool:
        """Return True if `binary` matches any pattern in `patterns`.

        Patterns use fnmatch glob syntax. "*" matches anything.
        Comparison is case-sensitive (POSIX binaries are case-sensitive).
        """
        for pattern in patterns:
            if fnmatch.fnmatch(binary, pattern):
                return True
        return False

    def _paths_match_scope(
        self,
        paths: list[Path],
        path_scope: list[str],
        binary: str,
        work_dir: Optional[Path] = None,
    ) -> bool:
        """Evaluate path_scope patterns against the action's target_paths.

        Path scope semantics (documented here because this is the trickiest part):

        Positive patterns (no "!" prefix), e.g. "**/.env":
          At least ONE target path must match at least one positive pattern
          for the rule to fire. If no target paths exist, we treat this as
          a match only if the scope is "*" (wildcard-everything).

        Negative patterns ("!" prefix), e.g. "!./project/**":
          The rule fires if at least one target path does NOT match the
          positive form of the pattern. Semantics: "deny if path is outside
          the allowed scope."

        WHY this design: it mirrors common firewall/policy convention where
        "!./project/**" means "anything NOT inside ./project" is in-scope for
        this rule. This lets you write "deny rm outside project dir" naturally.

        RISK: When an action has NO target_paths (e.g. `whoami`, `env`), path
        scope matching is inconclusive. We treat "*" scope as a match (fires)
        and all other scopes as non-matching (rule does not fire, falls through).
        This means catch-all rules (binary="*", path_scope=["*"]) still work
        for no-path commands.
        """
        # Separate positive from negative patterns
        positive = [p for p in path_scope if not p.startswith("!")]
        negative = [p[1:] for p in path_scope if p.startswith("!")]

        # Handle the case where there are no target paths
        if not paths:
            # Only match if every scope pattern is a wildcard
            all_wildcard = all(
                p in ("*", "**", "**/*") for p in (positive + negative)
            )
            return all_wildcard

        # Evaluate negative patterns first: rule fires if any path is OUTSIDE
        # the allowed scope (i.e., does NOT match the positive form of the negation)
        for neg_pattern in negative:
            for path in paths:
                if not self._path_matches_glob(path, neg_pattern, work_dir):
                    return True  # path is outside scope → rule fires

        # Evaluate positive patterns: rule fires if any path matches any pattern
        if positive:
            for pos_pattern in positive:
                for path in paths:
                    if self._path_matches_glob(path, pos_pattern, work_dir):
                        return True
            return False

        # If only negative patterns were specified and none fired, no match
        return False

    @staticmethod
    def _path_matches_glob(path: Path, pattern: str, work_dir: Optional[Path] = None) -> bool:
        """Match a resolved Path against a glob pattern.

        WHY use both fnmatch on string and Path.match(): fnmatch handles the
        "**" multi-segment wildcard correctly when applied to the string form,
        while Path.match() handles relative-pattern matching. We try both and
        return True if either matches.

        WHY match against multiple string forms: a resolved path like
        /home/user/project/.env should match the pattern "**/.env". fnmatch
        needs the full string, not just the basename.
        """
        _work_dir = (work_dir or Path.cwd()).resolve()
        is_relative_pattern = not pattern.startswith("/") and pattern not in ("*", "**", "**/*")

        if is_relative_pattern:
            base_part = pattern.rstrip("/").rstrip("*").rstrip("/")
            if base_part:
                try:
                    resolved_base = (_work_dir / base_part).resolve()
                    try:
                        path.relative_to(resolved_base)
                        return True
                    except ValueError:
                        pass
                except Exception:
                    pass

        path_str = str(path)
        # Try fnmatch against the full path string
        if fnmatch.fnmatch(path_str, pattern):
            return True
        # Try against just the basename for patterns like "*.env"
        if fnmatch.fnmatch(path.name, pattern):
            return True
        # Try Path.match() for relative patterns like "./project/**"
        try:
            if path.match(pattern):
                return True
        except Exception:
            pass
        # Try fnmatch with just the last N path components for "**/.env" style
        parts = path.parts
        for i in range(len(parts)):
            partial = str(Path(*parts[i:]))
            if fnmatch.fnmatch(partial, pattern):
                return True
        return False
