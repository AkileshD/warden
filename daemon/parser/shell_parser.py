"""
daemon/parser/shell_parser.py — Structural shell command parser for Warden.

CONTRACT: ShellParser.parse(raw: str) -> list[ParsedAction]
  Returns one ParsedAction per independent sub-command found in raw input.
  Callers MUST iterate over the returned list — a chained command (ls; rm -rf /)
  returns TWO ParsedAction objects, not one.

WHY shlex over regex: shlex correctly handles all POSIX quoting rules, including
  backslash escapes, single quotes (no escaping inside), and double quotes.
  Regex or str.split() would silently break on inputs like: echo 'hello; world'
  (should NOT be split) vs. ls; rm -rf / (MUST be split on the semicolon).

WHY pre-split on metacharacters before shlex: shlex.split() does not interpret
  shell control operators (;, &&, ||, |) as separators — it returns them as tokens.
  We must split the raw string ourselves, then shlex-tokenize each segment. This
  gives correct behavior for both quoted and unquoted metacharacters.

RISK: This parser handles the common POSIX subset. It does not handle:
  - Here-documents (<<EOF ... EOF)
  - Process substitution (<(...) or >(...))
  - Arithmetic expansion ($(( ... )))
  - Named pipe / coprocess syntax
  These are uncommon in AI agent workflows and deferred. TODO(phase2): evaluate
  whether any of the above appear in real agent traces and extend if needed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ParsedAction:
    """Structured representation of a single shell command.

    CONTRACT: One ParsedAction = one command invocation.
    Chained commands (via ; && || |) produce *multiple* ParsedAction objects,
    returned as a flat list by ShellParser.parse(). Each sub_command found via
    $(...) or backtick substitution is parsed recursively and attached here.
    """

    binary: str                              # The program being invoked, e.g. "rm"
    args: list[str] = field(default_factory=list)   # Positional arguments (non-flag)
    flags: list[str] = field(default_factory=list)  # Option tokens starting with "-"
    target_paths: list[Path] = field(default_factory=list)  # Resolved filesystem paths
    raw_input: str = ""                      # Original string that produced this action
    sub_commands: list[ParsedAction] = field(default_factory=list)  # From $(...) / backtick
    redirect_target: Optional[Path] = None   # Target path if command ends with > or >>
    redirect_append: bool = False            # True if >>, False if >

    def __repr__(self) -> str:
        return (
            f"ParsedAction(binary={self.binary!r}, flags={self.flags}, "
            f"args={self.args}, target_paths={[str(p) for p in self.target_paths]}, "
            f"sub_commands={len(self.sub_commands)}, "
            f"redirect_target={self.redirect_target})"
        )


# WHY this regex over shlex for the initial split: we need to split on ; && || |
# but ONLY when they are outside of quoted strings. The approach here is to first
# scan for quoted regions and avoid splitting inside them. We use a careful pattern
# that walks the string char-by-char to find shell metacharacter boundaries while
# respecting both single and double quotes.
_METACHAR_OPERATORS = re.compile(r"(&&|\|\||;|\|)")

# Regex to detect command substitution in argv tokens after shlex splits them
_CMD_SUBST_DOLLAR = re.compile(r"\$\((.+?)\)", re.DOTALL)   # $(...)
_CMD_SUBST_BACKTICK = re.compile(r"`(.+?)`", re.DOTALL)      # `...`


class ShellParser:
    """
    CONTRACT: implements ShellParser.parse() — the canonical command tokenizer
    for Warden. All command inspection starts here.

    Usage:
        parser = ShellParser(work_dir=Path("/some/project"))
        actions = parser.parse("ls; rm -rf /")
        # returns [ParsedAction(binary='ls', ...), ParsedAction(binary='rm', ...)]
    """

    def __init__(self, work_dir: Optional[Path] = None) -> None:
        # WHY store work_dir: target_paths are resolved relative to this directory
        # so that policy rules using relative glob patterns (./project/**) work
        # correctly regardless of where the daemon process itself is running.
        self.work_dir = Path(work_dir) if work_dir else Path.cwd()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw: str) -> list[ParsedAction]:
        """Parse a raw shell command string into a list of ParsedAction objects.

        Handles:
          - Simple commands:    "ls -la /tmp"          → [ParsedAction]
          - Semicolon chains:   "ls; rm -rf /"         → [ParsedAction, ParsedAction]
          - AND chains:         "mkdir x && cd x"       → [ParsedAction, ParsedAction]
          - OR chains:          "test || echo fail"     → [ParsedAction, ParsedAction]
          - Pipes:              "cat file | grep foo"   → [ParsedAction, ParsedAction]
          - Substitution:       "echo $(whoami)"        → [ParsedAction(sub=[ParsedAction])]
          - Quoted metas:       "echo 'hello; world'"   → [ParsedAction]  (no split)
        """
        raw = raw.strip()
        if not raw:
            return []

        segments = self._split_on_operators(raw)
        actions: list[ParsedAction] = []
        for segment in segments:
            segment = segment.strip()
            if segment:
                action = self._parse_segment(segment, original_raw=raw)
                if action:
                    actions.append(action)
        return actions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _split_on_operators(self, raw: str) -> list[str]:
        """Split raw on ; && || | while respecting quoted strings.

        WHY custom walk instead of regex: a regex over the entire string cannot
        easily track whether we're inside quotes. We walk char-by-char, toggle
        quote state, and only emit a split when we hit an operator outside quotes.
        """
        segments: list[str] = []
        current: list[str] = []
        i = 0
        in_single = False
        in_double = False

        while i < len(raw):
            ch = raw[i]

            # Toggle single-quote state (no nesting, no escaping inside)
            if ch == "'" and not in_double:
                in_single = not in_single
                current.append(ch)
                i += 1
                continue

            # Toggle double-quote state
            if ch == '"' and not in_single:
                in_double = not in_double
                current.append(ch)
                i += 1
                continue

            # Backslash outside quotes: escape next char, include both literally
            if ch == "\\" and not in_single and not in_double:
                current.append(ch)
                i += 1
                if i < len(raw):
                    current.append(raw[i])
                    i += 1
                continue

            # If inside any quote, accumulate literally
            if in_single or in_double:
                current.append(ch)
                i += 1
                continue

            # Check for two-char operators first (&&, ||)
            two = raw[i : i + 2]
            if two in ("&&", "||"):
                segments.append("".join(current))
                current = []
                i += 2
                continue

            # Single-char operators (; and |)
            # WHY separate check for |: we already consumed || above, so a lone
            # | here is genuinely a pipe operator.
            if ch in (";", "|"):
                segments.append("".join(current))
                current = []
                i += 1
                continue

            current.append(ch)
            i += 1

        if current:
            segments.append("".join(current))

        return [s for s in segments if s.strip()]

    def _parse_segment(self, segment: str, original_raw: str) -> Optional[ParsedAction]:
        """Tokenize a single command segment into a ParsedAction.

        Uses shlex.split() which correctly handles POSIX quoting, then classifies
        each token as binary / flag / arg / path, and recursively parses any
        command substitution found in token values.
        """
        segment = segment.strip()
        if not segment:
            return None

        try:
            tokens = shlex.split(segment)
        except ValueError:
            # WHY keep going on shlex error: malformed quoting shouldn't crash
            # the daemon — fallback to naive whitespace split and flag the action.
            # RISK: the fallback may misclassify tokens. Acceptable for now.
            tokens = segment.split()

        if not tokens:
            return None

        # ── Output Redirection Detection ──
        redirect_target: Optional[Path] = None
        redirect_append = False
        
        # Scan tokens for > or >>
        for i, token in enumerate(tokens):
            if token in (">", ">>") and i + 1 < len(tokens):
                redirect_append = (token == ">>")
                target_str = tokens[i + 1]
                resolved = self._resolve_path(target_str)
                if resolved:
                    redirect_target = resolved
                # Remove > and the target file from tokens
                tokens = tokens[:i] + tokens[i + 2:]
                break
            elif token.startswith(">") and len(token) > 1:
                # e.g., >test.py
                redirect_append = token.startswith(">>")
                target_str = token[2:] if redirect_append else token[1:]
                resolved = self._resolve_path(target_str)
                if resolved:
                    redirect_target = resolved
                tokens = tokens[:i] + tokens[i + 1:]
                break

        if not tokens:
            return None

        binary = tokens[0]
        flags: list[str] = []
        args: list[str] = []
        target_paths: list[Path] = []
        sub_commands: list[ParsedAction] = []
        
        if redirect_target:
            target_paths.append(redirect_target)

        # WHY scan the raw segment for substitutions (not individual tokens):
        # shlex.split() splits "$(find /tmp -name foo)" into ['$(find', '/tmp',
        # '-name', 'foo)'] — the $() span is destroyed. To correctly detect
        # command substitution, we must scan the raw segment string BEFORE shlex
        # processes it, then parse the inner command. The token-level scan below
        # is kept as a fallback for single-word substitutions like "$(whoami)".

        # Scan raw segment for $(...) substitutions
        # Build a version of the segment with whitespace for the regex
        _seen_subst_inner: set[str] = set()

        for match in _CMD_SUBST_DOLLAR.finditer(segment):
            inner = match.group(1).strip()
            if inner and inner not in _seen_subst_inner:
                _seen_subst_inner.add(inner)
                sub_actions = self.parse(inner)
                sub_commands.extend(sub_actions)

        for match in _CMD_SUBST_BACKTICK.finditer(segment):
            inner = match.group(1).strip()
            if inner and inner not in _seen_subst_inner:
                _seen_subst_inner.add(inner)
                sub_actions = self.parse(inner)
                sub_commands.extend(sub_actions)

        for token in tokens[1:]:
            if token.startswith("-"):
                flags.append(token)
            else:
                # Skip tokens that are part of a $() substitution construct
                # (e.g. "$(find", "/tmp", "foo)") — they are not real file args.
                # WHY: if we already detected a substitution in the raw segment,
                # these fragment tokens should not be resolved as target_paths.
                is_subst_fragment = (
                    bool(_seen_subst_inner)
                    and (token.startswith("$(") or token.endswith(")"))
                )
                if not is_subst_fragment:
                    args.append(token)
                    resolved = self._resolve_path(token)
                    if resolved is not None:
                        target_paths.append(resolved)

        return ParsedAction(
            binary=binary,
            args=args,
            flags=flags,
            target_paths=target_paths,
            raw_input=segment,
            sub_commands=sub_commands,
            redirect_target=redirect_target,
            redirect_append=redirect_append,
        )

    def _resolve_path(self, token: str) -> Optional[Path]:
        """Attempt to resolve a token as a filesystem path.

        WHY resolve (not just Path()): policy rules use absolute paths internally.
        Relative paths like ../../.env must be resolved against work_dir so that
        a rule matching /home/user/.env correctly fires even if the agent wrote
        `cat ../../.env` from inside a nested directory.

        WHY catch all exceptions: tokens can be arbitrary strings (URLs, regex,
        random args). We try to make a Path, and if it fails we return None.
        The caller simply won't add a target_path for that token.

        RISK: tokens that look like paths but are actually command arguments
        (e.g. a `grep` pattern like "foo/bar") will be resolved as paths.
        This produces false target_paths but the inspector/rule engine
        evaluate them against policy — a stray non-existent path matching
        no policy rule is harmless (it gets the default_action treatment).
        """
        try:
            # URLs and other non-path strings typically contain :// — skip them
            if "://" in token:
                return None
            p = Path(token)
            if p.is_absolute():
                return p.resolve()
            else:
                return (self.work_dir / p).resolve()
        except Exception:
            return None
