#!/usr/bin/env python3
"""Lint custom YARA rules for the defects that have actually reached review here.

`validate-rules.sh` proves the ruleset compiles. Compiling says nothing about
whether a rule can fire, whether one cosmetic edit turns it off, or whether it
matches things it should not. Every check below exists because that exact defect
was found in review on a real pull request; the header comment on each names it.

Severities
    ERROR  blocks: mechanical, no judgement involved.
    WARN   needs a human answer, not silence. Suppress one with a
           `// lint: allow <ID> - <reason>` comment inside the rule, which keeps
           the justification next to the code instead of in a PR thread.

This lints the diff, not the world. A rule you add or touch has to come back
clean; the pre-existing backlog is reported by `--all` and never blocks, so the
check could be switched on without a flag day.

Usage
    python3 scripts/lint-rules.py --changed-since origin/main   # what CI runs
    python3 scripts/lint-rules.py --all                         # advisory backlog
    python3 scripts/lint-rules.py FILE ...                      # specific files

    --strict makes WARN findings exit non-zero. CI uses it for changed files, so
    a warning has to be answered -- either by fixing it, or by writing
    `// lint: allow W1 - <reason>` in the rule and owning the reason in review.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Text-format markers: a file of this type still parses with bytes in front of
# the marker, so pinning one to offset 0 is a false negative rather than a guard.
# Binary magics are deliberately absent -- `MZ`/`PK`/`%PDF` genuinely do live at
# offset 0 and anchoring those is correct.
TEXT_FORMAT_MARKERS = (
    "<?php", "<?=", "<%", "<!doctype", "<html", "#!/", "<?xml",
)

# Call literals worth flagging: a call whose argument is a magic constant or a
# superglobal. These are the ones that have actually broken here, and they are
# the ones an operator reformats without thinking. A bare `function foo()`
# literal is brittle in theory too, but flagging every one of those buried the
# signal under 120 warnings, so the check is deliberately narrow.
BRITTLE_ARGS = ("__FILE__", "__DIR__", "$_GET", "$_POST", "$_REQUEST",
                "$_SERVER", "$_COOKIE", "$GLOBALS")
CALL_LITERAL_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]{2,}\s*\(\s*(?:" +
    "|".join(re.escape(a) for a in BRITTLE_ARGS) + r")"
)


class Finding:
    def __init__(self, severity, ident, path, rule, message, hint=""):
        self.severity = severity
        self.ident = ident
        self.path = path
        self.rule = rule
        self.message = message
        self.hint = hint

    def render(self) -> str:
        loc = f"{os.path.relpath(self.path, REPO_ROOT)}::{self.rule}"
        out = f"{self.severity:5s} {self.ident}  {loc}\n       {self.message}"
        if self.hint:
            out += f"\n       hint: {self.hint}"
        return out


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, preserving offsets and newlines."""
    out = list(text)
    i, n = 0, len(text)
    in_str = None
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"',):
            in_str = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for j in range(i, min(i + 2, n)):
                out[j] = " "
            i += 2
            continue
        i += 1
    return "".join(out)


def split_rules(text: str):
    """Yield (rule_name, raw_body, body_without_comments) from raw source.

    The raw body is brace-bounded so a `lint: allow` in one rule cannot
    suppress a finding in the next.
    """
    for m in re.finditer(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.M):
        name = m.group(1)
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        depth, i, n = 0, brace, len(text)
        while i < n:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[brace : i + 1]
        yield name, body, strip_comments(body)



def section(body_nc: str, keyword: str) -> str:
    m = re.search(rf"(?:^|[{{\s]){keyword}\s*:", body_nc, re.M)
    if not m:
        return ""
    rest = body_nc[m.end():]
    nxt = re.search(r"(?:^|[{\s])(strings|condition|meta)\s*:", rest, re.M)
    return rest[: nxt.start()] if nxt else rest.rstrip("}\n \t")


def parse_strings(strings_src: str):
    """Return {name: (kind, value)} where kind is 'text' | 'regex' | 'hex'."""
    out = {}
    for m in re.finditer(
        r"^\s*\$([A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", strings_src, re.M
    ):
        name, raw = m.group(1), m.group(2).strip()
        if raw.startswith('"'):
            end = 1
            while end < len(raw):
                if raw[end] == "\\":
                    end += 2
                    continue
                if raw[end] == '"':
                    break
                end += 1
            out[name] = ("text", raw[1:end])
        elif raw.startswith("/"):
            end = raw.rfind("/")
            out[name] = ("regex", raw[1:end] if end > 0 else raw)
        elif raw.startswith("{"):
            out[name] = ("hex", raw)
    return out


def allowed(body_with_comments: str, ident: str) -> bool:
    """True if the rule carries `// lint: allow <ID> - <reason>`.

    YARA comments are // and /* */, so that is the marker; a leading # is
    accepted too in case someone writes it out of habit.
    """
    return re.search(
        rf"(?://|/\*|#)\s*lint:\s*allow\s+{re.escape(ident)}\b",
        body_with_comments,
    ) is not None


def lint_rule(path, name, body, body_nc, findings):
    cond = section(body_nc, "condition")
    strings = parse_strings(section(body_nc, "strings"))

    def add(sev, ident, msg, hint=""):
        if allowed(body, ident):
            return
        findings.append(Finding(sev, ident, path, name, msg, hint))

    # --- E1: YARA-X 1.9.0 has no uint64. Caught here with a usable message
    # rather than as `error[E009]: unknown identifier` at compile time.
    if re.search(r"\buint64(be)?\s*\(", cond):
        add("ERROR", "E1", "uint64/uint64be does not exist in YARA-X 1.9.0.",
            "Use two uint32 reads, e.g. (uint32(0) != 0 or uint32(4) != 0).")

    # --- E2: every rule needs a size bound, or it scans SQL dumps and backups.
    if "filesize" not in cond:
        add("ERROR", "E2", "No filesize bound in the condition.",
            "Add an upper bound, e.g. filesize < 3MB.")

    # --- W5: no file-type anchor referenced. A warning, not an error: a rule
    # for a format with no magic (JavaScript, plain text) legitimately has none,
    # and several such rules predate this check.
    has_anchor = bool(re.search(r"\buint(8|16|32)(be)?\s*\(", cond))
    if not has_anchor:
        for sname, (kind, val) in strings.items():
            if kind in ("text", "regex") and re.search(
                "|".join(re.escape(m) for m in TEXT_FORMAT_MARKERS),
                val, re.I,
            ):
                if re.search(rf"[\$#@!]{re.escape(sname)}\b", cond):
                    has_anchor = True
                    break
    if not has_anchor:
        add("WARN", "W5", "No file-type anchor referenced in the condition.",
            "Reference a magic/opening-tag string or a uintN() check. If the "
            "target format has no magic (JS, plain text), allow this with a "
            "reason.")

    # --- W1: `$x at 0` on a text-format marker.
    # Found in review on three separate PRs. PHP enters code mode wherever the
    # tag appears, so a leading newline, a UTF-8 BOM (which editors add by
    # accident) or leading HTML all still execute while the rule goes quiet.
    for m in re.finditer(r"\$([A-Za-z0-9_]+)\s+at\s+0\b", cond):
        sname = m.group(1)
        kind, val = strings.get(sname, ("", ""))
        if kind and any(mk in val.lower() for mk in TEXT_FORMAT_MARKERS):
            add("WARN", "W1",
                f"${sname} is pinned to offset 0, but {val!r} is a text-format "
                f"marker that need not start the file.",
                f"Drop the offset: use ${sname} alone and let the rule's string "
                f"combinations carry the anchor.")

    # --- W2: bare-literal function-call patterns.
    # `\"file_put_contents(__FILE__\"` was defeated by a single space. Any code
    # pattern written as plain text has this problem.
    for sname, (kind, val) in strings.items():
        if kind != "text":
            continue
        if not re.search(rf"[\$#@!]{re.escape(sname)}\b", cond):
            continue
        if CALL_LITERAL_RE.search(val):
            add("WARN", "W2",
                f"${sname} matches a call-like pattern as a bare literal: {val!r}.",
                "One space after the parenthesis defeats it. Prefer a regex with "
                r"\s* between the tokens.")

    # --- W3: occurrence counting used as a specificity gate.
    # `#tpl_section > 5` over a generic comment shape was satisfied by six
    # ordinary comments, or by one comment repeated six times. Counting a
    # generic shape is not the same as requiring distinct markers.
    for m in re.finditer(r"#([A-Za-z0-9_]+)\s*(>=|>)\s*(\d+)", cond):
        sname, thresh = m.group(1), int(m.group(3))
        kind, val = strings.get(sname, ("", ""))
        if not kind or thresh < 2:
            continue
        # A pattern with a long literal run is specific enough to count.
        longest = max((len(t) for t in re.findall(r"[A-Za-z0-9_ ]{2,}", val)),
                      default=0)
        if longest < 6:
            add("WARN", "W3",
                f"#{sname} > {thresh} counts occurrences of a low-specificity "
                f"pattern ({val!r}).",
                "Repetition of one match satisfies a count. If the intent is "
                "'several distinct campaign markers', enumerate them as separate "
                "strings and use N of ($prefix_*).")

    # --- W4: an HTML rule gated on the doctype alone.
    # `$doctype and (...)` made the whole rule, conclusive branch included, miss
    # a page served without a doctype -- which renders fine and is a one-line
    # edit for the operator.
    doctype_names = [
        s for s, (k, v) in strings.items()
        if k == "text" and v.lower().startswith("<!doctype")
    ]
    html_names = [
        s for s, (k, v) in strings.items()
        if k == "text" and v.lower().startswith("<html")
    ]
    for sname in doctype_names:
        gate = re.search(rf"\$({re.escape(sname)})\s+and\b", cond)
        if gate and not html_names:
            add("WARN", "W4",
                f"${sname} gates the whole rule, but HTML renders without a "
                f"doctype.",
                f"Accept either marker: 1 of (${sname}, $html_open) with "
                f'$html_open = "<html" ascii nocase.')


def all_rule_files():
    return sorted(
        glob.glob(os.path.join(REPO_ROOT, "*.yar"))
        + glob.glob(os.path.join(REPO_ROOT, "*.yara"))
    )


def changed_rule_files(base_ref: str):
    """Root-level rule files added or modified relative to base_ref."""
    import subprocess
    try:
        merge_base = subprocess.run(
            ["git", "merge-base", "HEAD", base_ref],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        out = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=AM", merge_base, "--",
             "*.yar", "*.yara"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"lint-rules: cannot diff against {base_ref} ({exc}); "
              f"falling back to linting all rules", file=sys.stderr)
        return all_rule_files()
    # Root-level only; nested rules are rejected by validate-rules.sh anyway.
    return [os.path.join(REPO_ROOT, p) for p in out
            if "/" not in p and os.path.exists(os.path.join(REPO_ROOT, p))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero on WARN findings too")
    ap.add_argument("--changed-since", metavar="REF",
                    help="lint only rule files added/modified vs REF")
    ap.add_argument("--all", action="store_true",
                    help="lint every rule file, advisory only (always exits 0)")
    args = ap.parse_args()

    if args.files:
        paths = args.files
    elif args.changed_since:
        paths = changed_rule_files(args.changed_since)
        if not paths:
            print("lint-rules: no root-level rule files changed; nothing to lint")
            return 0
    else:
        paths = all_rule_files()

    if not paths:
        print("No YARA rule files found", file=sys.stderr)
        return 1

    findings, rules_seen = [], 0
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for name, raw_body, body_nc in split_rules(text):
            rules_seen += 1
            lint_rule(path, name, raw_body, body_nc, findings)

    errors = [f for f in findings if f.severity == "ERROR"]
    warns = [f for f in findings if f.severity == "WARN"]

    for f in errors + warns:
        print(f.render())
        print()

    scope = "all rules (advisory)" if args.all else f"{len(paths)} file(s)"
    print(f"lint-rules: {rules_seen} rules in {scope}, "
          f"{len(errors)} error(s), {len(warns)} warning(s)")

    if args.all:
        # Backlog report: never blocks, so the check can be adopted without a
        # flag day and the existing findings can be worked off deliberately.
        return 0
    if errors:
        return 1
    if warns and args.strict:
        print("\nEach warning needs an answer: fix it, or add "
              "`// lint: allow <ID> - <reason>` inside the rule.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
