#!/usr/bin/env python3
"""Fail the build when a rule or fixture carries an internal identifier.

This repository is public. Rules must describe attacker behaviour, not the environment a
sample was found in. Attacker infrastructure -- C2 domains, fake vendor URLs, cover personas,
malware hashes -- is the detection logic and belongs here. Victim-side and operational
identity does not: client names, site names, host names, ticket numbers, internal paths.

Two independent checks run over rule files, fixtures and top-level documentation.

1. STRUCTURAL patterns, below in plain text. These describe the *shape* of internal
   references (a ticket number, an evidence path, a host-name suffix) and name nothing, so
   they are safe to publish.

2. A hashed TERM denylist in identifier-denylist.sha256. Structural patterns alone are not
   sufficient -- an identifier can appear with no accompanying marker at all, for example
   embedded in a meta key name -- so exact terms are matched too. Storing them as SHA-256
   keeps the list itself from becoming the leak it exists to prevent.

   Terms are normalised by lowercasing and removing every non-alphanumeric character before
   hashing, so one entry covers the hyphenated, underscored and bare spellings of a name.
   Candidates are generated the same way, plus concatenations of up to three adjacent tokens,
   so a name split by punctuation is still caught.

   Known limitation: a short hashed term is guessable by dictionary attack. The threat model
   here is accidental disclosure by a contributor, not a motivated party trying to enumerate
   the list. If that is not good enough for a given term, keep it out of the denylist and out
   of the repository both.

On a hit this reports the file, the line number and which check fired -- never the matching
text. CI logs for a public repository are public, so echoing the offending line would publish
exactly what the check is meant to stop.

Usage:
  scripts/check-identifiers.py            check tracked files
  scripts/check-identifiers.py --hash TERM  print the hash for a new denylist entry
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DENYLIST = Path(__file__).resolve().parent / "identifier-denylist.sha256"

# Files worth checking. Rules and fixtures are the payload; the top-level docs are included
# because a case write-up pasted into a README leaks just as effectively as one in a rule.
INCLUDE_SUFFIXES = {".yar", ".yara", ".php", ".md", ".txt", ".fixture"}
# CODEOWNERS needs real GitHub handles to function, and this script quotes pattern shapes by
# necessity. Both would otherwise flag themselves.
EXCLUDE_PATHS = {
    ".github/CODEOWNERS",
    "scripts/check-identifiers.py",
    "scripts/identifier-denylist.sha256",
}

# Shapes of internal references. These name no client and no person.
STRUCTURAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bzoho\b", "internal ticketing system reference"),
    (r"(?i)\bticket\s*#?\s*\d{4,}\b", "ticket number"),
    (r"(?i)\bcase\s*#\s*\d{4,}\b", "case number"),
    (r"/root/(?:quarantine|evidence)", "evidence-store path"),
    (r"/var/tmp/ticket", "on-host evidence path"),
    (r"(?i)\bsupport\.[a-z0-9-]+\.[a-z]{2,}/agent/", "internal helpdesk URL"),
    (r"(?i)-(?:welsh|stantz|wauzer|daug)\d*\b", "internal host-name suffix"),
    (r"(?i)\bus-(?:east|west|central|south)\d-[a-z]\b", "cloud zone identifier"),
    (r"/home/[a-z][a-z0-9._-]{2,}/", "user home path"),
    (r"(?i)\bpreserve-\d{4}-\d{2}-\d{2}-premutation\b", "disk-image name"),
]

TOKEN_RE = re.compile(r"[a-z0-9]+")
MIN_TERM_LEN = 4
MAX_JOIN = 3


def normalise(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def load_denylist() -> set[str]:
    if not DENYLIST.exists():
        return set()
    out = set()
    for line in DENYLIST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line.split()[0].lower())
    return out


def candidates(line: str) -> set[str]:
    """Normalised substrings a denylisted term could plausibly appear as."""
    tokens = TOKEN_RE.findall(line.lower())
    found = set()
    for i, tok in enumerate(tokens):
        for j in range(1, MAX_JOIN + 1):
            if i + j > len(tokens):
                break
            joined = "".join(tokens[i : i + j])
            if len(joined) >= MIN_TERM_LEN:
                found.add(joined)
    return found


def tracked_files() -> list[Path]:
    try:
        raw = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"],
            capture_output=True, text=True, check=True,
        ).stdout
        names = [n for n in raw.split("\0") if n]
    except (subprocess.CalledProcessError, FileNotFoundError):
        names = [
            str(p.relative_to(REPO))
            for p in REPO.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]
    out = []
    for name in names:
        if name in EXCLUDE_PATHS:
            continue
        path = REPO / name
        if path.suffix.lower() in INCLUDE_SUFFIXES:
            out.append(path)
    return sorted(out)


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--hash":
        term = normalise(sys.argv[2])
        if len(term) < MIN_TERM_LEN:
            print(f"refusing: normalises to {len(term)} chars, minimum is {MIN_TERM_LEN}",
                  file=sys.stderr)
            return 2
        print(f"{hashlib.sha256(term.encode()).hexdigest()}  # {len(term)} chars")
        return 0

    denied = load_denylist()
    compiled = [(re.compile(p), why) for p, why in STRUCTURAL_PATTERNS]
    findings: list[tuple[str, int, str]] = []

    files = tracked_files()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(REPO)
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern, why in compiled:
                if pattern.search(line):
                    findings.append((str(rel), lineno, why))
            if denied:
                for cand in candidates(line):
                    if hashlib.sha256(cand.encode()).hexdigest() in denied:
                        findings.append((str(rel), lineno, "denylisted term"))
                        break

    print(f"Checked {len(files)} files against "
          f"{len(compiled)} structural patterns and {len(denied)} hashed terms.")

    if not findings:
        print("No internal identifiers found.")
        return 0

    print(f"\n{len(findings)} finding(s) -- matching text intentionally not shown:\n",
          file=sys.stderr)
    for rel, lineno, why in findings:
        print(f"  {rel}:{lineno}  {why}", file=sys.stderr)
    print("\nRemove the identifier, or -- if it is genuinely attacker infrastructure and not\n"
          "environment detail -- narrow the pattern in scripts/check-identifiers.py.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
