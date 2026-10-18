#!/usr/bin/env python3
"""Regression tests for lint-rules.py.

Each case is a defect that reached review on a real pull request, in the form it
had when it was found and in the form it was fixed to. A linter nobody tests is
the same mistake as a rule nobody fires at a sample, so these run in CI.

Fixtures are written to a temp directory rather than committed: any *.yar file
below the repo root is rejected by validate-rules.sh as non-deployable.

Usage: python3 scripts/test-lint-rules.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LINTER = os.path.join(HERE, "lint-rules.py")

# (name, rule source, ids that must fire, ids that must not fire)
CASES = [
    (
        "php-at-0 is flagged (PRs #12, #13, #14: one leading newline or a BOM "
        "disabled the whole rule)",
        '''
rule T { strings:
        $php = "<?php" ascii
        $a = "Core_Engine_9f9f" ascii
    condition: filesize < 3MB and $php at 0 and $a }
''',
        {"W1"}, {"E1", "E2", "W5"},
    ),
    (
        "php without the offset is clean (the accepted fix)",
        '''
rule T { strings:
        $php = "<?php" ascii
        $a = "Core_Engine_9f9f" ascii
    condition: filesize < 3MB and $php and $a }
''',
        set(), {"W1", "E2", "W5"},
    ),
    (
        "binary magic at 0 is NOT flagged (MZ really does start the file)",
        '''
rule T { strings:
        $mz = "MZ" ascii
        $a = "evilmarker" ascii
    condition: filesize < 3MB and $mz at 0 and $a }
''',
        set(), {"W1"},
    ),
    (
        "uint64 is rejected (YARA-X 1.9.0 has no uint64; PR #14)",
        '''
rule T { strings:
        $php = "<?php" ascii
    condition: filesize < 2MB and $php and uint64(0) != 0 }
''',
        {"E1"}, {"E2"},
    ),
    (
        "missing filesize is rejected",
        '''
rule T { strings:
        $php = "<?php" ascii
        $a = "evilmarker" ascii
    condition: $php and $a }
''',
        {"E2"}, {"E1"},
    ),
    (
        "bare call literal on a magic constant is flagged (PR #13: "
        "file_put_contents( __FILE__ with one space silenced the branch)",
        '''
rule T { strings:
        $php = "<?php" ascii
        $w = "file_put_contents(__FILE__" ascii
    condition: filesize < 3MB and $php and $w }
''',
        {"W2"}, {"E2"},
    ),
    (
        "the whitespace-tolerant regex form is clean (the accepted fix)",
        '''
rule T { strings:
        $php = "<?php" ascii
        $w = /file_put_contents\\s*\\(\\s*__FILE__/ ascii
    condition: filesize < 3MB and $php and $w }
''',
        set(), {"W2"},
    ),
    (
        "counting a generic pattern is flagged (PR #13: six ordinary comments, "
        "or one comment six times, satisfied #tpl_section > 5)",
        '''
rule T { strings:
        $doctype = "<!DOCTYPE html" ascii nocase
        $html_open = "<html" ascii nocase
        $tpl = /<!-- [A-Z][A-Z0-9 ]{2,40} -->/ ascii
    condition: filesize < 2MB and 1 of ($doctype, $html_open) and #tpl > 5 }
''',
        {"W3"}, {"E2", "W4"},
    ),
    (
        "distinct enumerated markers are clean (the accepted fix)",
        '''
rule T { strings:
        $doctype = "<!DOCTYPE html" ascii nocase
        $html_open = "<html" ascii nocase
        $tpl_a = /<!--\\s*CEKIM GARANTIISI\\s*-->/ ascii
        $tpl_b = /<!--\\s*GUVENLIK REHBERI\\s*-->/ ascii
        $tpl_c = /<!--\\s*LISANS DOGRULAMA\\s*-->/ ascii
    condition: filesize < 2MB and 1 of ($doctype, $html_open) and 3 of ($tpl_*) }
''',
        set(), {"W3", "W4", "E2"},
    ),
    (
        "doctype-only gate is flagged (PR #13: a page served without a doctype "
        "was invisible, conclusive branch included)",
        '''
rule T { strings:
        $doctype = "<!DOCTYPE html" ascii nocase
        $a = "evilbrand" ascii
    condition: filesize < 2MB and $doctype and $a }
''',
        {"W4"}, {"E2"},
    ),
    (
        "no file-type anchor is flagged",
        '''
rule T { strings:
        $a = "evilmarker" ascii
        $b = "othermarker" ascii
    condition: filesize < 2MB and $a and $b }
''',
        {"W5"}, {"E2"},
    ),
    (
        "an explicit allow suppresses the finding",
        '''
rule T {
    // lint: allow W1 - this family only ever lands as a dropped file whose
    // first bytes we control, and the offset is load-bearing here.
    strings:
        $php = "<?php" ascii
        $a = "evilmarker" ascii
    condition: filesize < 3MB and $php at 0 and $a }
''',
        set(), {"W1"},
    ),
]


def run_case(src: str):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "case.yar")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        proc = subprocess.run(
            [sys.executable, LINTER, path],
            capture_output=True, text=True,
        )
        ids = set()
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] in ("ERROR", "WARN") and len(parts) > 1:
                ids.add(parts[1])
        return ids, proc


def main() -> int:
    failures = 0
    for name, src, must, must_not in CASES:
        ids, proc = run_case(src)
        missing = must - ids
        spurious = must_not & ids
        if missing or spurious:
            failures += 1
            print(f"FAIL  {name}")
            if missing:
                print(f"        expected but not reported: {sorted(missing)}")
            if spurious:
                print(f"        reported but should not be: {sorted(spurious)}")
            print(f"        linter said: {sorted(ids) or 'nothing'}")
            if proc.stderr.strip():
                print(f"        stderr: {proc.stderr.strip()}")
        else:
            print(f"ok    {name}")

    print()
    print(f"test-lint-rules: {len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
