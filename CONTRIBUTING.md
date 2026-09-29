# Contributing

Submit rule changes through a pull request. Keep each change focused on one
threat family or exploit type and include the evidence needed for reviewers to
understand the detection without including malware samples or customer data.

Before opening the pull request:

1. Run `bash scripts/validate-rules.sh` with YARA-X CLI 1.9.0.
2. Test the rule recursively against approved malicious and benign fixtures.
3. Confirm that every matched string is safe to expose in source control.
4. Document expected matches and false-positive testing in the pull request.

False-positive exceptions belong in each scanner's suppression configuration,
not in this repository.

## Rule conventions

`scripts/lint-rules.py` checks these mechanically on the rules a change touches.
Each exists because that exact defect reached review here. Run it locally with
`python3 scripts/lint-rules.py --changed-since origin/main --strict`, and see the
whole-repo backlog with `--all`.

- **Never anchor a text-format marker to offset 0.** `$php at 0` reads like a
  file-type guard but is a false negative: PHP enters code mode wherever the tag
  appears, so a leading newline, a UTF-8 BOM or leading HTML all still execute
  while the rule goes quiet. Use `$php` and let the rule's string combinations
  carry the anchor. Binary magics (`MZ`, `PK`) are different -- those really do
  start the file, and anchoring them is correct.
- **Nothing ANDed ahead of the branch list may be optional for the attacker.**
  A whole-rule gate takes every branch down with it, including the conclusive
  one. `$doctype and (...)` hid a doorway page served without a doctype; prefer
  `1 of ($doctype, $html_open)`.
- **Write code patterns as whitespace-tolerant regexes, not bare literals.**
  `"file_put_contents(__FILE__"` is defeated by one space. Use
  `/file_put_contents\s*\(\s*__FILE__/`. Where a call's arguments can be
  reordered without changing behaviour (`hash_equals()`), match both orders.
- **Counting a generic pattern is not specificity.** `#tpl_section > 5` over
  "any uppercase comment" was satisfied by six ordinary comments, or by one
  comment six times. When the intent is "several distinct campaign markers",
  enumerate them and use `N of ($prefix_*)`, which repetition cannot satisfy.
- **Every rule needs a `filesize` bound**, or it reads SQL dumps and backups.
- **Do not add a guard for a false positive you have not observed.** Three
  successive guards on one branch were each a detection gap, defending a benign
  file shape that occurred zero times in 109,709 real files. Count how many real
  files carry the shape before writing the guard, and prefer anchors pinned by
  the malware's own logic or by the language spec. If a real false positive does
  appear, it belongs in the scanner's suppression config, not in the rule.
