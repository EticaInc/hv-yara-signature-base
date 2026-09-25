# Contributing

One pull request, one threat family. Include enough evidence for a reviewer to understand the
detection, and never include malware samples or customer data.

Before opening a pull request:

1. **Add fixtures alongside the rule.** At least one positive per condition branch, plus a
   negative that pins any `n of` threshold. See `tests/README.md`.

2. **Run the three checks** with YARA-X CLI 1.9.0:

   ```bash
   bash scripts/validate-rules.sh
   bash tests/run-rule-tests.sh
   python3 scripts/check-identifiers.py
   ```

3. **Confirm every string is safe to publish.** This repository is public. Attacker
   infrastructure belongs here; the environment a sample was found in does not.

4. **Describe expected matches and false-positive testing** in the pull request body.

CI runs the same three checks on every pull request. False-positive exceptions belong in each
scanner's suppression configuration, not in this repository.
