# HV YARA Signature Base

Custom YARA signatures for Etica-managed scanners. Detection logic only: no samples, no
customer data, no PHI.

## How it is consumed

Deployable rules are the `.yar` files **in the repository root**. Consumers clone the repo and
pin an explicit branch, tag or commit. The default deployment branch is `main`.

The `hv-yara` Salt formula clones this repo to `/opt/custom-yara-signature-base` and loads
`*.yar` from the root only, so nothing in a subdirectory is ever loaded as a rule. Other
scanners may use a different local path, but must consume the same root-level files.

## Adding a rule

Full checklist in `CONTRIBUTING.md`. The requirements:

| | |
|---|---|
| Filename | lowercase, starts with `custom_`, ends in `.yar` or `.yara` |
| Scope | one threat family or exploit type per file |
| Rule name | ends in `_CUST`; keep an existing name if changing it would break finding or suppression compatibility |
| Metadata | `description`, `author`, `severity`, `date`, plus a sample hash where available |
| Condition | a sensible `filesize` limit and a file-type marker |
| False positives | handled in scanner suppressions, never by customer-specific exceptions inside a rule |

## Testing

Install YARA-X CLI 1.9.0, then run the three checks:

```bash
bash scripts/validate-rules.sh        # rules compile, and none are nested
bash tests/run-rule-tests.sh          # rules detect what they should
python3 scripts/check-identifiers.py  # no internal identifiers reach this public repo
```

All three run in CI on every pull request. Details in `tests/README.md`.

## License

No open-source license has been applied. Contact the repository maintainers before
redistributing or reusing this rule set outside its intended scanners.
