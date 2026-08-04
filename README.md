# HV YARA Signature Base

Shared custom YARA signatures for Etica-managed scanners.

## Consumer contract

- Deployable `.yar` and `.yara` files live directly in the repository root.
- Consumers should clone `https://github.com/EticaInc/hv-yara-signature-base.git` and select an explicit branch, tag, or commit.
- The default deployment branch is `main`.
- Rule files must not contain PHI, credentials, customer identifiers, internal ticket references, or malware samples.

The `hv-yara` Salt formula deploys this checkout to
`/opt/custom-yara-signature-base`. Other scanners may use a different local
target, but must consume the root-level rule files.

## Rule requirements

- Use lowercase filenames beginning with `custom_` and ending in `.yar` or `.yara`.
- Prefer one threat family or exploit type per file.
- Prefer rule names ending in `_CUST`; retain an existing name when changing it would break finding or suppression compatibility.
- Include `description`, `author`, `severity`, and `date` metadata, plus a sample hash when available.
- Include a reasonable `filesize` limit and a relevant file-type marker.
- Handle false positives in scanner suppressions, never by embedding customer-specific exceptions in a rule.

## Validation

Install YARA-X CLI 1.9.0 and run:

```bash
bash scripts/validate-rules.sh
```

The validation compiles all root-level rules together and rejects nested rule
files that the `hv-yara` scanner would not inventory.

## License

No open-source license has been applied. Contact the repository maintainers
before redistributing or reusing this rule set outside its intended scanners.
