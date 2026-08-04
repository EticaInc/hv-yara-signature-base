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
