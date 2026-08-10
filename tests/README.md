# Rule tests

Two checks run on every pull request, alongside `scripts/validate-rules.sh`:

| Command | Asserts |
| --- | --- |
| `tests/run-rule-tests.sh` | every rule compiles, and each rule detects what it should without matching what it should not |
| `scripts/check-identifiers.py` | no internal identifier reaches this public repository |

## Running them

```bash
tests/run-rule-tests.sh          # finds yr on PATH or at /opt/wp-yara-scanner/bin/yr
YR=/path/to/yr tests/run-rule-tests.sh
scripts/check-identifiers.py
```

Engine is YARA-X CLI 1.9.0, matching `scripts/validate-rules.sh` and the deployed scanner.
No privileged access, no host, and no samples are needed.

## Why the harness gates before it reports

An empty, non-compiling, or unloaded rule file makes every scan return nothing — which is
indistinguishable from a clean result unless something explicitly checks. A rule file has
already been found corrupt and silently non-matching in this codebase's history, so the
harness refuses to report on fixtures until it has confirmed the engine exists, every rule
compiles, and a canary matches. It also fails when a fixture directory is empty, because a
suite with nothing in it passes trivially.

Read a failure in that order: a compile error invalidates every result after it.

## Fixtures

```
tests/fixtures/positive/    MUST match at least one rule
tests/fixtures/negative/    MUST NOT match any rule
```

**One fixture per `condition` branch.** A rule that matches on any of three independent
branches needs three positive fixtures. Narrowing that rule then fails a *named* test rather
than quietly reducing coverage — which is the failure mode that matters, because a rule that
still compiles and still matches one sample looks healthy while having lost most of its reach.

**Pin thresholds from both sides.** For a rule conditioned on `2 of ($marker_*)`, commit a
positive fixture with two markers and a negative fixture with one. The pair pins the
threshold, so loosening it to `1 of` breaks a test instead of silently widening into false
positives.

**Include real known-goods as negative controls.** `negative/stock_wp_index.php` is
byte-exact stock WordPress (405 B, sha256 `eea9347b1e266ca5407b92633958c148dbfebea307e511a3a226ea61828e2eba`).
Because it is genuinely unmodified upstream code rather than an approximation, `sha256sum`
against it also works as a field check on a suspect bootstrap file.

### Fixtures are synthetic, and must stay that way

A fixture carries the identity strings and structural shape a rule keys on — and nothing
else. No working payload, no network calls, no persistence or replication logic. Keep them
small; the committed ones are well under 1 KB.

Prefer rules whose trigger strings are inert markers when writing a fixture, since those need
no functional code at all. Where a rule keys on functional code, reproduce only the minimum
fragment the condition requires.

**Do not spell a rule's identity strings out in a fixture's own comments.** YARA matches
bytes and does not care that they sit in a docblock: a negative control that explains which
string it is avoiding will match on that explanation and inverts the test.

Generate any fixture that must exceed a filesize floor at runtime inside the harness instead
of committing it, so the repository holds no bulky malware-shaped artifact.

### Real samples

Never committed here. This repository holds detection logic only, per `SECURITY.md`. Samples
are client-derived, carry a retention obligation, and stay in the evidence store; rule `meta`
records their hashes. To validate against them, run on the host where they already are:

```bash
tests/run-rule-tests.sh --samples /path/to/evidence
```

That mode reports match counts only. It is skipped automatically when the path is absent, so
the same command is safe to run off-host.

## The identifier check

`scripts/check-identifiers.py` fails the build on internal identifiers: client and site
names, host names, ticket numbers, evidence paths, cloud zone and image names. It combines
plain-text structural patterns, which name nothing, with a hashed term denylist — see the
header of that script for the reasoning and its known limitation.

Add a term:

```bash
scripts/check-identifiers.py --hash 'the-term'   # append the hash to scripts/identifier-denylist.sha256
```

Normalisation strips punctuation, so one entry covers the hyphenated, underscored and bare
spellings.

**Attacker infrastructure is not an identifier and must stay.** C2 domains, fake vendor URLs,
cover personas and malware hashes are the detection logic. What gets removed is the
environment a sample was found in, not the sample's own indicators. If the check fires on
something genuinely attacker-side, narrow the pattern rather than dropping the string.

On a hit it prints the file, line number and which check fired — never the matching text. CI
logs for a public repository are public, so echoing the line would publish the very thing the
check exists to stop. Open the file locally to see what tripped it.
