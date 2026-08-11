# Rule tests

Three checks run on every pull request. All three also run locally, with no host access, no
privileged access and no malware samples.

| Command | Asserts |
| --- | --- |
| `scripts/validate-rules.sh` | every rule compiles, and no rule file is nested |
| `tests/run-rule-tests.sh` | each rule detects what it should, and ignores what it should not |
| `scripts/check-identifiers.py` | no internal identifier reaches this public repository |

## Running them

```bash
tests/run-rule-tests.sh                 # finds yr on PATH or at /opt/wp-yara-scanner/bin/yr
YR=/path/to/yr tests/run-rule-tests.sh  # or point it at a specific engine
scripts/check-identifiers.py
```

Engine is YARA-X CLI 1.9.0, the same version the deployed scanner runs.

## Reading a failure

The harness runs in stages and stops at the first broken one:

```
engine found  →  every rule compiles  →  canary matches  →  fixtures
```

Fix compile errors first. A compile error invalidates every result after it.

**Why it gates before it reports.** A rule file that is empty, non-compiling or never loaded
makes every scan return nothing, which is indistinguishable from a clean result unless
something checks. That has already happened in this codebase. So the harness proves the engine
works and a canary matches before it reports on real fixtures, and it fails on an empty
fixture directory, because a suite with nothing in it passes trivially.

## Fixtures

```
tests/fixtures/positive/    must match at least one rule
tests/fixtures/negative/    must match nothing
```

Add fixtures in the same pull request as the rule. Three rules of thumb:

1. **One positive per condition branch.** A rule that matches on any of three independent
   branches needs three positives. Narrowing it later then fails a *named* test, instead of
   quietly shrinking coverage — a rule that still compiles and still matches one sample looks
   healthy while having lost most of its reach.

2. **Pin thresholds from both sides.** For a rule conditioned on `2 of ($marker_*)`, commit a
   two-marker positive and a one-marker negative. Loosening it to `1 of` then breaks a test
   instead of silently widening into false positives.

3. **Use real known-goods as negative controls.** `negative/stock_wp_index.php` is byte-exact
   stock WordPress (405 B, sha256
   `eea9347b1e266ca5407b92633958c148dbfebea307e511a3a226ea61828e2eba`). Because it is genuinely
   unmodified upstream code, `sha256sum` against it also works as a field check on a suspect
   bootstrap file.

### Writing one

Fixtures are synthetic and must stay that way: the identity strings and structural shape a
rule keys on, and nothing else. No working payload, no network calls, no persistence or
replication logic. Keep them small — the committed ones are well under 1 KB.

- Prefer rules whose triggers are inert markers. Those need no functional code at all.
- Where a rule keys on functional code, reproduce only the fragment the condition requires.
- **Never spell a rule's trigger strings out in a fixture's own comments.** YARA matches bytes
  and does not care that they sit in a docblock. A negative control that explains which string
  it avoids will match on that explanation and invert the test.
- To clear a `filesize` floor, add a generator to `tests/fixtures/generators/` rather than
  committing a bulky, malware-shaped file. It runs at test time and is asserted exactly like a
  committed positive.

### Real samples

Never committed. This repository holds detection logic only, per `SECURITY.md`. Samples are
client-derived, carry a retention obligation, and stay in the evidence store; rule `meta`
records their hashes. To validate against them, run where they already are:

```bash
tests/run-rule-tests.sh --samples /path/to/evidence
```

That mode reports match counts only, and skips automatically when the path is absent, so the
same command is safe to run off-host.

## The identifier check

`scripts/check-identifiers.py` fails the build on client and site names, host names, ticket
numbers, evidence paths, and cloud zone or image names. It combines structural patterns, which
name nothing, with a SHA-256 denylist, so the list is not itself the leak it prevents. The
script header covers the reasoning and its known limitation.

Add a term:

```bash
scripts/check-identifiers.py --hash 'the-term'   # append to scripts/identifier-denylist.sha256
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
