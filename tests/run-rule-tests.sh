#!/usr/bin/env bash
#
# Rule test harness.
#
# Fails loudly rather than passing silently. An empty, non-compiling, or unloaded rule file
# makes every scan return nothing, which is indistinguishable from "clean" unless something
# checks for it. This script therefore gates on engine present, every rule file compiles, and
# a canary matches, before it reports anything about the real fixtures. It also refuses to
# report success when a fixture directory is empty, because a suite with nothing in it passes
# trivially.
#
# Usage:
#   tests/run-rule-tests.sh                       synthetic fixtures only
#   tests/run-rule-tests.sh --samples /path       also scan real samples (on-host, root)
#   YR=/path/to/yr tests/run-rule-tests.sh        override the engine path
#
# Engine: YARA-X CLI 1.9.0, matching scripts/validate-rules.sh and the deployed scanner.
#
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
POS="$HERE/fixtures/positive"
NEG="$HERE/fixtures/negative"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

YR="${YR:-}"
if [ -z "$YR" ]; then
  for c in /opt/wp-yara-scanner/bin/yr "$(command -v yr 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && YR="$c" && break
  done
fi
[ -n "$YR" ] || { echo "FATAL: no YARA-X engine found. Set YR=/path/to/yr"; exit 2; }

SAMPLES=""
[ "${1:-}" = "--samples" ] && SAMPLES="${2:-}"

pass=0; fail=0
ok(){  printf "  \033[32mPASS\033[0m %s\n" "$1"; pass=$((pass+1)); }
bad(){ printf "  \033[31mFAIL\033[0m %s\n" "$1"; fail=$((fail+1)); }

echo "engine: $YR ($("$YR" --version 2>/dev/null | head -1))"
echo "rules:  $REPO (root-level *.yar)"
echo

# ------------------------------------------------------------------ gate 1: compile
# Rules live at the repository root; scripts/validate-rules.sh rejects nested rule files as
# non-deployable, so this globs maxdepth 1 only. yr takes a rules FILE, not a directory --
# passing a directory loads nothing and every later scan returns "no match", which looks
# exactly like a clean result. Everything below therefore uses one combined rules file, built
# with the same invocation the tests use, so a harness fault cannot masquerade as a pass.
ALL="$TMP/all-rules.yar"
: > "$ALL"
echo "== gate: every root-level rule file compiles =="
shopt -s nullglob
rule_files=("$REPO"/*.yar "$REPO"/*.yara)
shopt -u nullglob
if [ "${#rule_files[@]}" -eq 0 ]; then
  bad "no root-level rule files found"
  echo; echo "aborting: nothing to test"; exit 1
fi
for f in "${rule_files[@]}"; do
  base="$(basename "$f")"
  [ -s "$f" ] || { bad "$base is EMPTY"; continue; }
  if "$YR" compile "$f" --output "$TMP/$base.bin" >"$TMP/err" 2>&1; then
    ok "$base compiles"; cat "$f" >> "$ALL"; printf '\n' >> "$ALL"
  else
    bad "$base does NOT compile"; sed 's/^/       /' "$TMP/err"
  fi
done
[ -s "$ALL" ] || bad "combined rules file is empty"
[ "$fail" -eq 0 ] || { echo; echo "aborting: fix compile errors before trusting any scan result"; exit 1; }

# ------------------------------------------------------------------ gate 2: canary
# Proves the engine, the combined rules file and the scan invocation actually work together.
# Deliberately rule-agnostic: it compiles its own throwaway rule, so it keeps working as the
# repository's real rules come and go.
echo
echo "== gate: canary must match (proves the harness can detect anything at all) =="
CANARY_RULE="$TMP/canary.yar"
cat > "$CANARY_RULE" <<'CANARY'
rule HARNESS_CANARY {
    strings:
        $marker = "harness-canary-string-do-not-remove" ascii
    condition:
        $marker
}
CANARY
printf 'harness-canary-string-do-not-remove' > "$TMP/canary.txt"
if [ "$("$YR" scan "$CANARY_RULE" "$TMP/canary.txt" 2>/dev/null | wc -l)" -ge 1 ]; then
  ok "canary matched"
else
  bad "canary did NOT match: harness is broken, results below are meaningless"
  exit 1
fi

# ------------------------------------------------------------------ positive fixtures
echo
echo "== positive fixtures: each MUST match at least one rule =="
shopt -s nullglob
pos_files=("$POS"/*)
shopt -u nullglob
if [ "${#pos_files[@]}" -eq 0 ]; then
  bad "no positive fixtures present: an empty suite passes trivially"
else
  for f in "${pos_files[@]}"; do
    [ -f "$f" ] || continue
    n=$("$YR" scan "$ALL" "$f" 2>/dev/null | wc -l)
    if [ "$n" -ge 1 ]; then ok "$(basename "$f")  (${n} rule/s)"
    else bad "$(basename "$f")  no match"; fi
  done
fi

# ------------------------------------------------------------------ negative fixtures
echo
echo "== negative fixtures: each MUST NOT match =="
shopt -s nullglob
neg_files=("$NEG"/*)
shopt -u nullglob
if [ "${#neg_files[@]}" -eq 0 ]; then
  bad "no negative fixtures present: false positives would go unnoticed"
else
  for f in "${neg_files[@]}"; do
    [ -f "$f" ] || continue
    hits=$("$YR" scan "$ALL" "$f" 2>/dev/null)
    if [ -z "$hits" ]; then ok "$(basename "$f")"
    else bad "$(basename "$f")  FALSE POSITIVE:"; echo "$hits" | sed 's/^/       /'; fi
  done
fi

# ------------------------------------------------------------------ real samples (optional)
# Samples are never committed. See tests/README.md.
if [ -n "$SAMPLES" ]; then
  echo
  echo "== real samples under $SAMPLES =="
  if [ -d "$SAMPLES" ]; then
    tot=$(find "$SAMPLES" -type f 2>/dev/null | wc -l)
    hit=$("$YR" scan --recursive "$ALL" "$SAMPLES" 2>/dev/null | wc -l)
    echo "     files=$tot  rule-hits=$hit"
    [ "$hit" -ge 1 ] && ok "real samples produced matches" || bad "real samples produced NO matches"
  else
    echo "     skipped: $SAMPLES not present on this machine (expected off-host)"
  fi
else
  echo
  echo "== real samples: not requested. See tests/README.md. =="
fi

echo
echo "-------- $pass passed, $fail failed --------"
[ "$fail" -eq 0 ] || exit 1
