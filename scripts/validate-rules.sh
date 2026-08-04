#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

mapfile -d '' root_rules < <(
  find "$repo_root" -maxdepth 1 -type f \
    \( -name '*.yar' -o -name '*.yara' \) -print0 \
    | sort -z
)

if (( ${#root_rules[@]} == 0 )); then
  echo "No root-level YARA rules found" >&2
  exit 1
fi

mapfile -d '' nested_rules < <(
  find "$repo_root" -mindepth 2 -type f \
    \( -name '*.yar' -o -name '*.yara' \) -print0 \
    | sort -z
)

if (( ${#nested_rules[@]} > 0 )); then
  printf 'Nested YARA rule is not deployable: %s\n' "${nested_rules[@]}" >&2
  exit 1
fi

compiled_rules=$(mktemp)
trap 'rm -f "$compiled_rules"' EXIT

yr compile "${root_rules[@]}" --output "$compiled_rules"
printf 'Validated %d root-level YARA rule files.\n' "${#root_rules[@]}"
