#!/usr/bin/env bash
set -euo pipefail

candidate="/opt/sbom-sentry/sbom-sentry"
input_zip="/opt/sbom-sentry/testdata/release-happy-path.zip"
expected_paths="/opt/sbom-sentry/testdata/expected-delivery-paths.txt"
out_dir="$(mktemp -d /tmp/sbom-sentry-release-test.XXXXXX)"

cleanup() {
  rm -rf "$out_dir"
}
trap cleanup EXIT

set +e
"$candidate" --unsafe --output-dir "$out_dir" --root-name "release-fixture" "$input_zip"
exit_code=$?
set -e

if [[ "$exit_code" -ne 0 && "$exit_code" -ne 1 ]]; then
  echo "unexpected sbom-sentry exit code: $exit_code"
  exit 1
fi

sbom_path="$out_dir/release-happy-path.cdx.json"
report_path="$out_dir/release-happy-path.report.md"

[[ -f "$sbom_path" ]] || { echo "missing SBOM output"; exit 1; }
[[ -f "$report_path" ]] || { echo "missing report output"; exit 1; }

jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6"' "$sbom_path" >/dev/null
jq -e '.metadata.component.name == "release-fixture"' "$sbom_path" >/dev/null

while IFS= read -r expected; do
  [[ -z "$expected" ]] && continue
  jq -e --arg p "$expected" '[.components[]? | .properties[]? | select(.name == "sbom-sentry:delivery-path") | .value] | index($p) != null' "$sbom_path" >/dev/null
  echo "validated delivery-path: $expected"
done < "$expected_paths"

jq -e '[
  .components[]? as $c
  | ($c.properties // []) as $props
  | {
      path: ($props[]? | select(.name == "sbom-sentry:delivery-path") | .value),
      status: ($props[]? | select(.name == "sbom-sentry:extraction-status") | .value)
    }
] as $rows
| any($rows[]; (.path | endswith(".7z")) and .status == "extracted")
  and any($rows[]; (.path | endswith(".cab")) and .status == "extracted")
  and any($rows[]; (.path | endswith(".tgz")) and .status == "extracted")
  and any($rows[]; (.path | endswith(".jar")) and .status == "syft-native")' "$sbom_path" >/dev/null

echo "release candidate passed containerized release test"
