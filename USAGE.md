# USAGE

This guide explains extract-sbom in scenario form: what to run, which parameters
matter, and which outputs to expect.

## Exit Codes

- `0`: success (all relevant subtrees fully processed)
- `1`: partial (some subtrees skipped/incomplete or scan failures)
- `2`: hard security incident or fatal runtime/configuration failure

## Output Naming

For input `delivery.zip` and output directory `out/`:

- SBOM: `out/delivery.cdx.json`
- Human report: `out/delivery.report.md` (`--report human`)
- Machine report: `out/delivery.report.json` (`--report machine`)
- Both: both report files (`--report both`)

## Scenario 1: Standard Incoming Check (Trusted CI Worker)

Goal:

- process one delivery file and get SBOM + human report quickly

Command:

```bash
mkdir -p out
./extract-sbom \
  --unsafe \
  --output-dir out \
  vendor-delivery.zip
```

Why these parameters:

- `--unsafe`: allows external extractors without sandbox (typical on macOS/dev machines)
- `--output-dir`: required writable destination

Expected outputs:

- `out/vendor-delivery.cdx.json`
- `out/vendor-delivery.report.md`

## Scenario 2: Strict Security Gate in Linux CI

Goal:

- fail hard when limits/security issues appear
- use sandboxed external extraction

Command:

```bash
mkdir -p out
./extract-sbom \
  --policy strict \
  --mode installer-semantic \
  --report both \
  --output-dir out \
  vendor-delivery.zip
```

Environment expectation:

- Linux host with `bwrap` available
- required external tools (`7zz`, `unshield`) installed based on format usage

Expected outputs:

- SBOM JSON
- report Markdown and JSON
- non-zero exit if hard security/fatal condition occurs

## Scenario 3: Continue Despite Partial Failures

Goal:

- keep scanning unaffected subtrees when one nested archive violates a limit

Command:

```bash
mkdir -p out
./extract-sbom \
  --unsafe \
  --policy partial \
  --max-depth 8 \
  --max-files 300000 \
  --output-dir out \
  vendor-delivery.zip
```

Behavior:

- violating subtree is skipped or marked incomplete
- run can still produce SBOM/report
- likely exit code `1` (partial)

## Scenario 4: Procurement Metadata on Root Component

Goal:

- annotate root SBOM component with supplier/product context

Command:

```bash
mkdir -p out
./extract-sbom \
  --unsafe \
  --output-dir out \
  --root-manufacturer "Acme Corp" \
  --root-name "Widget Suite" \
  --root-version "2026.04" \
  --root-delivery-date "2026-04-11" \
  --root-property contract=4711 \
  --root-property channel=partner \
  vendor-delivery.zip
```

Output effect:

- SBOM metadata component contains these values/properties
- report root metadata section documents them

## Scenario 5: Machine-Readable Report for Automation

Goal:

- feed run details into downstream checks/pipelines

Command:

```bash
mkdir -p out
./extract-sbom \
  --unsafe \
  --report machine \
  --output-dir out \
  vendor-delivery.zip
```

Result:

- `out/vendor-delivery.report.json` contains structured extraction/scanning/decision data

## Parameters by Concern

### Input/Output

**positional `<input-file>`**

The delivery file to analyze. Can be archive (ZIP, TAR, CAB, MSI, 7z, RAR,
InstallShield CAB) or container (OCI image, Docker archive).

**`--output-dir` (required)**

Writable directory where SBOM and report files are written. Created if
missing. Files are named after the input file:

```text
--output-dir out → out/delivery.cdx.json, out/delivery.report.md
```

**`--work-dir`**

Temporary directory for extraction and scratch storage. Defaults to system
temp (`/tmp` on Linux/macOS). Useful for:

- Performance: use fast local SSD instead of network mount
- Debugging: inspect unprocessed extractions (preserved if scan fails)
- Disk isolation: keep temporary files separate from output

**`--config`**

Path to a YAML configuration file. If not provided, extract-sbom will look
for `.extract-sbom.yaml` or `.extract-sbom.yml` in the current directory and
the user's home directory; an explicit `--config` overrides auto-discovery.

**`--format`**

SBOM output format. Currently the tool only supports `cyclonedx-json`.

**`--parallel`**

Number of concurrent Syft scan workers. Default follows `GOMAXPROCS` and
is capped at 16; increase for better throughput on many-core machines,
or decrease to reduce memory usage.

**`--skip-extensions`**

Comma-separated list of file extensions (with leading dot) to exclude from
recursive extraction and Syft-native scanning (for example:
`.docx,.xlsx,.pdf`). This overrides the built-in default list. Pass an empty
string to explicitly disable extension filtering.

### Policy and Interpretation

**`--policy strict|partial` (default: partial)**

Controls behavior when a nested archive violates safety limits (depth, file
count, compression ratio).

- `strict`: stops processing immediately, exits with code 2. Use in security
  gates where violations must fail the build.
- `partial`: marks violating subtree as incomplete, continues with other
  subtrees. Useful for analyzing large/complex deliveries despite one problem
  area. Exit code becomes 1 (partial).

Example: a 500-file nested archive might violate `--max-files`, but other
branches should still be scanned.

**`--mode physical|installer-semantic` (default: installer-semantic)**

Determines how installer packages (MSI, CAB) are interpreted.

- `physical`: extracts all contained files as-is (layer 0 = extracted, layer
  1 = nested content inside extracted files).
- `installer-semantic`: attempts to parse installer semantics and identify
  software components from metadata (more accurate for setup bundles, better
  traceability). This is the recommended default.

Override to `physical` only for raw archive analysis where installer metadata
is not relevant.

**`--report human|machine|both` (default: human)**

Output format for the audit report.

- `human`: Markdown file (`*.report.md`), readable for manual review.
- `machine`: JSON file (`*.report.json`), structured for tooling/CI
  integration.
- `both`: both formats written.

**`--progress quiet|normal|verbose` (default: normal)**

Controls runtime progress output on stderr.

- `quiet`: no progress output (only final paths/errors)
- `normal`: stage markers, periodic extraction counters, aggregated native-scan completion updates,
  and keep-alive output for genuinely long scan tasks
- `verbose`: everything from `normal`, plus detailed extracted-directory scan progress and slow or
  failing native-file scans; short native scans are intentionally coalesced to keep logs readable

Examples:

```bash
# CI log-friendly
extract-sbom --progress normal ...

# Deep troubleshooting of slow deliveries
extract-sbom --progress verbose ...

# Silent mode for wrappers that provide their own progress UI
extract-sbom --progress quiet ...
```

For the end-to-end processing model behind these progress messages, see
[SCAN_APPROACH.md](SCAN_APPROACH.md).

**`--language en|de` (default: en)**

Language for human-readable report. German (`de`) translates all narrative
text; SBOM and machine report remain English.

### Root Metadata

Annotates the root component in the SBOM with procurement/supplier context.
Used in supply chain traceability workflows.

**`--root-manufacturer`**

Supplier/vendor name. Appears in SBOM root component metadata.

**`--root-name`**

Product name. Identifies what was delivered (e.g., "Widget Suite").

**`--root-version`**

Product version (e.g., "2026.04"). Should match version naming scheme.

**`--root-delivery-date` (format: YYYY-MM-DD)**

Date delivery was received or prepared for analysis. ISO 8601 format.

**`--root-property key=value` (repeatable)**

Custom metadata as key-value pairs. Can be used multiple times:

```bash
--root-property contract=4711 \
--root-property channel=partner \
--root-property risk-level=medium
```

All properties appear in SBOM root component and report metadata.

### Safety/Resource Limits

Prevent runaway processing (DoS, resource exhaustion) on malicious or
accidentally-complex deliveries. Defaults are conservative:

- `MaxDepth`: 6 (typical complex nested archive: 3–4 levels)
- `MaxFiles`: 200,000
- `MaxTotalSize`: 20 GiB
- `MaxEntrySize`: 2 GiB (single file inside archive)
- `MaxRatio`: 150 (compression ratio; e.g., 1 MiB → 150 MiB after
  extraction)
- `Timeout`: 60 seconds

When a limit is exceeded **and** `--policy strict`, exit code is 2 (hard
failure). With `--policy partial`, the violating subtree is skipped.

**`--max-depth`**

Maximum nesting levels. ZIP→TAR→TAR = 3. Use higher values for known complex
deliveries from partners. Each level deeper increases attack surface.

**`--max-files`**

Total file count across all extractions. Bomb-like archives can create
millions of zero-byte files. Increase only if you trust the delivery source.

**`--max-size`**

Total bytes extracted before stopping. Protects disk space on CI workers.

**`--max-entry-size`**

Size of any single file inside an archive. Prevents extracting a single
compressed multi-gigabyte blob that explodes.

**`--max-ratio`**

Compression ratio (extracted bytes ÷ compressed bytes). Ratio > 150 is
suspicious (e.g., 10 MiB compressed → 1.5 GiB extracted suggests compression
bomb). Typical files: ratio 1–5.

**`--timeout`**

Go duration string (e.g., `60s`, `5m`). Hard stop if any single extraction
operation (per-archive) exceeds this time. Prevents hangs when processing
malicious or accidentally complex archives in CI.

### Sandboxing

**`--unsafe`**

Disable external extractor sandboxing. External tools (`7zz`, `unshield`) run
without isolation constraints.

**When to use:**

- macOS/BSD: `bwrap` is unavailable on these platforms; `--unsafe` is the
  default behavior there.
- WSL/Docker container: no `bwrap` available; use `--unsafe` instead.
- Trusted vendor input: when the delivery source is cryptographically verified
  or from a known partner with established trust.
- Development machine analyzing own artifacts.

**When NOT to use:**

- Untrusted external input in production.
- Public-facing services analyzing arbitrary user-uploaded files.
- Strict security gates in hardened CI environments (always require sandbox on
  Linux with `bwrap` available).

On Linux with `bwrap` available and without `--unsafe`, extraction runs in an
isolated namespace (restricted access to filesystem, network, IPC). This is
the secure default on Linux.

## Reading the Outputs

SBOM (`*.cdx.json`):

- CycloneDX format (`bomFormat`, `specVersion`)
- delivery traceability in component properties:
  - `extract-sbom:delivery-path`
  - `extract-sbom:extraction-status`

Use [Grype](https://github.com/anchore/grype) to scan the resulting SBOM for known
vulnerabilities. Grype is an open-source vulnerability scanner from Anchore that
can analyze container images, filesystem contents, and SBOMs. After extract-sbom
writes the BOM, run:

```bash
grype sbom:delivery.cdx.json --output json > delivery.grype.json
```

This command saves a CVE vulnerability scan of the identified software components
result into a JSON file. You can query the file for vulnerable components with a
HIGH or even CRITICAL CVSS value with a tool like [jq](https://jqlang.org/): 

```bash
jq '.matches[] | select((.vulnerability.severity == "High") or (.vulnerability.severity == "Critical")) | {artifact_id: .artifact.id, package: .artifact.name, version: .artifact.version, vulnerability: .vulnerability.id, severity: .vulnerability.severity}' grype.json
```

The output record of this query look like this:

```json
{
  "artifact_id": "extract-sbom:F5WE_M28G",
  "package": "zlib",
  "version": "1.2.11",
  "vulnerability": "CVE-2022-37434",
  "severity": "Critical"
}
```

Search for the artifact_id (extract-sbom:F5WE_MESG) in the report generated by
extract-sbom to find all files that contain the CRITICAL component in the original
delivery.zip. Automated processes can find this information in the
`"name": "extract-sbom:delivery-path"` property in the SBOM generates by extract-sbom.

Report (`*.report.md` / `*.report.json`):

- input hashes (SHA-256, SHA-512)
- effective configuration and limits
- sandbox mode used
- extraction tree and statuses
- scan outcomes and policy decisions
- processing issues (if any)
- residual risk/limitations section
