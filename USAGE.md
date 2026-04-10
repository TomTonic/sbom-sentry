# USAGE

This guide explains sbom-sentry in scenario form: what to run, which parameters
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
./sbom-sentry \
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
./sbom-sentry \
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
./sbom-sentry \
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
./sbom-sentry \
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
./sbom-sentry \
  --unsafe \
  --report machine \
  --output-dir out \
  vendor-delivery.zip
```

Result:

- `out/vendor-delivery.report.json` contains structured extraction/scanning/decision data

## Parameters by Concern

Input/output:

- positional `<input-file>`
- `--output-dir`
- `--work-dir`

Policy and interpretation:

- `--policy strict|partial`
- `--mode physical|installer-semantic`
- `--report human|machine|both`
- `--language en|de`

Root metadata:

- `--root-manufacturer`
- `--root-name`
- `--root-version`
- `--root-delivery-date` (YYYY-MM-DD)
- `--root-property key=value` (repeatable)

Safety/resource limits:

- `--max-depth`
- `--max-files`
- `--max-size`
- `--max-entry-size`
- `--max-ratio`
- `--timeout` (duration, e.g. `60s`)

Sandboxing:

- `--unsafe` enables unsandboxed external extraction when sandbox is unavailable

## Reading the Outputs

SBOM (`*.cdx.json`):

- CycloneDX format (`bomFormat`, `specVersion`)
- delivery traceability in component properties:
  - `sbom-sentry:delivery-path`
  - `sbom-sentry:extraction-status`

Report (`*.report.md` / `*.report.json`):

- input hashes (SHA-256, SHA-512)
- effective configuration and limits
- sandbox mode used
- extraction tree and statuses
- scan outcomes and policy decisions
- processing issues (if any)
- residual risk/limitations section
