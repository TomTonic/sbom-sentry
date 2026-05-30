# extract-sbom

[![Go Report Card](https://goreportcard.com/badge/github.com/TomTonic/extract-sbom)](https://goreportcard.com/report/github.com/TomTonic/extract-sbom)
[![Tests](https://github.com/TomTonic/extract-sbom/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/TomTonic/extract-sbom/actions/workflows/tests.yml)
[![Linter](https://github.com/TomTonic/extract-sbom/actions/workflows/linter.yml/badge.svg)](https://github.com/TomTonic/extract-sbom/actions/workflows/linter.yml)
[![Vulnerabilities](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/TomTonic/a4353e77e0b8762f50931635603edc4e/raw/release_scan.json)](https://gist.github.com/TomTonic/a4353e77e0b8762f50931635603edc4e#file-release_scan-md)

extract-sbom performs standardized incoming inspection for software deliveries.
Given one input file, it produces:

- one consolidated SBOM (CycloneDX JSON, CycloneDX XML, or SPDX JSON)
- one audit report (Markdown, HTML, JSON, SARIF, or any combination)

It recursively processes nested containers and archive formats, applies safety
limits, records extraction/scanning decisions, and keeps traceability via
`extract-sbom:delivery-path` metadata.

The concrete scan strategy, including determinism and trust boundaries, is
explained in [SCAN_APPROACH.md](SCAN_APPROACH.md).

## Why This Project Exists

Software procurement teams regularly receive deliveries from external vendors — ZIP
archives, MSI installers, setup executables — and must verify that these deliveries
are free of known vulnerabilities (CVEs) before they are accepted and deployed.
This is the software equivalent of an incoming goods inspection: in supply-chain-critical
environments, nothing is deployed without being checked first. The relevant risk is not
just in the top-level package, but throughout the entire software supply chain —
transitive dependencies, bundled libraries, and components buried inside nested
installer formats.

Existing SBOM tools cover the development and build side of the supply chain well,
but none address the inspection of an already-packaged, opaque vendor delivery:

- **[Syft](https://github.com/anchore/syft)** generates SBOMs from container images,
  source directories, and simple archive formats. It does not recursively unpack
  deeply nested archives or installer formats (MSI, CAB, InstallShield), produces no
  auditable report, and provides no sandboxing for untrusted inputs. extract-sbom uses
  Syft internally as a component cataloging engine, but Syft alone cannot handle the
  delivery inspection workflow.

- **[cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli)** is a BOM
  manipulation tool for converting, merging, diffing, validating, and signing existing
  SBOM documents. It has no ability to generate an SBOM from a software artifact and no
  extraction capability.

- **[microsoft/sbom-tool](https://github.com/microsoft/sbom-tool)** generates SPDX
  SBOMs from a build drop path or source tree. It is designed for software *producers*
  to describe their own products during CI/CD — not for *consumers* performing incoming
  inspection of an opaque binary or installer received from an external vendor.

- **[jimmykarily/sbom-extractor](https://github.com/jimmykarily/sbom-extractor)** pulls
  an SBOM that was previously attached to a container image as an OCI attestation. It
  operates exclusively on container registry images and cannot inspect a locally
  received file. It also relies entirely on the vendor having already attached an SBOM
  to the image — no independent verification is possible.

extract-sbom fills the gap by treating the vendor delivery file as the unit of
inspection: one file in, one consolidated CycloneDX SBOM and one auditable report out.

### Feature Comparison

| Feature | extract-sbom | Syft | cyclonedx-cli | microsoft/sbom-tool | jimmykarily/sbom-extractor |
|---|:---:|:---:|:---:|:---:|:---:|
| Designed for incoming delivery inspection | ✓ | ✗ | ✗ | ✗ | ✗ |
| Recursive nested archive extraction | ✓ | ✗ | ✗ | ✗ | ✗ |
| MSI / CAB / InstallShield / ISO / CPIO / Squashfs support | ✓ | ✗ | ✗ | ✗ | ✗ |
| Single delivery file in → consolidated SBOM out | ✓ | ✗ | ✗ | ✗ | ✗ |
| Auditable extraction report (Markdown / HTML / JSON / SARIF) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Delivery-path traceability in SBOM metadata | ✓ | ✗ | ✗ | ✗ | ✗ |
| Sandboxed execution for untrusted vendor input | ✓ | ✗ | ✗ | ✗ | ✗ |
| Policy-controlled extraction (depth / size limits) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Deterministic / reproducible output | ✓ | ✗ | ✗ | ✗ | ✗ |
| Component cataloging across packaging ecosystems | ✓ (via Syft) | ✓ | ✗ | ✓ | ✗ |
| CycloneDX output (JSON + XML) | ✓ | ✓ | ✓ | ✗ | ~ |
| SPDX 2.3 JSON output | ✓ | ✓ | ✓ | ✓ | ✗ |
| SARIF output for CI security gates | ✓ | ✗ | ✗ | ✗ | ✗ |
| Independent of container registry / OCI | ✓ | ✓ | ✓ | ✓ | ✗ |
| SBOM manipulation (merge, diff, validate, sign) | ✗ | ✗ | ✓ | ✗ | ✗ |

> **Note:** cyclonedx-cli and Syft are complementary tools that integrate naturally
> with extract-sbom: Syft is used by extract-sbom as a cataloging engine, and
> cyclonedx-cli can be used to further process or validate the SBOM output.
> The table reflects suitability for the *incoming delivery inspection* workflow,
> not general-purpose capability.

---

## What It Does

- Identifies archive/container formats (ZIP, TAR variants, CAB, MSI, 7z, RAR, InstallShield CAB, ISO, CPIO, Squashfs/Snap, AppImage)
- Extracts recursively with policy and resource limits
- Detects encrypted ZIP entries and automatically re-routes those archives to 7-Zip
- Tries configured passwords in order for password-protected formats handled by external extractors
- Uses Syft in library mode for component cataloging
- Assembles one deterministic SBOM in CycloneDX 1.6 JSON (`--format cyclonedx-json`), CycloneDX XML (`--format cyclonedx-xml`), or SPDX 2.3 JSON (`--format spdx-json`)
- Generates an auditable report in Markdown (`--report markdown`), standalone HTML (`--report html`), structured JSON (`--report json`), SARIF 2.1.0 (`--report sarif`), or all formats at once (`--report all`) — in English or German

## Encrypted Archives and Password Sources

For encrypted archives, extract-sbom supports ordered password attempts from:

- `--password` (repeatable)
- `EXTRACT_SBOM_PASSWORDS` (comma-separated)
- `--password-file` (one password per line, `#` comments allowed)

Password attempts are ordered by source precedence:

1. command-line flags (`--password`)
2. environment variable (`EXTRACT_SBOM_PASSWORDS`)
3. password file (`--password-file`)

Within extraction, extract-sbom first tries without a password, then each
configured password in order. Secrets are never printed in logs or reports.

## Optional Vulnerability Enrichment (`--grype`)

If `--grype` is enabled, extract-sbom runs Grype against the generated SBOM and
enriches the audit report without changing SBOM structure or extraction/scan decisions.

- Summary view: grype-inspired vulnerability table with `Name`, installed/fixed versions,
  vulnerability ID, severity (including CVSS score when available), EPSS, risk, and KEV.
- Detail view: package-grouped occurrence index with per-occurrence vulnerability status
  (`found`, `none`, `not-assessable`), including type, fix data, CVSS version/score/vector,
  description, EPSS, and source references when available.
- Runtime diagnostics: Grype version/database metadata and explicit enrichment state
  (`completed`, `completed-with-errors`, `unavailable`, `not-requested`).
- Failure behavior: if Grype is missing or returns invalid/unusable output, SBOM and report
  are still generated; the report records enrichment as unavailable/incomplete.

## Quick Start

Install a prebuilt release binary (see [INSTALL.md](INSTALL.md)) or build
from source (see [BUILD.md](BUILD.md)).

Run (sandboxed mode on Linux with `bwrap`):

```bash
mkdir -p out
extract-sbom \
  --output-dir out \
  sample-delivery.zip
```

Run (unsandboxed, e.g., macOS or trusted CI):

```bash
mkdir -p out
extract-sbom \
  --unsafe \
  --output-dir out \
  sample-delivery.zip
```

Typical outputs in `out/` (base name derived from input file):

- `sample-delivery.cdx.json` (default; use `--format cyclonedx-xml` for `.cdx.xml`, `--format spdx-json` for `.spdx.json`)
- `sample-delivery.report.md` (default; use `--report json` for `.report.json`, `--report html` for `.report.html`, `--report sarif` for `.sarif.json`, `--report all` for all formats)

## Documentation

- [INSTALL.md](INSTALL.md): installation and dependency troubleshooting
- [BUILD.md](BUILD.md): building from source and release tooling
- [USAGE.md](USAGE.md): scenario-based usage, parameters, and outputs
- [SCAN_APPROACH.md](SCAN_APPROACH.md): operator-focused explanation of how scanning works and why the result is trustworthy
- [DESIGN.md](DESIGN.md): functional and security design
- [MODULE_GUIDE.md](MODULE_GUIDE.md): module architecture and decisions

## Project Status in CI

Core CI currently checks build, test, race, coverage, lint, plus dedicated
workflows for fuzz testing and release candidate verification.
