# extract-sbom

extract-sbom performs standardized incoming inspection for software deliveries.
Given one input file, it produces:

- one consolidated CycloneDX SBOM
- one audit report (human-readable Markdown, machine-readable JSON, or both)

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
| MSI / CAB / InstallShield support | ✓ | ✗ | ✗ | ✗ | ✗ |
| Single delivery file in → consolidated SBOM out | ✓ | ✗ | ✗ | ✗ | ✗ |
| Auditable extraction report (Markdown / JSON) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Delivery-path traceability in SBOM metadata | ✓ | ✗ | ✗ | ✗ | ✗ |
| Sandboxed execution for untrusted vendor input | ✓ | ✗ | ✗ | ✗ | ✗ |
| Policy-controlled extraction (depth / size limits) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Deterministic / reproducible output | ✓ | ✗ | ✗ | ✗ | ✗ |
| Component cataloging across packaging ecosystems | ✓ (via Syft) | ✓ | ✗ | ✓ | ✗ |
| CycloneDX output | ✓ | ✓ | ✓ | ✗ | ~ |
| Independent of container registry / OCI | ✓ | ✓ | ✓ | ✓ | ✗ |
| SBOM manipulation (merge, diff, validate, sign) | ✗ | ✗ | ✓ | ✗ | ✗ |

> **Note:** cyclonedx-cli and Syft are complementary tools that integrate naturally
> with extract-sbom: Syft is used by extract-sbom as a cataloging engine, and
> cyclonedx-cli can be used to further process or validate the SBOM output.
> The table reflects suitability for the *incoming delivery inspection* workflow,
> not general-purpose capability.

---

## What It Does

- Identifies archive/container formats (ZIP, TAR variants, CAB, MSI, 7z, RAR, InstallShield CAB)
- Extracts recursively with policy and resource limits
- Uses Syft in library mode for component cataloging
- Assembles one deterministic CycloneDX 1.6 SBOM
- Generates an auditable report in English or German

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

- `sample-delivery.cdx.json`
- `sample-delivery.report.md` (or `.report.json`, depending on `--report`)

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
