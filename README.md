# sbom-sentry

sbom-sentry performs standardized incoming inspection for software deliveries.
Given one input file, it produces:

- one consolidated CycloneDX SBOM
- one audit report (human-readable Markdown, machine-readable JSON, or both)

It recursively processes nested containers and archive formats, applies safety
limits, records extraction/scanning decisions, and keeps traceability via
`sbom-sentry:delivery-path` metadata.

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
sbom-sentry \
  --output-dir out \
  sample-delivery.zip
```

Run (unsandboxed, e.g., macOS or trusted CI):

```bash
mkdir -p out
sbom-sentry \
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
- [DESIGN.md](DESIGN.md): functional and security design
- [MODULE_GUIDE.md](MODULE_GUIDE.md): module architecture and decisions

## Project Status in CI

Core CI currently checks build, test, race, coverage, lint, plus dedicated
workflows for fuzz testing and release candidate verification.
