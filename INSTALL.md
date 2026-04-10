# INSTALL

This document explains how to install sbom-sentry, its dependencies, how to
recognize missing dependencies, and how to install them in common environments.

## 1. Prerequisites

Required:

- Go `1.26.2` or newer (`go.mod`)
- A writable output directory
- A writable work directory (defaults to OS temp directory)

Runtime tool dependencies depend on your input formats and safety mode:

- `7zz` (7-Zip): required for CAB, MSI payload extraction, 7z, RAR, and TAR XZ/Zstd extraction fallback
- `unshield`: required for InstallShield CAB extraction
- `bwrap` (Bubblewrap, Linux only): required for sandboxed external extraction unless `--unsafe` is used

Note: Syft is used as a Go library and is linked into the binary. You do not need a separate `syft` CLI installation.

## 2. Build / Install

### Option A: Build locally

```bash
go build -o sbom-sentry ./cmd/sbom-sentry
```

### Option B: Install via go install

```bash
go install ./cmd/sbom-sentry
```

This installs the binary into your Go bin path.

## 3. Verify Installation

Binary available:

```bash
./sbom-sentry --version
```

Dependency checks (common quick test):

```bash
command -v 7zz || echo "7zz missing"
command -v unshield || echo "unshield missing"
command -v bwrap || echo "bwrap missing (Linux sandbox mode)"
```

## 4. How Missing Dependencies Show Up

### 4.1 Missing output or work directory permissions

Symptoms:

- startup error like `output directory is not writable` or `work directory is not writable`

Fix:

- create directory and set permissions
- pass explicit `--output-dir` / `--work-dir`

### 4.2 Missing 7zz

When input requires 7-Zip-backed extraction (e.g., CAB, 7z, MSI, RAR):

- extraction node status becomes `tool-missing`
- status detail mentions `7zz (7-Zip) is not installed`
- run may become partial (exit code 1) depending on policy/results

### 4.3 Missing unshield

When processing InstallShield CAB:

- extraction node status becomes `tool-missing`
- status detail mentions `unshield is not installed`

### 4.4 Missing bwrap (sandbox)

If `bwrap` is unavailable and you did not pass `--unsafe`:

- report/issues include sandbox resolution/execution denial
- external extraction is denied with explicit message referring to `--unsafe`

If you pass `--unsafe`, sbom-sentry will run external tools unsandboxed and prints a warning on startup.

## 5. Getting Dependencies (Typical)

### 5.1 macOS (Homebrew)

```bash
brew install p7zip unshield
```

Sandbox note:

- `bwrap` is Linux-focused; on macOS use `--unsafe` in trusted environments when external tools are needed.

### 5.2 Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full unshield bubblewrap
```

### 5.3 Fedora / RHEL-like

```bash
sudo dnf install -y p7zip p7zip-plugins unshield bubblewrap
```

Package names can vary by distribution version. If a package is not found, search for the equivalent `7zip`, `unshield`, or `bubblewrap` package.

## 6. Minimal Post-Install Smoke Test

```bash
mkdir -p out
./sbom-sentry --unsafe --output-dir out integration/testdata/release/release-happy-path.zip
```

Expected:

- non-crashing execution
- generated `*.cdx.json` and report file in `out/`
- exit code 0 or 1 (partial is possible depending on available tools and scan results)
