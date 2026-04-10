# INSTALL

This document explains how to install a release build of sbom-sentry, install its
runtime dependencies, recognize missing dependencies, and get them in common
environments.

For building from source or for development, see [BUILD.md](BUILD.md).

## 1. Download a Release Binary

Prebuilt binaries for Linux and macOS (amd64 and arm64) are available at:

```
https://github.com/sbom-sentry/sbom-sentry/releases
```

Each release ships:

- `sbom-sentry_<version>_<os>_<arch>.tar.gz` — binary archive
- `checksums.txt` — SHA-256 checksums for all archives

Example for Linux amd64:

```bash
VERSION=v1.0.0
curl -Lo sbom-sentry.tar.gz \
  "https://github.com/sbom-sentry/sbom-sentry/releases/download/${VERSION}/sbom-sentry_${VERSION}_linux_amd64.tar.gz"
curl -Lo checksums.txt \
  "https://github.com/sbom-sentry/sbom-sentry/releases/download/${VERSION}/checksums.txt"
```

## 2. Verify Checksum

```bash
sha256sum --check --ignore-missing checksums.txt
```

Expected output:

```
sbom-sentry.tar.gz: OK
```

Do not proceed if verification fails.

## 3. Extract and Install

```bash
tar xzf sbom-sentry.tar.gz
sudo mv sbom-sentry /usr/local/bin/sbom-sentry
```

Or place the binary anywhere on your `PATH`.

## 4. Runtime Dependencies

The binary itself has no external Go runtime dependencies. Certain input formats,
however, require external tools at runtime:

- `7zz` (7-Zip): required for CAB, 7z, MSI payload, RAR, and TAR XZ/Zstd extraction
- `unshield`: required for InstallShield CAB extraction
- `bwrap` (Bubblewrap, Linux only): required for sandboxed external extraction unless `--unsafe` is used

Syft is compiled into the binary. No separate Syft installation is needed.

## 5. Verify Installation

Binary available:

```bash
sbom-sentry --version
```

Dependency checks:

```bash
command -v 7zz || echo "7zz missing"
command -v unshield || echo "unshield missing"
command -v bwrap || echo "bwrap missing (Linux sandbox mode)"
```

## 6. How Missing Dependencies Show Up

### 6.1 Missing output or work directory permissions

Symptoms:

- startup error like `output directory is not writable` or `work directory is not writable`

Fix:

- create directory and set permissions
- pass explicit `--output-dir` / `--work-dir`

### 6.2 Missing 7zz

When input requires 7-Zip-backed extraction (e.g., CAB, 7z, MSI, RAR):

- extraction node status becomes `tool-missing`
- status detail mentions `7zz (7-Zip) is not installed`
- run may become partial (exit code 1) depending on policy/results

### 6.3 Missing unshield

When processing InstallShield CAB:

- extraction node status becomes `tool-missing`
- status detail mentions `unshield is not installed`

### 6.4 Missing bwrap (sandbox)

If `bwrap` is unavailable and you did not pass `--unsafe`:

- report/issues include sandbox resolution/execution denial
- external extraction is denied with explicit message referring to `--unsafe`

If you pass `--unsafe`, sbom-sentry will run external tools unsandboxed and prints a warning on startup.

## 7. Getting Dependencies (Typical)

### 7.1 macOS (Homebrew)

```bash
brew install p7zip unshield
```

Sandbox note:

- `bwrap` is Linux-focused; on macOS use `--unsafe` in trusted environments when external tools are needed.

### 7.2 Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full unshield bubblewrap
```

### 7.3 Fedora / RHEL-like

```bash
sudo dnf install -y p7zip p7zip-plugins unshield bubblewrap
```

Package names can vary by distribution version. If a package is not found, search for the equivalent `7zip`, `unshield`, or `bubblewrap` package.

## 8. Minimal Post-Install Smoke Test

```bash
mkdir -p out
./sbom-sentry --unsafe --output-dir out integration/testdata/release/release-happy-path.zip
```

Expected:

- non-crashing execution
- generated `*.cdx.json` and report file in `out/`
- exit code 0 or 1 (partial is possible depending on available tools and scan results)
