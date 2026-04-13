# extract-sbom — Software Module Guide

This document describes the solution architecture, tool selection, module
structure, interfaces, and implementation plan for extract-sbom. It fulfils the
requirement in AGENT.md §3.1 and serves as the primary reference for subsequent
coding agent invocations.

---

## 1. Tool and Library Selection

### 1.1 Go Libraries

| Library | Version | Purpose | Rationale |
|---|---|---|---|
| `github.com/anchore/syft` | v1.x (latest stable) | SBOM cataloging in library mode | Mandatory per DESIGN.md §9.2. `syft.GetSource()` resolves a path to a `source.Source`; `syft.CreateSBOM(ctx, src, cfg)` returns an `sbom.SBOM`. Builder-pattern config via `DefaultCreateSBOMConfig().WithTool(…)`. Avoids shelling out. |
| `github.com/CycloneDX/cyclonedx-go` | v0.10.x | SBOM data model, encoding, decoding | Standard Go binding for CycloneDX 1.6. Provides `BOM`, `Component`, `Dependency`, `Composition` types plus JSON/XML encoder/decoder. Used for merging per-subtree SBOMs and adding container components. |
| `github.com/spf13/cobra` | v1.x | CLI framework | De facto standard for Go CLIs. Provides flag parsing, subcommands, help generation. Low-risk, widely adopted. |
| `github.com/spf13/viper` | v1.x | Configuration binding | Binds CLI flags, env vars, and config files to a single config struct. Pairs naturally with cobra. |
| `github.com/richardlehane/mscfb` | v1.x | OLE/CFBF compound document reader | Required for reading MSI Property tables (ProductName, Manufacturer, ProductVersion). Used in both physical and installer-semantic modes for container metadata enrichment (see §5.8). |

Go Standard Library modules used directly for archive handling:

| Stdlib package | Purpose |
|---|---|
| `archive/zip` | ZIP extraction with per-entry streaming (Go 1.0+, mature, actively CVE-patched) |
| `archive/tar` | TAR extraction with per-entry streaming (Go 1.0+, mature, actively CVE-patched) |
| `compress/gzip` | Gzip decompression for `.tar.gz` |
| `compress/bzip2` | Bzip2 decompression for `.tar.bz2` (read-only — sufficient for our case) |

Additional Go compression modules (only if the corresponding TAR variant must be supported):

| Library | Purpose |
|---|---|
| `github.com/ulikunitz/xz` | XZ decompression for `.tar.xz` |
| `github.com/klauspost/compress/zstd` | Zstandard decompression for `.tar.zst` |

### 1.2 External Binaries

| Binary | Purpose | Rationale |
|---|---|---|
| **7-Zip** (`7zz`) | Extract Microsoft CAB and MSI files; also 7z and RAR if encountered | No viable pure-Go library exists for Microsoft CAB or MSI (OLE compound document) formats. 7-Zip handles both natively, is widely packaged on Linux, and is the preferred extractor per DESIGN.md §9.2. |
| **unshield** | Extract InstallShield CAB files (`data1.cab` + `data1.hdr`) | InstallShield uses a proprietary cabinet format incompatible with Microsoft CABs. `unshield` (MIT, actively maintained, v1.6.2) is the only tool capable of extracting these. Available via Linux package managers and Homebrew. |
| **Bubblewrap** (`bwrap`) | Sandbox for all external binary invocations (`7zz`, `unshield`) | Lightweight Linux namespace sandbox (LGPL-2.1). Used by Flatpak. Provides mount, PID, network, and IPC namespace isolation without requiring root or Docker. |

### 1.3 Tool Availability Strategy

| Mechanism | Available | Not Available |
|---|---|---|
| `bwrap` | All external binary invocations (`7zz`, `unshield`) are sandboxed | User must pass `--unsafe` flag; extraction runs unsandboxed. Prominently flagged in report. |
| `7zz` | Microsoft CAB/MSI extraction proceeds normally. Also handles 7z/RAR inputs. | Microsoft CAB/7z/RAR archives are recorded as non-extractable components in the SBOM. MSI payload extraction is skipped, but MSI container metadata is still read directly from the MSI database and added to the SBOM. Audit report notes missing tool. |
| `unshield` | InstallShield CAB extraction proceeds normally. | InstallShield CABs are recorded as non-extractable components in the SBOM. Audit report notes missing tool. |
| Syft (library) | Required | Fatal error. |

### 1.4 Why Go Standard Library over mholt/archives

An earlier design iteration considered `github.com/mholt/archives` (v0.1.x)
as a unified, pure-Go archive library. It was removed for the following reasons:

1. **Maturity gap.** mholt/archives has five releases, has not been updated in
   over six months, and covers a broad format surface (ZIP, TAR, RAR, 7z,
   eleven compression algorithms). A wide format surface combined with a short
   track record increases the likelihood of undiscovered parsing bugs —
   even if the library does not execute archive contents.

2. **Go stdlib is battle-tested.** `archive/zip` and `archive/tar` have been
   part of the Go standard library since Go 1.0 (2012). They receive prompt
   CVE-grade fixes via the Go release process, are fuzz-tested by the Go
   team and OSS-Fuzz, and are among the most widely used Go packages.
   For the two formats that dominate vendor deliveries (ZIP, TAR), stdlib
   provides all the functionality we need: per-entry streaming extraction
   with header inspection before writing any bytes.

3. **We do not need mholt/archives' extra format coverage.** The formats
   mholt/archives adds beyond stdlib (RAR, 7z as pure Go) are uncommon in
   software deliveries. For the rare cases where they appear, 7-Zip
   (already required for CAB/MSI) handles them as well.

4. **Reduced dependency surface.** stdlib modules add zero supply-chain risk.
   Fewer third-party dependencies means fewer transitive CVEs to track and
   a simpler audit trail — which matters for a tool whose purpose is to *assess*
   supply chain integrity.

The trade-off is that we have two extraction paths (in-process stdlib for ZIP/TAR,
external 7-Zip for CAB/MSI/7z/RAR). This is justified in §1.5.

### 1.5 Security Architecture

**Threat model scope.** extract-sbom is a supply-chain inspection tool, not a
malware or virus scanner (see DESIGN.md §1.3). It never executes, interprets,
or dynamically analyses any content from the input file. Its security boundary
covers *extraction safety* — the data-plane threats that arise from unpacking
untrusted archives:

| Threat | Mitigation | Layer |
|---|---|---|
| Zip bomb / compression bomb | Per-entry ratio check, total size limit, file count limit | `safeguard` |
| Path traversal (`../`, absolute paths) | Path canonicalization and containment check before writing | `safeguard` |
| Symlink escape | Symlink detection and rejection before writing | `safeguard` |
| Special files (devices, pipes) | File-type check before writing | `safeguard` |
| Resource exhaustion (depth, time) | Configurable depth limit and per-extraction timeout | `extract` |

These mitigations apply to *all* extraction paths (Go stdlib and 7-Zip).

**Two extraction paths — one security standard.**

| Path | Format coverage | Safeguard integration |
|---|---|---|
| Go stdlib (in-process) | ZIP, TAR (+compressed variants) | Per-entry streaming: each entry's header is validated by `safeguard` *before* any bytes are written to disk. Extraction can be aborted mid-stream on the first violation. |
| 7-Zip (external, sandboxed) | CAB, MSI, 7z, RAR | Extraction runs under Bubblewrap namespace isolation (read-only input bind, write-only output bind, no network). After extraction completes, `safeguard` walks the output directory and validates all resulting paths and file types. |

The in-process path provides *proactive* per-entry checks; the 7-Zip path provides
*reactive* post-extraction checks plus process-level isolation via Bubblewrap.
Both paths enforce the same `safeguard` invariants. Hard security violations
(path traversal, symlink escape, special files) are **never** overridable,
regardless of `--unsafe`.

**Why in-process extraction is acceptable for ZIP/TAR.** The specific concern
with in-process archive parsing is that a parser bug could let a crafted archive
compromise the host process. For extract-sbom this risk is bounded:

- Go's `archive/zip` and `archive/tar` are memory-safe (no buffer overflows).
- Both are continuously fuzz-tested by the Go team and OSS-Fuzz.
- We never interpret the *content* of extracted files — we only write them to
  disk and pass the directory to Syft. A parser bug could at worst cause a
  crash or incorrect extraction, not code execution.
- extract-sbom is not a persistent service; it runs as a one-shot CLI tool.
  A crash is a clean failure, not a persistent compromise.

For formats without comparable Go-stdlib maturity (CAB, MSI), we do not accept
this trade-off and use an external process under sandbox isolation instead.

### 1.6 CAB / MSI / Setup.exe — Architecture and Limitations

CAB and MSI are the most complex formats in scope. This section documents the
known complexity and our handling strategy.

**Why we need an external tool.** No maintained, pure-Go library exists for
reading Microsoft CAB files or MSI (OLE Compound Binary File Format) structures.
The reference implementation is the C library `libmspack` (used by `cabextract`).
7-Zip implements its own CAB and OLE/MSI parsers and is widely packaged. Using
7-Zip keeps the external dependency count at one.

**Physical vs. installer-semantic mode — what changes?**

| Aspect | Physical mode | Installer-semantic mode |
|---|---|---|
| CAB extraction | 7-Zip extracts raw contents; filenames taken as-is | Same — CAB filenames are normally unmangled |
| MSI extraction | 7-Zip extracts internal CAB streams and raw MSI tables | Must additionally read the MSI `File` table to map mangled internal CAB entry names back to the original target filenames and directory structure |
| Setup.exe | 7-Zip extracts embedded payloads (CABs, MSIs, ZIPs) | Same — outer wrapper is a physical container; installer semantics apply to the embedded MSI if present |

**MSI name-mangling problem.** An MSI packages its file payload in one or more
internal CAB streams. The entry names inside those CABs are often *not* the
original filenames the installer would write to disk. Instead, the MSI database
contains a `File` table that maps each internal entry name to a target path,
component, and feature. In installer-semantic mode, extract-sbom must:

1. Extract the raw MSI with 7-Zip (yielding internal CAB streams + table data).
2. Parse the MSI's OLE structure to read the `File` table.
   The Go OLE/CFBF reader `github.com/richardlehane/mscfb` provides
   stream-level access; the MSI table format itself requires a small custom
   parser for the string pool and table records.
3. Use the `File` table to remap internal CAB entry names to target paths.
4. Document all remappings in the audit report.

This functionality is deferred to the installer-semantic implementation phase
(Phase 4). Physical mode does not require MSI table parsing for filename
remapping.

**MSI metadata extraction (both modes).** Independently of filename remapping,
the MSI Property table is read directly from the original MSI in *both*
physical and installer-semantic modes to extract product metadata for SBOM
enrichment. This step does not depend on 7-Zip and still runs when payload
extraction is unavailable:

| MSI Property | Usage |
|---|---|
| `Manufacturer` (required) | CPE vendor field |
| `ProductName` (required) | CPE product field, component name |
| `ProductVersion` (required) | CPE version field, component version |
| `UpgradeCode` (optional) | Correlates related product releases; stored as component property |
| `ProductCode` (required) | Unique product GUID; stored as component property |
| `ProductLanguage` (required) | Stored as component property |

The OLE reader (`mscfb`) and the MSI string-pool parser are shared between
metadata extraction (Phase 3) and full table parsing (Phase 4). See §5.8.

**Implementation risk note for installer-semantic MSI support.** Parsing the MSI
`File` table, resolving directories, and remapping internal CAB names back to
installer target paths is the highest-risk feature in the current design. If
this logic cannot be implemented defensibly, the fallback is:

- keep physical-mode extraction as the source of truth for file payloads
- still extract MSI container metadata in both modes
- emit installer-semantic remapping only where reconstruction is reliable
- document unresolved MSI path semantics explicitly in the audit report

**InstallShield CABs.** InstallShield uses a proprietary cabinet format that is
*not* compatible with Microsoft CABs. Files typically arrive as `data1.cab` +
`data1.hdr`. Neither 7-Zip nor `cabextract` can unpack these; the tool
`unshield` is required.

When `unshield` is installed, extract-sbom extracts InstallShield CABs via the
sandbox interface (same pattern as 7-Zip) and recurses into the extracted contents.
When `unshield` is not installed, such files are recorded as non-extractable
components in the SBOM and flagged in the audit report.

Detection heuristic: a file named `data1.cab` accompanied by `data1.hdr` (or
`data2.cab`, etc.) in the same directory is treated as an InstallShield cabinet
set. Additionally, the `identify` module checks for the InstallShield magic bytes
(`ISc(` at offset 0) to distinguish InstallShield CABs from Microsoft CABs.

---

## 2. Module Overview

```text
cmd/
  extract-sbom/          CLI entry point

internal/
  config/               Configuration types and defaults
  identify/             Format detection
  extract/              Archive extraction engine
  safeguard/            Security validation (paths, symlinks, ratios)
  sandbox/              Isolation wrapper (bwrap / passthrough)
  scan/                 Syft integration
  assembly/             CycloneDX SBOM merge and construction
  report/               Audit report generation
  policy/               Policy enforcement (strict / partial)
  orchestrator/         End-to-end pipeline coordination
```

---

## 3. Module Specifications

### 3.1 `cmd/extract-sbom`

**Purpose:** Binary entry point. Parses CLI arguments, constructs a `config.Config`,
and delegates to the orchestrator.

**Interface:**

```text
main()
  → cobra root command
    → run(cfg config.Config) error
```

**Key flags:**

- `--input` / positional arg: path to delivery file
- `--output-dir`: target directory for SBOM + report
- `--work-dir`: base directory for temporary extraction work (default: system temp dir)
- `--format`: SBOM output format (`cyclonedx-json` default)
- `--policy`: `strict` (default) | `partial`
- `--mode`: `installer-semantic` (default) | `physical`
- `--report`: `human` (default) | `machine` | `both`
- `--language`: `en` (default) | `de`
- `--root-manufacturer`: override manufacturer / supplier for the SBOM root component
- `--root-name`: override software / product name for the SBOM root component
- `--root-version`: override version for the SBOM root component
- `--root-delivery-date`: delivery date for the inspected software delivery (`YYYY-MM-DD`)
- `--root-property`: repeated `key=value` property added to the SBOM root component
- `--unsafe`: enable unsandboxed extraction (must never be silent)
- `--max-depth`, `--max-files`, `--max-size`, `--max-entry-size`,
  `--max-ratio`, `--timeout`: override default limits

**Design decisions:**

- No subcommands. Single verb: run the inspection.
- `--unsafe` prints a hard warning to stderr before proceeding.
- Root metadata flags apply only to the top-level delivered software component,
  never to nested container components discovered during extraction.

---

### 3.2 `internal/config`

**Purpose:** Central configuration struct and defaults.

**Interface:**

```go
type Config struct {
    InputPath       string
    OutputDir       string
  WorkDir         string        // base directory for temporary extraction work
    SBOMFormat      string        // "cyclonedx-json"
    PolicyMode      PolicyMode    // Strict | Partial
    InterpretMode   InterpretMode // Physical | InstallerSemantic
    ReportMode      ReportMode    // Human | Machine | Both
    Language        string        // "en" | "de"
  RootMetadata    RootMetadata
    Unsafe          bool
    Limits          Limits
}

type RootMetadata struct {
  Manufacturer string
  Name         string
  Version      string
  DeliveryDate string            // canonical input format: YYYY-MM-DD
  Properties   map[string]string // extra root-level metadata from --root-property
}

type Limits struct {
    MaxDepth     int
    MaxFiles     int
    MaxTotalSize int64  // bytes
    MaxEntrySize int64  // bytes
    MaxRatio     int
    Timeout      time.Duration
}

func DefaultLimits() Limits
func (c *Config) Validate() error
```

**Design decisions:**

- All limits have tested defaults matching DESIGN.md §6.1.
- `Validate()` enforces invariants (e.g. input file must exist, output dir writable,
  work dir must exist and be writable).
- `RootMetadata.Validate()` normalizes duplicate property keys, validates the
  delivery-date format, and rejects malformed `key=value` pairs.
- If `RootMetadata.Name` is empty, assembly derives a deterministic fallback
  from the input filename; explicit CLI input always wins.

---

### 3.3 `internal/identify`

**Purpose:** Detect the format of a file, and determine whether Syft can handle
it natively or whether extract-sbom needs to extract it.

**Interface:**

```go
type FormatInfo struct {
    Format     Format   // ZIP, TAR, GzipTAR, Bzip2TAR, XzTAR, ZstdTAR, CAB, MSI, SevenZip, RAR, InstallShieldCAB, Unknown
    MIMEType   string
    Extension  string
    SyftNative bool     // true if Syft already understands this format (JAR, RPM, DEB, etc.)
    Extractable bool   // true if we can extract it (Go stdlib or 7z or unshield)
}

func Identify(ctx context.Context, path string) (FormatInfo, error)
```

**Design decisions:**

- Detection uses file-magic bytes (first 16 bytes) and file extension:
  - ZIP: `PK\x03\x04` — then further check for Syft-native ZIP-based
    formats (JAR/WAR/EAR via manifest, .whl/.egg via extension, .nupkg,
    .apk, etc.). If Syft-native → `SyftNative = true`.
  - TAR: `ustar` at offset 257
  - CAB (Microsoft): `MSCF` at offset 0
  - CAB (InstallShield): `ISc(` at offset 0, or `data*.cab`/`data*.hdr` naming pattern
  - MSI: OLE compound document `D0 CF 11 E0 A1 B1 1A E1` at offset 0
  - 7z: `7z\xBC\xAF\x27\x1C` at offset 0
  - RAR: `Rar!\x1A\x07` at offset 0
  - Compressed TAR: detect outer compression (gzip magic `\x1F\x8B`,
    bzip2 `BZ`, xz `\xFD7zXZ\x00`, zstd `\x28\xB5\x2F\xFD`), then
    verify inner TAR header.
- **Syft-native formats** are file types where Syft has a dedicated cataloger
  that understands the internal structure (e.g. JAR → Java packages, RPM →
  RPM metadata, DEB → Debian packages). These are passed directly to Syft
  and never extracted by extract-sbom. The list of Syft-native formats is
  maintained as a configuration constant.
- Never attempts extraction. Read-only, bounded I/O.

---

### 3.4 `internal/safeguard`

**Purpose:** Validate extracted paths and entries before they are written to disk.
This is the hard security boundary (DESIGN.md §6.2 / §6.3).

**Interface:**

```go
// ValidatePath checks a single entry name/path for safety violations.
// Returns a non-nil HardSecurityError on path traversal, symlink escape,
// special files, or unsafe permissions.
func ValidatePath(name string, baseDir string) error

// ValidateEntry checks size, ratio, and file-type constraints.
func ValidateEntry(header EntryHeader, limits config.Limits, stats *ExtractionStats) error

// HardSecurityError signals a non-overridable violation.
type HardSecurityError struct { /* … */ }
```

**Design decisions:**

- Hard security failures (path traversal, symlink escape, special files)
  are **never** overridable, not even in unsafe mode. They abort the
  current extraction subtree immediately.
- Ratio checking compares compressed vs. uncompressed size per entry.
- Counters for file count and total size are accumulated in `ExtractionStats`
  and checked per entry.

---

### 3.5 `internal/sandbox`

**Purpose:** Wrap external binary execution in an isolated namespace.

**Interface:**

```go
type Sandbox interface {
    // Run executes the command inside the sandbox.
    // inputPath is bind-mounted read-only; outputDir is bind-mounted read-write.
    Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error

    // Available reports whether this sandbox mechanism is functional.
    Available() bool

    // Name returns a human-readable identifier for audit logging.
    Name() string
}

func NewBwrapSandbox() Sandbox       // Bubblewrap implementation
func NewPassthroughSandbox() Sandbox // No isolation (unsafe fallback)
func Resolve(cfg config.Config) (Sandbox, error)
```

**Bubblewrap invocation pattern:**

```sh
bwrap \
  --ro-bind <input-file-dir> /input \
  --bind <output-dir> /output \
  --tmpfs /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-all \
  --new-session \
  --die-with-parent \
  -- 7zz x /input/<filename> -o/output
```

**Design decisions:**

- `--unshare-all` creates new mount, PID, IPC, UTS, network, and user namespaces.
- `--die-with-parent` ensures cleanup if the parent (extract-sbom) crashes.
- `--new-session` mitigates `TIOCSTI` injection.
- `Resolve()` checks `Available()` on the bwrap sandbox; if unavailable and
  `cfg.Unsafe == true`, returns passthrough.
- If unavailable and `cfg.Unsafe == false`, `Resolve()` returns
  `DeniedSandbox` plus a non-nil error so the condition is explicit and
  deterministic in reports.
- The same sandbox interface is used for both `7zz` and `unshield` invocations.
- Every invocation is logged with the sandbox name for the audit trail.

---

### 3.6 `internal/extract`

**Purpose:** Recursive, auditable extraction of archive formats. Applies the
**Syft-first principle**: every file is first checked for Syft-native handling;
extract-sbom only extracts when Syft cannot see through a container format.

**Interface:**

```go
// ExtractionNode is the central processing data structure.
// Each node represents a container artifact encountered during traversal.
type ExtractionNode struct {
    Path          string         // physical artifact path relative to delivery root
    OriginalPath  string         // absolute filesystem path of the original file
    Format        identify.FormatInfo
    Status        ExtractionStatus // pending, syft-native, extracted, skipped, failed, security-blocked, tool-missing
    StatusDetail  string
    ExtractedDir  string         // filesystem path of extracted contents (empty if SyftNative)
    Children      []*ExtractionNode
    Metadata      *ContainerMetadata // non-nil for formats with structured metadata (MSI)
    InstallerHint string         // installer-semantic enrichment hint (when available)
    Tool          string         // "archive/zip" | "archive/tar" | "7zz" | "unshield" | "syft"
    SandboxUsed   string         // sandbox mechanism used for external tools
    Duration      time.Duration
    EntriesCount  int
    TotalSize     int64
    ExtensionFilteredPaths []string // direct-child paths excluded by SkipExtensions
}

// ContainerMetadata holds structured product information extracted from
// container formats that carry it (currently: MSI Property table).
type ContainerMetadata struct {
    ProductName    string // MSI: ProductName
    Manufacturer   string // MSI: Manufacturer
    ProductVersion string // MSI: ProductVersion
    ProductCode    string // MSI: ProductCode (GUID)
    UpgradeCode    string // MSI: UpgradeCode (GUID)
    Language       string // MSI: ProductLanguage
}

// Extract recursively processes the given file according to config.
// Returns the root of the extraction tree.
func Extract(ctx context.Context, inputPath string, cfg config.Config, sandbox sandbox.Sandbox) (*ExtractionNode, error)
```

**Implementation layout (maintainability):**

- `extract.go`: package-level extraction model overview
- `types.go`: extraction statuses and node metadata structures
- `extract_flow.go`: recursive traversal, status assignment order, policy handling
- `extract_inprocess.go`: ZIP/TAR extractors and in-process safeguard checks
- `extract_external.go`: sandboxed `7zz`/`unshield` integration and tool lookup
- `msi.go`: direct MSI metadata parsing (`_StringPool`, `_StringData`, `Property`)

**Syft-first dispatch logic:**

```text
For each file encountered:
  1. Identify format (identify.Identify)
  2. If file is MSI:
    → read Property table directly via mscfb
    → populate node.Metadata even if later payload extraction is unavailable
  3. If SyftNative == true:
     → mark as SyftNative leaf (Tool = "syft")
     → scan module will invoke Syft directly on the original file
     → do NOT extract
  4. If SyftNative == false AND file is a recognized container format:
     → extract:
        ├─ ZIP                 → Go stdlib archive/zip (in-process, per-entry safeguard)
        ├─ TAR / compressed TAR → Go stdlib archive/tar + compress/* (in-process, per-entry safeguard)
      ├─ CAB, MSI, 7z, RAR   → 7zz via sandbox (post-extraction safeguard walk)
      ├─ InstallShield CAB   → unshield via sandbox (post-extraction safeguard walk)
      └─ Unknown container   → mark as non-extractable leaf
     → for each extracted child: recurse (depth + 1)
  5. If not a container format:
     → mark as plain leaf (will be picked up by Syft when its parent directory is scanned)
```

**Example:** A delivery ZIP contains a DLL, a JAR, and a nested MSI.

- ZIP → extracted with `archive/zip`
- DLL → plain leaf, cataloged when Syft scans the extracted directory
- JAR → SyftNative (Syft's Java cataloger handles it directly)
- MSI → Property table read directly from the original file → extracted with 7zz via sandbox
  when available → produces internal CABs → recurse

**Design decisions:**

- **Go stdlib extraction** (`archive/zip`, `archive/tar`) runs in-process.
  Each entry header is passed to `safeguard.ValidatePath` and
  `safeguard.ValidateEntry` before any bytes are written. On violation,
  extraction stops immediately (hard security) or the entry is skipped
  (policy-dependent for resource limits).
- **7-Zip extraction** is always mediated by the sandbox interface.
  After 7-Zip completes, `safeguard` walks the output directory to validate
  all resulting paths and file types.
- **MSI metadata extraction** is independent of 7-Zip. If payload extraction
  is unavailable, the MSI node still remains in the tree with enriched
  metadata and a non-extractable or partial status.
- Depth, file count, total size, and per-entry limits from `config.Limits`
  are enforced continuously. Violations trigger policy behavior:
  `strict` → abort entire run, `partial` → skip subtree, continue.
- Hard security violations block the affected subtree immediately, but the
  orchestrator still writes a final SBOM and report once input validation has
  succeeded and the root extraction node has been created.
- Every node logs tool, sandbox, timing, and outcome for the audit trail.
- Temporary extraction directories use `os.MkdirTemp` under a
  configurable work directory and are cleaned up after processing.

---

### 3.7 `internal/scan`

**Purpose:** Invoke Syft in library mode to catalog software components while
avoiding redundant direct scans wherever Syft has already produced explicit,
reusable package locations.

Operates on two distinct node types produced by the extract module:

1. **SyftNative leaves** — Syft is pointed at the *original file* (e.g. a JAR).
2. **Extracted directories** — Syft is pointed at the *extraction output directory*.

For a reader-oriented explanation of the same logic, see
[SCAN_APPROACH.md](SCAN_APPROACH.md).

**Interface:**

```go
type ScanResult struct {
    NodePath      string
    BOM           *cdx.BOM
    EvidencePaths map[string][]string
    Error         error
}

func ScanAll(ctx context.Context, root *extract.ExtractionNode, cfg config.Config) ([]ScanResult, error)

func FlattenEvidencePaths(result ScanResult) []string
```

**Implementation layout (current):**

- `scan.go` provides package-level overview and responsibility map.
- `types.go` defines shared scan types and package-level synchronization state.
- `scan_flow.go` contains tree traversal, target partitioning, and phase orchestration (`ScanAll`).
- `scan_parallel.go` implements worker scheduling, cancellation-aware execution, and progress aggregation.
- `scan_reuse.go` handles package-to-node ownership matching and syft-native result reuse.
- `scan_syft.go` encapsulates direct Syft invocation and Syft→CycloneDX conversion.
- `evidence.go` derives deterministic evidence paths and exposes evidence flattening helpers.

**Current scan flow:**

```go
1. Walk the extraction tree and collect scannable nodes.
2. Partition scan targets into:
   - extracted directories
   - Syft-native leaves
3. Scan extracted directories first.
4. Keep Syft's sorted package collection from those scans.
5. For each extracted-directory result:
   - compare each package location with descendant Syft-native child paths
   - if the package clearly belongs to such a child, reassign it there
   - keep only the remaining packages on the parent directory node
6. Rebuild child and parent BOMs from those package sets.
7. Directly scan only the Syft-native nodes that remain unresolved.
8. Attach deterministic evidence paths where extract-sbom can name the
   exact supporting artifact.
9. Return per-node results to the assembly module.
```

**Design decisions:**

- The distinction between SyftNative and extracted nodes is the core of the
  Syft-first principle: Syft's own catalogers take precedence for formats
  they understand (JAR, RPM, DEB, etc.). extract-sbom only extracts "dumb"
  container formats where Syft needs the files to be laid out on disk.
- Extracted directories are scanned before Syft-native child files so that
  one broader scan can often provide reusable package evidence for many nested
  native artifacts.
- Package reassignment is conservative. extract-sbom only reuses packages when
  Syft already reported a concrete package location that matches a descendant
  Syft-native node. If that proof is missing, the native file is scanned
  directly.
- Matching uses explicit real-path and access-path comparisons. When more than
  one child path matches, the most specific path wins. This keeps the behavior
  deterministic and avoids broad fuzzy attribution.
- Package collections are stored in sorted form before BOM rebuilding so that
  reused results stay deterministic.
- Syft's internal `sbom.SBOM` is serialized to CycloneDX JSON using
  Syft's own format encoder, then deserialized with `cyclonedx-go` to
  produce a standard `*cyclonedx.BOM`. This avoids coupling to Syft
  internals while preserving Syft's tested CycloneDX conversion.
- For JAR-like native archives, the scan module can derive a precise manifest
  evidence path and attach it as `extract-sbom:evidence-path` to support audit
  explanations without changing package identity.
- Runtime progress output is intentionally asymmetric: extracted-directory scans
  can still log detailed work, while short native-file scans are aggregated so
  large deliveries do not flood stderr with hundreds of low-value log lines.
- Scan errors are captured per node, not fatal to the overall run.
  The policy module decides how to handle them.

---

### 3.8 `internal/assembly`

**Purpose:** Merge per-node CycloneDX BOMs into one consolidated SBOM. Add
container-as-module components and the dependency graph.

**Interface:**

```go
// Assemble builds the final, unified CycloneDX BOM.
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cyclonedx.BOM, []SuppressionRecord, error)
```

**Assembly rules:**

1. Create a single top-level `Component` (type `Application`) for the input file itself.
   This component also represents the root `ExtractionNode`; the root is not
   emitted again as a second `File` component.
   - Apply `cfg.RootMetadata` to this component.
   - Set the component `Name` from `cfg.RootMetadata.Name`, or fall back to a
     deterministic value derived from the input filename.
   - Set the component `Version` from `cfg.RootMetadata.Version` when provided.
   - Set supplier / manufacturer information from
     `cfg.RootMetadata.Manufacturer` when provided.
   - Store `cfg.RootMetadata.DeliveryDate` as a root component property
     (`extract-sbom:delivery-date`).
   - Store each entry in `cfg.RootMetadata.Properties` as a root component
     property.
2. For every non-root `ExtractionNode`:
   - Create a `Component` (type `File`) representing the container artifact.
   - Set `BOMRef` to a deterministic identifier derived from the node path.
   - Attach any hashes (SHA-256 at minimum) computed during extraction.
   - Set the `extract-sbom:delivery-path` property to the node's full path
     within the delivery structure (e.g.
     `sw_delivery.zip/server/webserver.tar.gz/java/component.jar`).
   - If `node.Metadata` is non-nil (MSI), set the component's `Name` to
     `Metadata.ProductName`, `Version` to `Metadata.ProductVersion`, and
     generate a CPE from Manufacturer/ProductName/ProductVersion. Store
     `ProductCode`, `UpgradeCode`, and `Language` as component properties.
3. For every `ScanResult`:
   - Merge its `BOM.Components` into the unified component list.
   - Prefix each `BOMRef` with the node path to avoid collisions.
   - Set `extract-sbom:delivery-path` on each merged component to the nearest
     defensible physical artifact path in the original delivery, usually the
     scanned node path itself.
   - Add optional repeated `extract-sbom:evidence-path` properties when exact
     internal files or archive members used for identification are known.
4. Build `Dependencies`:
   - Each container component `dependsOn` its child container components
     and the packages discovered inside it.
5. Set `Compositions`:
   - `Complete` for fully extracted subtrees.
   - `Incomplete` for skipped, failed, or security-blocked nodes.
   - `Unknown` for nodes where Syft scan failed.
6. Set `Metadata.Tools` to include extract-sbom + Syft version info.
7. Encode to CycloneDX JSON via `cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON)`.
8. Return suppression records for every dropped component candidate so the
  report module can render deterministic suppression traceability.

**Design decisions:**

- BOMRef namespacing by node path guarantees uniqueness across merged BOMs.
- Root metadata is a first-class part of the consolidated SBOM and is sourced
  from CLI/config input, not inferred from nested package discovery.
- `extract-sbom:delivery-path` is the exact supplier-facing pointer to the
  physical artifact in the delivery; `extract-sbom:evidence-path` is optional
  supporting provenance for components derived from richer internal evidence.
- In the first implementation, `extract-sbom:evidence-path` is limited to cases
  where extract-sbom itself directly knows the exact supporting artifact, such
  as blocked archive members, direct manifest-based detections, or explicit
  internal container members. Generic Syft-derived packages do not require it.
- Composition completeness annotations enable downstream consumers to
  programmatically assess coverage without reading the audit report.
- The dependency graph models containment/origin (per DESIGN.md §5.2),
  not runtime linkage.

---

### 3.9 `internal/report`

**Purpose:** Generate the audit report from the processing state.

**Interface:**

```go
type ReportData struct {
    Input            InputSummary
    Config           config.Config
    Tree             *extract.ExtractionNode
    Scans            []scan.ScanResult
    PolicyDecisions  []policy.Decision
    SandboxInfo      SandboxSummary
    ProcessingIssues []ProcessingIssue
    StartTime        time.Time
    EndTime          time.Time
}

// GenerateHuman writes a human-readable Markdown report.
func GenerateHuman(data ReportData, lang string, w io.Writer) error

// GenerateMachine writes a structured JSON report.
func GenerateMachine(data ReportData, w io.Writer) error
```

**Implementation layout (current):**

- `report.go`: public API, input summary hashing, machine-report entry wiring, and shared report models.
- `report_i18n.go`: localized string catalog and language selection (`en`, `de`).
- `report_human_main.go`: human Markdown section orchestration, summary/progress sections, and processing-issues appendix.
- `report_suppression.go`: suppression appendix rendering and replacement-link resolution.
- `report_occurrence.go`: component occurrence indexing, quality filtering, and deterministic duplicate collapsing.
- `report_stats_tree.go`: extraction-tree rendering, residual-risk section, and phase statistics collectors.

**Required content (per DESIGN.md §10.4):**

- Input identification (filename, size, SHA-256, SHA-512)
- Configuration snapshot (limits, policy, mode, language)
- Root SBOM metadata, including which fields were supplied explicitly via CLI
- Interpretation mode and policy mode
- Full recursive extraction log with delivery paths
- Exact offending archive-member or file paths for blocked security events
- Tools and isolation used per extraction step
- SBOM modeling assumptions
- Container metadata extracted (e.g. MSI properties) and how it was used
- Optional evidence paths where component identification relied on internal
  files rather than a single physical artifact
- Whether unsafe override was active
- Unidentified binaries and other coverage gaps
- Summary of completeness and limitations
- Explicit residual risk statement

**Design decisions:**

- Human-readable output is Markdown (renders well in terminals, browsers, and
  PDF pipelines).
- Machine-readable output is JSON matching a documented schema.
- i18n uses compile-time string bundles (`translations` struct), not runtime
  template loading, to keep output deterministic and easy to audit.
- The report is generated after all processing is complete, from a read-only
  snapshot of the processing state.
- Processing-stage errors are captured as structured `ProcessingIssue` entries
  and included in both human and machine reports.
- The report distinguishes explicit root metadata input from derived defaults.
- A full migration to a template engine is intentionally deferred: the current
  report has high logic density (ordering, conditional sections, and
  provenance-driven tables), where direct writer functions are simpler and
  less error-prone for deterministic audit output.

---

### 3.10 `internal/policy`

**Purpose:** Evaluate limit violations and determine processing behavior.

**Interface:**

```go
type Decision struct {
    Trigger    string       // what limit was hit
    NodePath   string       // where in the tree
    Action     Action       // Abort | Skip | Continue
    Detail     string
}

type Engine struct { /* … */ }

func NewEngine(mode config.PolicyMode) *Engine
func (e *Engine) Evaluate(violation Violation) Decision
func (e *Engine) Decisions() []Decision
```

**Design decisions:**

- In `strict` mode, any violation produces `Abort`.
- In `partial` mode, the offending subtree is `Skip`-ped; processing
  continues elsewhere.
- Hard security failures (`safeguard.HardSecurityError`) always produce
  an abort of the affected subtree and elevate the final process status,
  regardless of policy mode.
- All decisions are collected for the audit report.

---

### 3.11 `internal/orchestrator`

**Purpose:** Coordinate the end-to-end processing pipeline.

**Interface:**

```go
type Result struct {
  ExitCode   ExitCode
  SBOMPath   string
  ReportPath string
  Error      error
}

func Run(ctx context.Context, cfg config.Config) Result
```

**Pipeline:**

```text
1. cfg.Validate()
2. Compute input file hash (SHA-256, SHA-512)
3. sandbox.Resolve(cfg) → (Sandbox, optional error)
4. extract.Extract(ctx, cfg.InputPath, cfg, sandbox) → ExtractionTree
5. scan.ScanAll(ctx, tree, cfg) → []ScanResult
6. assembly.Assemble(tree, scans, cfg) → *cyclonedx.BOM
7. Write SBOM to output file
8. report.Generate*(reportData, cfg, outputWriter)
9. Clean up temporary directories
10. Return exit code (0 = success, 1 = partial/incomplete, 2 = hard security incident or fatal runtime failure)
```

**Design decisions:**

- The orchestrator owns the lifecycle of temporary directories.
- Exit codes are deterministic and machine-parseable.
- Processing-stage errors (sandbox resolution, extraction, scan, assembly,
  output writing) are captured in `ReportData` before report generation,
  so failures are documented when report output succeeds.
- Once input validation has succeeded and the root extraction node exists,
  later hard security events no longer suppress final output generation.
- The orchestrator still writes a final SBOM and audit report, marks the
  affected subtree incomplete or security-blocked, and returns exit code `2`.

---

## 4. Data Flow Diagram

```text
                        ┌────────────────┐
                        │  Input File    │
                        └──────┬─────────┘
                               │
                    ┌──────────▼──────────┐
                    │  identify.Identify  │
                    │  (magic bytes +     │
                    │   Syft-native check)│
                    └──────────┬──────────┘
                               │ FormatInfo
                    ┌──────────▼──────────┐
                    │  extract.Extract    │◄───── safeguard.*
                    │  (recursive,        │◄───── sandbox.Run (7z only)
                    │   Syft-first)       │
                    └──────────┬──────────┘
                               │ ExtractionTree
                               │  (SyftNative leaves + extracted dirs)
                    ┌──────────▼──────────┐
                    │  scan.ScanAll       │  Syft library mode:
                    │                     │  - SyftNative → scan original file
                    │                     │  - Extracted  → scan output dir
                    └──────────┬──────────┘
                               │ []ScanResult (CycloneDX BOMs)
                    ┌──────────▼──────────┐
                    │  assembly.Assemble  │
                    └──────────┬──────────┘
                               │ *cyclonedx.BOM (unified)
              ┌────────────────┼────────────────┐
              ▼                                  ▼
     SBOM output file                  report.Generate*
     (CycloneDX JSON)                  (Markdown / JSON)
```

---

## 5. Key Architectural Decisions

### 5.1 Syft SBOM → CycloneDX Conversion Path

Syft internally uses its own `sbom.SBOM` type. To produce a CycloneDX BOM:

1. Encode `sbom.SBOM` to CycloneDX JSON bytes using Syft's built-in
   `cyclonedxjson` format encoder.
2. Decode those bytes with `cyclonedx-go`'s `NewBOMDecoder` into a
   standard `*cyclonedx.BOM`.

This approach avoids deep coupling to Syft's internal types while
leveraging Syft's well-tested CycloneDX conversion logic.

### 5.2 ExtractionTree as Central State

The `ExtractionNode` tree is the single source of truth for what was
processed, how, and with what outcome. Both the SBOM assembly and the
audit report are derived from this tree. This guarantees consistency
between the two outputs.

### 5.3 Hard Security vs. Policy Limits

Two distinct categories, enforced at different layers:

| Category | Examples | Layer | Overridable? |
|---|---|---|---|
| Hard security | Path traversal, symlink escape, special files | `safeguard` | Never |
| Resource limits | Depth, file count, total size, ratio, timeout | `extract` + `policy` | Via policy mode |

The `--unsafe` flag affects only the sandbox requirement, never the
hard security checks.

Hard security events therefore change the final status code and subtree
completeness, but do not suppress final output generation when the run has
already initialized the root processing state.

### 5.4 External Binaries: 7-Zip and unshield

7-Zip and unshield are the only external binary dependencies for
extraction. Their roles are strictly partitioned:

- **7-Zip** covers Microsoft CAB, MSI (OLE compound documents), plus
  7z and RAR inputs if encountered.
- **unshield** covers InstallShield proprietary CABs — a format that no
  other tool (including 7-Zip) can handle.

For ZIP and TAR — the dominant delivery formats — Go's standard library
provides mature, streaming extraction with per-entry validation callbacks.
This eliminates the need for an external extractor and the associated
sandbox overhead in the common case.

Both external binaries are optional at runtime. If either is missing, the
corresponding format is recorded as non-extractable in the SBOM. Both
are always invoked through the sandbox interface when available.

### 5.5 Syft-First Principle

Before extract-sbom extracts any file, it checks whether Syft has a
native cataloger for that file format. Syft-native formats (JAR, WAR,
RPM, DEB, wheel, egg, nupkg, apk, etc.) are passed directly to Syft
without extraction by extract-sbom.

This principle has three benefits:

1. **Correctness:** Syft's format-specific catalogers produce richer
   metadata (versions, licenses, dependencies) than scanning raw
   extracted files would.
2. **Efficiency:** No unnecessary extraction, no temporary files.
3. **Reduced attack surface:** Files that Syft understands natively
   are never parsed by extract-sbom's extraction code.

extract-sbom only extracts "dumb" container formats (ZIP, TAR, CAB, MSI)
that Syft cannot see through, in order to present their contents to Syft.

### 5.6 Downstream Vulnerability Matching (CPE / PURL)

extract-sbom does not perform CVE scanning itself (see DESIGN.md §1.3),
but the SBOM it produces must be immediately usable by tools like
**Grype** for vulnerability matching. Grype matches packages against
vulnerability databases using two identifiers:

1. **Package URL (PURL)** — the primary match path for ecosystem packages.
2. **CPE (Common Platform Enumeration)** — the match path for binaries
   and packages without ecosystem-specific identifiers.

**How Syft generates these identifiers.** Syft's catalogers produce both
PURLs and CPEs automatically:

| Cataloger type | PURL generation | CPE generation |
|---|---|---|
| Ecosystem catalogers (Java, npm, Python, Go, Ruby, .NET, etc.) | From package manifest metadata (pom.xml, package.json, requirements.txt, go.sum, etc.) | Heuristic: derived from package name + vendor heuristics, NVD dictionary lookup, or declared by package metadata |
| Binary classifier cataloger | n/a (no ecosystem) | Pattern-matched from known binary signatures (e.g. `openssl`, `curl`, `nginx`) |
| PE binary cataloger | n/a | Derived from Windows PE Version Info resource (ProductName, CompanyName, FileVersion) |
| ELF package cataloger | From `.note` section or embedded metadata | Derived from ELF metadata |

**Why the Syft-first principle is critical for vulnerability matching.**

If extract-sbom were to extract a JAR file into a flat directory and then
scan that directory, Syft would see individual `.class` files and a
`MANIFEST.MF` — it could still identify the Java package, but it would
lose the JAR-level context (filename, embedded pom.xml properties). By
passing the JAR directly to Syft, the Java cataloger gets the full
package metadata, produces the correct Maven PURL
(`pkg:maven/group/artifact@version`), and generates accurate CPEs.

The same applies to RPM, DEB, wheel, nupkg, and other ecosystem formats.

**Known limitations for raw binaries (DLLs, EXEs).**

When vendor deliveries contain standalone Windows binaries (not packaged
in an ecosystem format), Syft relies on:

- The **binary classifier** — a set of known signatures for common open-source
  libraries (OpenSSL, zlib, libcurl, etc.). If a binary matches, Syft
  produces a CPE with the correct vendor/product/version.
- The **PE binary cataloger** — reads the Version Info resource embedded
  in PE files. This yields a product name, company name, and version, from
  which Syft generates a CPE like
  `cpe:2.3:a:<company>:<product>:<version>:*:*:*:*:*:*:*`.

If a vendor strips Version Info metadata or delivers a binary that does
not match any known classifier, Syft cannot identify it. In this case:

- The file still appears as a `Component` in the SBOM (of type `File`,
  with SHA-256 hash), but without CPE or PURL.
- The audit report flags these files under "unidentified binaries"
  as a coverage gap.
- This is an inherent limitation of any SBOM tool and is not specific
  to extract-sbom's architecture.

**MSI name-mangling and CPE impact.** In physical mode, mangled internal
CAB entry names from MSI packages are passed to Syft as-is. Since Syft's
binary classifier and PE cataloger work on file *contents* (signatures
and embedded metadata), not on filenames, this does not affect CPE
generation. Filenames only matter for matching ecosystem package archives
(e.g. `foo-1.2.3.jar`), but those are handled via the Syft-first
principle and never reach the MSI extraction path.

### 5.8 Container Metadata as CPE Source

Syft cannot see the MSI database — it only sees the extracted files. But
the MSI itself represents a product with a vendor, name, and version.
extract-sbom reads the MSI Property table (via `mscfb` + MSI table parser)
and uses it to create a proper CPE for the MSI component:

```text
Input:  Manufacturer = "Contoso Ltd", ProductName = "Widget Server", ProductVersion = "3.2.1"
Output: cpe:2.3:a:contoso_ltd:widget_server:3.2.1:*:*:*:*:*:*:*
```

CPE vendor/product normalization follows the same rules as NVD:
lowercase, spaces replaced with underscores, special characters stripped.

This enrichment is critical because without it, the MSI component would
only appear as an opaque file with a SHA-256 hash — completely invisible
to vulnerability scanners like Grype.

Because the Property table is read directly from the original MSI, this
enrichment remains available even if 7-Zip is missing or MSI payload
extraction is otherwise skipped.

The same approach can be extended to other metadata-bearing container
formats in the future (e.g. InstallShield data files, NSIS installers)
if suitable parsers become available.

### 5.9 Delivery Path Traceability in SBOM

Every component in the consolidated SBOM carries a
`extract-sbom:delivery-path` property recording the nearest defensible
physical artifact path within the original delivery, e.g.:

```text
sw_delivery.zip/server/webserver.tar.gz/java/component.jar
```

This applies to:

- **Container components** created by extract-sbom (path = `ExtractionNode.Path`)
- **Package components** discovered by Syft (path = the physical delivery
  artifact from which the package was observed, typically the scanned node path)

If more precise internal provenance is available, extract-sbom additionally
stores one or more `extract-sbom:evidence-path` properties for the exact
manifest, archive member, or internal file that supported the identification.

For the first implementation, this is intentionally limited to provenance that
extract-sbom can name directly and deterministically. Generic Syft-derived
package evidence is not reconstructed unless the underlying scan data provides
it cleanly.

The property uses forward-slash separators regardless of host OS and is
always relative to the delivery root (the input file name). It enables
downstream consumers to locate any SBOM component within the original
delivery without re-extracting it.

### 5.10 Deterministic Output

- Components are sorted by BOMRef before encoding.
- Dependencies are sorted by Ref.
- Hashes are computed before any processing begins.
- Timestamps in the SBOM use the input file's modification time,
  not the current wall clock.

---

## 6. Implementation Plan

### Phase 1 — Foundation

**Goal:** Minimal end-to-end pipeline for a single non-nested archive.

1. Project scaffolding: `go.mod`, directory skeleton, CI (lint + test)
2. `config`: types, defaults, `Validate()`
3. `identify`: ZIP/TAR/GzipTAR detection via file magic bytes + Syft-native format list
4. `safeguard`: path validation, symlink check, ratio check
5. `extract`: single-level extraction for ZIP/TAR via Go stdlib (`archive/zip`, `archive/tar`)
6. `scan`: Syft library-mode integration (Syft-first: native leaves + extracted dirs)
7. `assembly`: minimal unified BOM with root component, deterministic BOMRefs,
  baseline `extract-sbom:delivery-path` properties for all produced components,
  and CLI-driven root metadata
8. `orchestrator`: wire everything, produce SBOM output file
9. `cmd/extract-sbom`: cobra CLI with core flags
10. Basic end-to-end test: ZIP → SBOM

### Phase 2 — Recursive Extraction and SBOM Modeling

**Goal:** Nested containers, dependency graph, container-as-module.

1. `extract`: recursive traversal with depth tracking
2. `assembly`: multi-BOM merge, container components, dependency graph,
   composition annotations
3. `policy`: strict/partial engine
4. `report`: basic human-readable Markdown report (EN only)
5. Extend delivery-path handling to nested container trees
6. Integration tests with nested archives (ZIP-in-ZIP, TAR.GZ-in-ZIP)

### Phase 3 — CAB/MSI and Sandbox

**Goal:** Cover Windows-native delivery formats under isolation.

1. `identify`: CAB/MSI detection via file-magic heuristics (`MSCF`, OLE `D0 CF 11 E0`)
2. `sandbox`: Bubblewrap implementation + passthrough fallback
3. `extract`: 7-Zip invocation via sandbox for CAB/MSI; post-extraction safeguard walk
4. MSI metadata extraction: OLE reader (`mscfb`) + MSI string-pool parser to read
  Property table directly from the original MSI → populate `ContainerMetadata`
  → CPE generation in assembly, independent of 7-Zip availability
5. `--unsafe` flag and associated warning logic
6. Extend delivery-path handling to CAB/MSI and sandboxed extraction paths
7. Integration tests with CAB and MSI test fixtures
8. Test sandbox availability detection and fallback behavior

### Phase 4 — Reporting and Modes

**Goal:** Full audit report, i18n, interpretation modes.

1. `report`: complete human-readable report with all required sections
2. `report`: machine-readable JSON schema and encoder
3. `report`: German language support via embedded templates
4. Installer-semantic interpretation mode: MSI table parsing via OLE reader,
  CAB name remapping (see §1.6); if reconstruction is not defensible,
  fall back to physical-mode paths plus explicit audit disclosure
5. `--report`, `--language`, `--mode` CLI flags
6. End-to-end tests for all report/mode combinations

### Phase 5 — Hardening

**Goal:** Production readiness.

1. Fuzz tests for archive parsing paths
2. Stress tests with large / deeply nested archives
3. RAR and 7z (as input formats) testing
4. macOS compatibility testing and fixes
5. Documentation review and finalization
6. Performance profiling and optimization if needed

---

## 7. Test Fixture Strategy

Test archives will be generated programmatically in Go test helpers where
possible (using `archive/zip`, `archive/tar`, etc.). For CAB and MSI
formats where no Go creation library exists, pre-built minimal test
fixtures will be committed to `testdata/`.

Fixture naming convention: `testdata/<format>/<scenario>.<ext>`
Examples:

- `testdata/zip/flat-three-files.zip`
- `testdata/zip/nested-zip-in-zip.zip`
- `testdata/cab/simple.cab`
- `testdata/msi/minimal.msi`
- `testdata/tar/gzip-nested-cab.tar.gz`

---

## 8. Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success: SBOM and report produced, all subtrees fully processed |
| 1 | Partial: some subtrees skipped or incomplete (partial policy) |
| 2 | Hard security incident or fatal runtime failure; if processing state exists, SBOM and report are still written with affected subtrees marked incomplete |
