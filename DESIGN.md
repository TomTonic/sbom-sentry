# sbom-sentry — Design Specification

## 1. Purpose and Context

### 1.1 Purpose
sbom-sentry is a tool for the **standardized incoming inspection of software deliveries**.
Its primary function is to make complex vendor deliveries auditable, reproducible,
and suitable for downstream vulnerability assessment.

Given exactly one delivery file as input, sbom-sentry produces:

1. A **single, consolidated Software Bill of Materials (SBOM)**  
   - Default format: **CycloneDX JSON**
2. A **formal audit report** explaining what was processed, how, and with which limitations

The input is intentionally restricted to **one file per run**. The file type may be
ZIP, TAR, compressed TAR, MSI, or another supported delivery/container format.

The tool is designed for procurement, compliance, and security assurance contexts,
including dispute resolution with suppliers.

### 1.2 Problem Statement
Software vendors frequently deliver products in deeply nested or installer-based formats:
ZIP files containing CABs, MSIs, further ZIPs, and similar constructs.

Without controlled unpacking, SBOM generation and CVE analysis produce incomplete or misleading results.
sbom-sentry addresses this by combining **safe recursive extraction** with **explicit SBOM modeling**
of container artifacts and their contents.

### 1.3 Non-Goals
- Performing CVE scanning (e.g., via Grype) is **explicitly excluded**
- No malware or virus scanning — sbom-sentry inspects delivery structure and
  software components, but does not assess whether any content is malicious
- No execution or dynamic analysis of delivered software
- No online or service-based operation model

---

## 2. Platforms and Execution Modes

### 2.1 Supported Platforms
- **Linux** (mandatory)
- **macOS** (optional, best-effort target)

macOS support must only be added if it does not significantly complicate
the overall design or compromise safety guarantees.

### 2.2 Execution Modes
- Native execution is the primary mode
- Containerized execution is optional and intended for reproducibility
- A container runtime must **not** be a hard prerequisite

### 2.3 Container Environment
If provided, container images must be based on **Alpine Linux** and act as
a convenience wrapper, not as a mandatory runtime dependency.

---

## 3. Core Processing Model

### 3.1 End-to-End Flow
1. Validate the input file (existence, supported format, size, cryptographic hash)
2. Prepare an isolated working context
3. Recursively analyze the delivery contents:
   - Identify container formats
   - Apply controlled extraction where applicable
4. Invoke **Syft** (in library mode where possible) to catalog software components
5. Merge all findings into one consolidated SBOM
6. Produce a detailed audit report

### 3.2 Determinism
For a given input archive and configuration:
- SBOM structure must be reproducible
- Dependency relationships must be stable
- Non-deterministic behavior must be avoided or explicitly documented

---

## 4. Recursive Extraction Semantics

### 4.1 Scope of Extraction
Recursive extraction applies **only to container formats not directly supported by Syft**.

Examples include:
- ZIP, CAB, MSI, 7z, TAR variants
- Arbitrary nesting combinations thereof

Formats already handled by Syft (e.g., directory trees or recognized ecosystems)
are passed directly to Syft without forced unpacking.

### 4.2 Depth-First, Auditable Traversal
Extraction proceeds recursively until a stopping condition is met:
- Configured depth limit
- Resource or safety limit
- Explicit policy decision

Every extraction attempt must be recorded, including:
- Input container
- Extraction tool used
- Outcome and reason

### 4.3 Syft-First Principle
Formats that Syft already understands natively (e.g. JAR, RPM, DEB, wheel,
nupkg, apk) must be passed directly to Syft without extraction by sbom-sentry.
sbom-sentry only extracts "dumb" container formats (ZIP, TAR, CAB, MSI) that
Syft cannot see through.

This ensures:
- Richer metadata from Syft's format-specific catalogers
- Correct PURL and CPE generation for ecosystem packages
- Reduced attack surface (fewer files parsed by sbom-sentry)

### 4.4 Extraction Interpretation Modes
The system shall support at least two configurable interpretation modes:

- **physical**: model only artifacts that are directly present or can be materially extracted
- **installer-semantic** (default): additionally model installer-derived relationships and
   reconstructed contents when they can be derived with defensible confidence

The selected mode must be included in the audit report and, where relevant, in SBOM metadata.

### 4.5 Special Handling: CAB Files from Setup.exe/MSI Contexts

Vendor deliveries frequently use setup.exe wrappers that internally unpack CAB files, sometimes in combination with MSI installers. These CAB files may exhibit name mangling or non-standard filenames due to legacy packaging tools.

sbom-sentry must:
- Detect and extract CAB files from setup.exe/MSI contexts, including nested scenarios.
- Restore original filenames and directory structures as accurately as possible.
- Ensure that MSI-referenced CAB contents are represented according to installer logic.
- Document any name mangling or extraction ambiguities in both the SBOM and audit report.

This applies recursively for multi-layered delivery structures.

---

## 5. SBOM Semantics (CycloneDX)

### 5.1 Container-as-Module Principle
Every container artifact encountered:
- Is represented as a **first-class SBOM component**
- Exists independently of extraction success
- Acts as the provenance anchor for its extracted contents

### 5.2 Dependency Graph
Relationships between containers and their contents are expressed via
a **dependency graph** within the SBOM.

This graph:
- Represents containment and origin, not runtime linkage
- Is fully machine-readable
- Does not require any visual (DOT/graphical) representation

### 5.3 Delivery Path Traceability
Every component in the SBOM must carry at least one provenance reference into
the original delivery structure.

The primary reference is the exact physical artifact path, expressed relative to
the delivery root and including all nesting levels, e.g.:

    sw_delivery.zip/server/webserver.tar.gz/java/component.jar

This physical artifact reference is stored as a CycloneDX component property
(`sbom-sentry:delivery-path`). It is the main pointer used to show a supplier
the exact defective or vulnerable artifact within the delivered package.

If a component is derived from richer evidence than a single physical artifact
(for example a package inferred from a manifest inside a JAR), the SBOM may
add one or more optional provenance references such as
`sbom-sentry:evidence-path` for the specific internal files or archive members
that support the identification.

This model ensures:
- Every component has a stable, defensible pointer back into the original delivery
- File and container components point to the exact physical artifact in question
- Logically derived packages can retain additional evidence without pretending
  they always map 1:1 to a single file
- The audit log can preserve the exact blocked or suspicious archive member path
  for dispute resolution

### 5.4 Container Metadata Enrichment
Container formats that carry structured metadata about their contents must be
parsed for that metadata, even in physical mode. The extracted metadata is used
to enrich the SBOM component representing the container with accurate
identifiers (CPE, PURL) for downstream vulnerability matching.

The primary case is **MSI packages**, whose Property table contains:
- `Manufacturer` (required) → CPE vendor
- `ProductName` (required) → CPE product
- `ProductVersion` (required) → CPE version
- `UpgradeCode` (optional) → correlates related product releases

These fields directly map to a CPE
(`cpe:2.3:a:<manufacturer>:<productname>:<version>:*:*:*:*:*:*:*`) and
potentially a generic PURL. Without this metadata, the MSI component would
appear in the SBOM as an opaque file with only a hash — invisible to
vulnerability scanners.

For MSI, metadata extraction is a direct read of the MSI database and must not
depend on whether payload extraction via 7-Zip is available. Even if the MSI's
internal files cannot be unpacked, the MSI component itself shall still be
represented in the SBOM with the best available product metadata.

This principle extends to any future container format that provides
structured product metadata.

### 5.5 Partial and Failed Extraction
If extraction fails or is restricted:
- The container component remains in the SBOM
- The SBOM and report must clearly indicate the limitation
- Downstream consumers must be able to assess resulting coverage gaps
- Hard-security-blocked subtrees remain represented as incomplete or
  security-blocked parts of the final SBOM whenever the overall run can still
  complete and write outputs

---

## 6. Safety and Resource Limits

### 6.1 Default Limits
Unless overridden, the following defaults apply:

- Maximum recursion depth: 6
- Maximum file count: 200,000
- Maximum total uncompressed size: 20 GiB
- Maximum single extracted entry: 2 GiB
- Maximum compression ratio: 150
- Per-extraction timeout: 60 seconds

All limits must be configurable.

### 6.2 Zip-Bomb and Abuse Protection
The extraction logic must robustly prevent:
- Zip-bomb style amplification
- Path traversal (absolute paths, `..` segments)
- Symlink escapes
- Materialization of special files (devices, pipes)
- Inheritance of unsafe permissions

### 6.3 Hard Security Events
Hard security violations — path traversal, symlink escape, special file
materialization — are **never** overridable, regardless of any CLI flag or
configuration. They abort the affected extraction subtree immediately.

If the overall orchestration can still continue, sbom-sentry shall still write
the final SBOM and audit report. The affected subtree is then represented as
incomplete or security-blocked, and the process exits with a non-success status.
The audit report must always document the exact offending path or archive member
that caused the block.

### 6.4 Explicit Unsafe Override Mode
If the preferred technical isolation mechanism is unavailable, the operator may explicitly opt into
an unsafe recursive extraction mode via a dedicated command-line parameter.

This mode:
- Is intended only for controlled environments and forensic fallback use
- Affects **only** the sandbox isolation requirement; hard security checks
  (§6.3) remain fully enforced
- Must never silently activate
- Must be highlighted prominently in the audit output and machine-readable report metadata

---

## 7. Policy Model

### 7.1 Policy Modes
Policy determines behavior when limits are reached:

- **strict** (default): abort processing, document fully
- **partial**: skip offending subtree, continue elsewhere, document clearly

### 7.2 Policy Transparency
All policy decisions must be explicitly recorded in the audit report,
including their impact on SBOM completeness.

---

## 8. Sandbox and Isolation

### 8.1 Isolation Principle
All extraction tools must be executed in an isolated environment whenever feasible.

Suitable lightweight mechanisms include:
- Bubblewrap
- Firejail
- gVisor
- Kata Containers
- Wasmtime (for WASI-compatible tools)

No specific mechanism is mandated, but:
- Docker must **not** be assumed
- Isolation failures must be detectable and reportable
- The concrete isolation mechanism is a solution design decision and must be documented,
  including fallback behavior when it is unavailable

---

## 9. Toolchain Constraints

### 9.1 Programming Language
All relevant code must be written in **Go**.

### 9.2 External Dependencies
- Dependencies on external binaries and libraries must be kept minimal
- The concrete selection of helper tools is a solution design decision and must be documented
- **7-Zip** is the preferred extractor for Microsoft CAB, MSI, and related formats
- **unshield** is the required extractor for InstallShield proprietary CABs
- **Syft** is mandatory, preferably used in library mode
- External extraction tools are optional at runtime; if missing, the corresponding
  formats are recorded as non-extractable in the SBOM rather than causing a fatal error
- Direct metadata reads from supported container formats (for example MSI
  product metadata) should remain available even when payload extraction tools
  are missing

---

## 10. Reporting and Localization

### 10.1 Audit Report Purpose
The report must enable a third party to answer:
- What was inspected?
- How was it processed?
- Which parts are complete, incomplete, or unverifiable?

### 10.2 Language Support
- Project language: English
- Report output language:
   - English (default)
   - German
- Additional languages must be easy to add

### 10.3 Report Representation Modes
The audit output shall support both of the following forms:

- **Human-readable report** (default)
- **Machine-readable report** for downstream automation

The chosen output mode or modes must be selectable explicitly.

### 10.4 Required Report Content
At minimum:
- Input identification (hashes, metadata)
- Configuration and limits
- Interpretation mode and policy mode
- Full recursive extraction log with delivery paths
- Exact offending archive-member or file paths for blocked security events
- Tools and isolation used
- SBOM modeling assumptions
- Container metadata extracted (e.g. MSI properties) and how it was used
- Optional evidence paths where component identification relied on internal
  files rather than a single physical artifact
- Whether unsafe override mode was active
- Unidentified binaries and other coverage gaps
- Summary of completeness and limitations
- Explicit statement of residual risk and uncertainty

---

## 11. Acceptance Criteria
sbom-sentry is complete when:

- One input file yields exactly one SBOM and one audit report
- Nested container formats are processed safely and recursively
- CAB and MSI contents are extractable and auditable
- Containers always appear as SBOM components
- Every SBOM component carries a delivery-path reference to its origin
- Optional evidence paths are retained where they materially strengthen
  traceability
- Container metadata (e.g. MSI properties) is extracted and used for CPE enrichment
- MSI container metadata remains available even when payload extraction is not
  possible
- Hard security findings still produce a final SBOM and report whenever overall
  orchestration can continue, with affected subtrees marked incomplete
- Limits and policies are enforced and documented
- Native Linux execution is fully supported
- Results are reproducible and defensible