// Package model defines the shared report contracts used across report outputs
// and the root report facade.
package model

import (
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// ToolVersions contains version strings for external tools used during processing.
// Empty strings indicate tools that were not used or could not be detected.
type ToolVersions struct {
	SevenZip   string
	Unshield   string
	Unsquashfs string
	Grype      string
	GrypeDB    string
}

// InputSummary describes the inspected input artifact.
// Field constraints:
//   - All hash fields use lowercase hexadecimal encoding.
//   - Size is the exact byte count from os.FileInfo and is never negative.
//   - Empty string values indicate missing input metadata and should not occur
//     in normal orchestrator-driven report generation.
type InputSummary struct {
	// Filename is the base name of the inspected file (no directory prefix).
	// It is copied from os.FileInfo.Name and is plain text.
	Filename string
	// Size is the input size in bytes. Valid range: >= 0.
	Size int64
	// SHA256 is the lowercase hex-encoded SHA-256 digest (64 chars).
	SHA256 string
	// SHA512 is the lowercase hex-encoded SHA-512 digest (128 chars).
	SHA512 string
}

// SandboxSummary describes runtime sandbox behavior for this run.
type SandboxSummary struct {
	// Name identifies the sandbox strategy in plain text (for example
	// "bubblewrap", "nsjail", "passthrough"). It can be empty if unknown.
	Name string
	// Available reports whether the configured sandbox backend was detected and
	// usable at runtime.
	Available bool
	// UnsafeOvr is true when the user explicitly disabled sandbox isolation with
	// --unsafe. This is independent from Available.
	UnsafeOvr bool
}

// ProcessingIssue captures a non-nil error encountered in a pipeline stage.
// The orchestrator collects these so reports document failures deterministically.
type ProcessingIssue struct {
	// Stage is a stable stage identifier (for example "assembly", "scan",
	// "extract"). It is plain text and intended for filtering/grouping.
	Stage string `json:"stage"`
	// Message is the human-readable error detail from the producing module.
	// It is plain text (not Markdown) and may include wrapped upstream errors.
	Message string `json:"message"`
}

// ReportData holds all information needed to generate the audit report.
// It is a read-only snapshot of the processing state taken after all
// extraction, scanning, and assembly is complete.
type ReportData struct { //nolint:revive // stuttering is acceptable for clarity
	// Input is the immutable input fingerprint for this run.
	Input InputSummary
	// Generator is extract-sbom build metadata (version/revision/time/dirty).
	Generator buildinfo.Info
	// Config is the effective runtime configuration snapshot used for processing.
	Config config.Config
	// Tree is the extraction result tree root. Nil means extraction did not
	// produce a root node.
	Tree *extract.ExtractionNode
	// Scans contains one entry per submitted scan task. It may be empty.
	Scans []scan.ScanResult
	// Vulnerabilities contains optional Grype-based enrichment data.
	Vulnerabilities *vulnscan.Result
	// PolicyDecisions contains all policy outcomes in chronological processing
	// order. It may be empty.
	PolicyDecisions []policy.Decision
	// SandboxInfo captures the sandbox mode that was active during this run.
	SandboxInfo SandboxSummary
	// ProcessingIssues contains pipeline-level issues that are not represented
	// solely by extraction or scan status fields. It may be empty.
	ProcessingIssues []ProcessingIssue
	// StartTime is the run start timestamp.
	StartTime time.Time
	// EndTime is the run end timestamp. EndTime should be >= StartTime.
	EndTime time.Time
	// BOM is the assembled final CycloneDX BOM used for component sections.
	// Nil means no final BOM was produced.
	BOM *cdx.BOM
	// SBOMPath is the output path to the written SBOM artifact. It is plain text
	// and may be empty when no SBOM file was written.
	SBOMPath string
	// Suppressions records every component that assembly removed from the SBOM
	// during normalization or deduplication. The report must document each one.
	Suppressions []assembly.SuppressionRecord
	// ToolVersions contains version information for external tools used during
	// extraction and scanning. Tools that were not used have empty version strings.
	ToolVersions ToolVersions
}
