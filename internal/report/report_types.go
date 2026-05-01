// This file defines all shared data types and rendering-helper types used
// throughout the report package, together with the canonical Markdown anchor
// constants referenced by the human report renderer.
package report

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

// InputSummary describes the inspected input artifact.
//
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
}

// componentOccurrence is one normalized, reportable view of an SBOM component
// with delivery/evidence provenance already flattened for Markdown output.
type componentOccurrence struct {
	// ObjectID is the CycloneDX BOM reference (bom-ref). It is expected to be
	// non-empty for stable anchoring.
	ObjectID string
	// ComponentType is the CycloneDX component type category.
	ComponentType cdx.ComponentType
	// PackageName is the normalized component name used in report output.
	PackageName string
	// Version is the normalized component version. Empty means unknown.
	Version string
	// PURL is the package URL. Empty means this occurrence cannot be matched by
	// package URL-based tooling.
	PURL string
	// CPE is the normalized CPE string when present on the SBOM component.
	// It is used for vulnerability-assessability decisions.
	CPE string
	// DeliveryPaths are logical supplier-delivery paths ("/"-separated,
	// leaf-most, deduplicated). Empty is invalid for indexed occurrences.
	DeliveryPaths []string
	// EvidencePaths are logical evidence file paths ("/"-separated, leaf-most,
	// deduplicated). Empty means no concrete evidence path was recorded.
	EvidencePaths []string
	// EvidenceSource is a plain-text generic evidence statement used when no
	// concrete EvidencePaths are available.
	EvidenceSource string
	// FoundBy identifies the cataloger/source module (for example
	// "java-archive-cataloger"). Empty means unknown.
	FoundBy string
}

// componentIndexStats tracks filtering and indexing counters used to explain
// why certain SBOM components are absent from the occurrence appendix.
type componentIndexStats struct {
	// TotalComponents is the number of BOM components seen before index filters.
	TotalComponents int
	// MissingDeliveryPath counts components skipped because they had no
	// extract-sbom:delivery-path property.
	MissingDeliveryPath int
	// FilteredContainerNodes counts structural extraction/container nodes that
	// are excluded from occurrence indexing.
	FilteredContainerNodes int
	// FilteredAbsolutePathNames counts low-quality components where Name looked
	// like an absolute filesystem path.
	FilteredAbsolutePathNames int
	// FilteredLowValueFileArtifacts counts file entries with insufficient package
	// identity metadata.
	FilteredLowValueFileArtifacts int
	// DuplicateMerged counts occurrences removed by duplicate-collapse rules.
	DuplicateMerged int
	// IndexedComponents is the final number of occurrence entries rendered.
	IndexedComponents int
	// IndexedWithPURL counts rendered occurrences with non-empty PURL.
	IndexedWithPURL int
	// IndexedWithoutPURL counts rendered occurrences with empty PURL.
	IndexedWithoutPURL int
	// IndexedWithEvidencePath counts rendered occurrences with concrete path
	// evidence.
	IndexedWithEvidencePath int
	// IndexedWithEvidenceSourceOnly counts rendered occurrences that have only a
	// generic evidence source text.
	IndexedWithEvidenceSourceOnly int
	// IndexedWithoutEvidence counts rendered occurrences with neither concrete
	// evidence paths nor generic evidence source.
	IndexedWithoutEvidence int
}

// extractionStats summarizes extraction outcomes and records relevant paths for
// each non-success category.
type extractionStats struct {
	// Total is the total number of extraction nodes visited.
	Total int
	// Extracted counts nodes with status extract.StatusExtracted.
	Extracted int
	// SyftNative counts nodes handled directly by Syft-native extraction paths.
	SyftNative int
	// Failed counts nodes with terminal extraction failure.
	Failed int
	// Skipped counts nodes skipped by policy/limits.
	Skipped int
	// ToolMissing counts nodes requiring unavailable helper tools.
	ToolMissing int
	// SecurityBlocked counts nodes blocked by security safeguards.
	SecurityBlocked int
	// Pending counts nodes left in pending state.
	Pending int
	// Other counts nodes with an unknown/unmapped status.
	Other int
	// ExtensionFiltered counts files excluded by extension filter across all
	// visited extraction nodes.
	ExtensionFiltered int
	// ExtensionFilteredPaths lists logical paths excluded by extension filter.
	// Values are plain text and may contain duplicates before downstream sorting.
	ExtensionFilteredPaths []string
	// FailedPaths lists logical node paths with failed extraction status.
	FailedPaths []string
	// ToolMissingPaths lists logical node paths requiring unavailable tools.
	ToolMissingPaths []string
	// SecurityBlockedPaths lists logical node paths blocked by security checks.
	SecurityBlockedPaths []string
}

// scanStats summarizes per-node scan outcomes and scan-level coverage gaps.
type scanStats struct {
	// Total is the number of scan tasks in the run.
	Total int
	// Successful is the number of scan tasks without error.
	Successful int
	// Errors is the number of scan tasks with non-nil error.
	Errors int
	// TotalComponents is the sum of component counts over successful scan tasks.
	TotalComponents int
	// NoComponentTasks counts successful scans that produced zero components.
	NoComponentTasks int
	// ErrorPaths lists task node paths for scan failures.
	ErrorPaths []string
	// NoComponentPaths lists task node paths where scans succeeded but returned
	// no package identities.
	NoComponentPaths []string
}

// suppressionStats groups assembly suppression records by normalization reason.
type suppressionStats struct {
	// FSArtifacts counts suppressions flagged as filesystem artifacts.
	FSArtifacts int
	// LowValueFiles counts suppressions flagged as low-value file artifacts.
	LowValueFiles int
	// WeakDuplicate counts suppressions where a stronger sibling record exists.
	WeakDuplicate int
	// PURLDuplicate counts suppressions collapsed by package identity (PURL).
	PURLDuplicate int
}

// policyStats aggregates policy engine decisions for summary tables.
type policyStats struct {
	// Total is the number of policy decisions emitted.
	Total int
	// Continue is the number of decisions with ActionContinue.
	Continue int
	// Skip is the number of decisions with ActionSkip.
	Skip int
	// Abort is the number of decisions with ActionAbort.
	Abort int
}

// processingEntry is a flattened log row used in the processing-issues table.
type processingEntry struct {
	// Source is the producer category: "pipeline", "extraction", or "scan".
	Source string
	// Location is a stage name or logical node path, depending on Source.
	Location string
	// Detail is plain-text diagnostic content.
	Detail string
}

// reportSection defines one TOC entry and heading anchor in the human report.
type reportSection struct {
	// title is the localized section heading text (plain text).
	title string
	// anchor is the HTML/Markdown anchor id without leading '#'.
	anchor string
	// level encodes nesting depth in the TOC and heading hierarchy.
	// Valid values: 0 (##), 1 (###), 2 (####).
	level int
}

const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

	anchorHowToUse               = "how-to-use-this-report"
	anchorMethodOverview         = "method-at-a-glance"
	anchorAppendix               = "appendix"
	anchorInputFile              = "input-file"
	anchorConfig                 = "configuration"
	anchorExtensionFilter        = "extension-filter"
	anchorRootMetadata           = "root-sbom-metadata"
	anchorSandbox                = "sandbox-configuration"
	anchorSummary                = "summary"
	anchorProcessingErrors       = "processing-errors"
	anchorResidualRisk           = "residual-risk-and-limitations"
	anchorPolicy                 = "policy-decisions"
	anchorComponentIndex         = "component-occurrence-index"
	anchorComponentsWithPURL     = "components-with-purl"
	anchorComponentsWithoutPURL  = "components-without-purl"
	anchorSuppression            = "component-normalization"
	anchorSuppressionFSArtifacts = "suppression-fs-artifacts"
	anchorSuppressionLowValue    = "suppression-low-value-file-artifacts"
	anchorScan                   = "scan-results"
	anchorScanNoPackageIDs       = "scan-tasks-without-package-identities"
	anchorExtraction             = "extraction-log"
)
