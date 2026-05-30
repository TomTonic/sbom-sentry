package json

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
)

// ReportV2 is the top-level canonical JSON report payload for schema 2.0.0.
//
// It captures the complete audit state from a single tool run: the raw orchestrator
// snapshot (raw), normalized entity objects (entities), renderer-oriented projection
// views (projections), and reference integrity metrics (integrity).
type ReportV2 struct {
	Schema        reportSchemaV2   `json:"schema"`
	Run           runV2            `json:"run"`
	Input         inputSummaryV2   `json:"input"`
	Generator     generatorV2      `json:"generator"`
	Config        configSnapshotV2 `json:"config"`
	Runtime       runtimeV2        `json:"runtime"`
	Raw           rawV2            `json:"raw"`
	Entities      entitiesV2       `json:"entities"`
	Projections   projectionsV2    `json:"projections"`
	Integrity     integrityV2      `json:"integrity"`
	Compatibility compatibilityV2  `json:"compatibility"`
}

// reportSchemaV2 identifies the report schema and the moment it was generated.
type reportSchemaV2 struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generatedAt"`
}

// runV2 records execution timing and the deterministic run identifier.
// RunID is derived from immutable input data so that identical runs produce the same ID.
type runV2 struct {
	RunID     string `json:"runId"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
	Duration  string `json:"duration"`
	ExitCode  int    `json:"exitCode"`
}

// inputSummaryV2 holds the identity of the primary input artifact.
// SHA256 and SHA512 are hex-encoded and enable downstream verification.
type inputSummaryV2 struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
}

// generatorV2 describes the extract-sbom binary that produced this report.
type generatorV2 struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

// configSnapshotV2 is the fully expanded effective runtime configuration.
// All values reflect what the tool actually used, not what was specified on the CLI.
type configSnapshotV2 struct {
	SBOMFormat           string            `json:"sbomFormat"`
	PolicyMode           string            `json:"policyMode"`
	InterpretMode        string            `json:"interpretMode"`
	ReportSelection      string            `json:"reportSelection"`
	ProgressLevel        string            `json:"progressLevel"`
	Language             string            `json:"language"`
	MarkdownRenderEngine string            `json:"markdownRenderEngine"`
	MarkdownTemplateFile string            `json:"markdownTemplateFile,omitempty"`
	GrypeEnabled         bool              `json:"grypeEnabled"`
	Unsafe               bool              `json:"unsafe"`
	ParallelScanners     int               `json:"parallelScanners"`
	SkipExtensions       []string          `json:"skipExtensions,omitempty"`
	RootMetadata         rootMetadataV2    `json:"rootMetadata"`
	Limits               limitsV2          `json:"limits"`
	Passwords            passwordInfoV2    `json:"passwords"`
	Properties           map[string]string `json:"properties,omitempty"`
}

// rootMetadataV2 carries operator-supplied metadata for the top-level delivery component.
// These values describe the software from a procurement perspective and override auto-derived values.
type rootMetadataV2 struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// limitsV2 documents the resource and safety limits enforced during extraction.
type limitsV2 struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

// passwordInfoV2 records how many passwords were supplied without exposing them.
// SensitiveRedacted is always true; passwords are never written to the report.
type passwordInfoV2 struct {
	Count             int  `json:"count"`
	SensitiveRedacted bool `json:"sensitiveRedacted"`
}

// runtimeV2 captures the execution environment: sandbox status, external tool versions, and warnings.
type runtimeV2 struct {
	Sandbox      sandboxV2      `json:"sandbox"`
	ToolVersions toolVersionsV2 `json:"toolVersions"`
	Warnings     []warningV2    `json:"warnings"`
}

// sandboxV2 records whether a filesystem isolation sandbox was active for this run.
type sandboxV2 struct {
	Name           string `json:"name"`
	Available      bool   `json:"available"`
	UnsafeOverride bool   `json:"unsafeOverride"`
}

// toolVersionsV2 holds version strings for external binaries invoked during extraction and scanning.
type toolVersionsV2 struct {
	SevenZip   string `json:"sevenZip,omitempty"`
	Unshield   string `json:"unshield,omitempty"`
	Unsquashfs string `json:"unsquashfs,omitempty"`
	Grype      string `json:"grype,omitempty"`
	GrypeDB    string `json:"grypeDb,omitempty"`
}

// warningV2 is a single structured runtime warning emitted during the run.
type warningV2 struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	RelatedNodeID string `json:"relatedNodeId,omitempty"`
}

// vulnerabilityStateV2 records the overall outcome of vulnerability enrichment for this run.
// The values mirror vulnscan.State but are owned by the report schema; the mapping in
// toVulnerabilityResultV2 / fromVulnerabilityResultV2 decouples the two layers.
type vulnerabilityStateV2 string

// vulnerabilityCoverageV2 records the per-component coverage result from the vulnerability scan.
// The values mirror vulnscan.CoverageState and are converted at the report boundary.
type vulnerabilityCoverageV2 string

// vulnerabilityMatchV2 is one normalized vulnerability match keyed by SBOM bom-ref.
// It captures all fields emitted by Grype at schema 2.0.0; future Grype schema changes
// only require updating the conversion functions, not the report schema.
type vulnerabilityMatchV2 struct {
	VulnerabilityID string   `json:"vulnerabilityId"`
	Severity        string   `json:"severity"`
	CVSSScore       *float64 `json:"cvssScore,omitempty"`
	CVSSVersion     string   `json:"cvssVersion,omitempty"`
	CVSSVector      string   `json:"cvssVector,omitempty"`
	Description     string   `json:"description,omitempty"`
	Namespace       string   `json:"namespace,omitempty"`
	DataSource      string   `json:"dataSource,omitempty"`
	URLs            []string `json:"urls,omitempty"`
	FixState        string   `json:"fixState,omitempty"`
	FixVersions     []string `json:"fixVersions,omitempty"`
	Matcher         string   `json:"matcher,omitempty"`
	MatchType       string   `json:"matchType,omitempty"`
	ArtifactName    string   `json:"artifactName,omitempty"`
	ArtifactVersion string   `json:"artifactVersion,omitempty"`
	ArtifactType    string   `json:"artifactType,omitempty"`
	ArtifactPURL    string   `json:"artifactPurl,omitempty"`
	EPSS            *float64 `json:"epss,omitempty"`
	EPSSPercentile  *float64 `json:"epssPercentile,omitempty"`
	Risk            *float64 `json:"risk,omitempty"`
	KEV             *bool    `json:"kev,omitempty"`
}

// vulnerabilityIssueV2 captures a non-fatal enrichment diagnostic for report transparency.
type vulnerabilityIssueV2 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// vulnerabilityResultV2 is the canonical snapshot of vulnerability enrichment output.
// It is a schema-stable copy of vulnscan.Result; changes to the external scan package
// are isolated to the conversion functions toVulnerabilityResultV2 / fromVulnerabilityResultV2.
type vulnerabilityResultV2 struct {
	State            vulnerabilityStateV2               `json:"state"`
	Requested        bool                               `json:"requested"`
	GrypeVersion     string                             `json:"grypeVersion,omitempty"`
	DBSchemaVersion  string                             `json:"dbSchemaVersion,omitempty"`
	DBBuilt          string                             `json:"dbBuilt,omitempty"`
	DBUpdated        string                             `json:"dbUpdated,omitempty"`
	MatchesByBOMRef  map[string][]vulnerabilityMatchV2  `json:"matchesByBomRef,omitempty"`
	CoverageByBOMRef map[string]vulnerabilityCoverageV2 `json:"coverageByBomRef,omitempty"`
	Errors           []vulnerabilityIssueV2             `json:"errors,omitempty"`
}

// rawV2 is a near-1:1 snapshot of the orchestrator's output at the end of each pipeline stage.
// It is intended as a complete audit log; downstream consumers should prefer the normalized
// entities and projections sections for rendering.
type rawV2 struct {
	ExtractionTreeRaw   *extract.ExtractionNode      `json:"extractionTreeRaw"`
	ScansRaw            []rawScanV2                  `json:"scansRaw"`
	BOMRaw              *cdx.BOM                     `json:"bomRaw"`
	VulnerabilitiesRaw  *vulnerabilityResultV2       `json:"vulnerabilitiesRaw"`
	PolicyDecisionsRaw  []policy.Decision            `json:"policyDecisionsRaw"`
	ProcessingIssuesRaw []ProcessingIssue            `json:"processingIssuesRaw"`
	SuppressionsRaw     []assembly.SuppressionRecord `json:"suppressionsRaw"`
	ArtifactPaths       artifactPathsV2              `json:"artifactPaths"`
}

// rawScanV2 is the raw output of one Syft scan task on a single archive node.
type rawScanV2 struct {
	NodePath      string              `json:"nodePath"`
	BOM           *cdx.BOM            `json:"bom,omitempty"`
	EvidencePaths map[string][]string `json:"evidencePaths,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// artifactPathsV2 records the filesystem paths of all output artifacts produced by this run.
type artifactPathsV2 struct {
	SBOMPath           string `json:"sbomPath"`
	MarkdownReportPath string `json:"markdownReportPath,omitempty"`
	JSONReportPath     string `json:"jsonReportPath,omitempty"`
	HTMLReportPath     string `json:"htmlReportPath,omitempty"`
	SARIFReportPath    string `json:"sarifReportPath,omitempty"`
}

// nodeEntityV2 represents a single node in the extraction tree hierarchy.
// Each node corresponds to one archive or file processed by the extraction pipeline.
// ParentID and ChildIDs establish the acyclic tree structure; Status records the extraction outcome.
type nodeEntityV2 struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Status   string   `json:"status"`
	ParentID string   `json:"parentId,omitempty"`
	ChildIDs []string `json:"childIds,omitempty"`
}

// scanTaskEntityV2 represents one Syft scan task associated with a tree node.
// ComponentIDs links to the components discovered by this scan.
type scanTaskEntityV2 struct {
	ID           string   `json:"id"`
	NodeID       string   `json:"nodeId,omitempty"`
	NodePath     string   `json:"nodePath"`
	ComponentIDs []string `json:"componentIds,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// componentEntityV2 is a canonical software component normalized from the assembled BOM.
// BOMRef is the CycloneDX reference string; PURL is the package URL for cross-referencing.
type componentEntityV2 struct {
	ID      string `json:"id"`
	BOMRef  string `json:"bomRef,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Type    string `json:"type,omitempty"`
}

// packageGroupEntityV2 aggregates all componentEntityV2 occurrences that share the same
// package identity (PURL prefix). This is the primary grouping unit for vulnerability rendering.
type packageGroupEntityV2 struct {
	ID           string   `json:"id"`
	PURL         string   `json:"purl"`
	ComponentIDs []string `json:"componentIds"`
}

// vulnerabilityEntityV2 records one matched vulnerability against a specific component.
// ComponentID links to the affected componentEntityV2.
type vulnerabilityEntityV2 struct {
	ID              string `json:"id"`
	VulnerabilityID string `json:"vulnerabilityId"`
	ComponentID     string `json:"componentId,omitempty"`
	Severity        string `json:"severity,omitempty"`
	BOMRef          string `json:"bomRef,omitempty"`
}

// suppressionEntityV2 records a component that was suppressed during BOM normalization.
// ResolutionStatus and ResolutionReason indicate whether the suppressed and kept components
// could be resolved to entity IDs.
type suppressionEntityV2 struct {
	ID                     string `json:"id"`
	Reason                 string `json:"reason"`
	SuppressedComponentRef string `json:"suppressedComponentRef,omitempty"`
	SuppressedComponentID  string `json:"suppressedComponentId,omitempty"`
	KeptComponentName      string `json:"keptComponentName,omitempty"`
	KeptComponentFoundBy   string `json:"keptComponentFoundBy,omitempty"`
	KeptComponentID        string `json:"keptComponentId,omitempty"`
	ResolutionStatus       string `json:"resolutionStatus,omitempty"`
	ResolutionReason       string `json:"resolutionReason,omitempty"`
}

// policyDecisionEntityV2 captures one policy engine decision from the extraction run.
// NodeID links to the tree node that triggered the decision, if applicable.
type policyDecisionEntityV2 struct {
	ID       string `json:"id"`
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath,omitempty"`
	NodeID   string `json:"nodeId,omitempty"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
}

// issueEntityV2 records one processing issue surfaced during extraction or scanning.
type issueEntityV2 struct {
	ID      string `json:"id"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// projectionRowV2 is one renderer-facing projection row with back-references to source entities.
// SourceRefs must contain IDs of entities in the same report; the integrity validator enforces this.
type projectionRowV2 struct {
	SourceRefs       []string       `json:"sourceRefs"`
	ResolutionStatus string         `json:"resolutionStatus,omitempty"`
	ResolutionReason string         `json:"resolutionReason,omitempty"`
	Data             map[string]any `json:"data,omitempty"`
}

// entitiesV2 holds all normalized canonical entity collections for this report.
// Arrays are pre-sorted deterministically; ordinal positions are not stable across runs.
type entitiesV2 struct {
	Nodes           []nodeEntityV2           `json:"nodes"`
	ScanTasks       []scanTaskEntityV2       `json:"scanTasks"`
	Components      []componentEntityV2      `json:"components"`
	PackageGroups   []packageGroupEntityV2   `json:"packageGroups"`
	Vulnerabilities []vulnerabilityEntityV2  `json:"vulnerabilities"`
	Suppressions    []suppressionEntityV2    `json:"suppressions"`
	PolicyDecisions []policyDecisionEntityV2 `json:"policyDecisions"`
	Issues          []issueEntityV2          `json:"issues"`
}

// projectionsV2 holds renderer-oriented view models pre-computed from the entity layer.
// Renderers should consume these projections instead of processing raw or entity data directly.
type projectionsV2 struct {
	Generic  genericProjectionV2  `json:"generic"`
	Markdown markdownProjectionV2 `json:"markdown"`
	HTML     htmlProjectionV2     `json:"html"`
}

// genericProjectionV2 contains format-neutral projection views usable by any renderer.
type genericProjectionV2 struct {
	Summary           map[string]any    `json:"summary"`
	ExtractionRows    []projectionRowV2 `json:"extractionRows"`
	VulnerabilityRows []projectionRowV2 `json:"vulnerabilityRows"`
	IssueRows         []projectionRowV2 `json:"issueRows"`
	ComponentIndex    []projectionRowV2 `json:"componentIndex"`
}

// markdownProjectionV2 contains Markdown-specific projection views including TOC and anchors.
type markdownProjectionV2 struct {
	Sections []projectionRowV2 `json:"sections"`
	TOC      []projectionRowV2 `json:"toc"`
	Anchors  []projectionRowV2 `json:"anchors"`
}

// htmlProjectionV2 contains HTML-specific projection views for summary cards and table models.
type htmlProjectionV2 struct {
	SummaryCards []projectionRowV2 `json:"summaryCards"`
	TableModels  []projectionRowV2 `json:"tableModels"`
}

// integrityV2 holds the results of cross-reference validation over the entity and projection layers.
// A ValidationState of "warning" or "error" indicates dangling references or structural problems.
type integrityV2 struct {
	Counts                 integrityCountsV2 `json:"counts"`
	DanglingReferenceCount int               `json:"danglingReferenceCount"`
	ValidationState        string            `json:"validationState"`
	ValidationErrors       []string          `json:"validationErrors"`
}

// integrityCountsV2 records entity counts per collection, used to detect unexpected truncation.
type integrityCountsV2 struct {
	Nodes           int `json:"nodes"`
	ScanTasks       int `json:"scanTasks"`
	Components      int `json:"components"`
	PackageGroups   int `json:"packageGroups"`
	Vulnerabilities int `json:"vulnerabilities"`
	Suppressions    int `json:"suppressions"`
	PolicyDecisions int `json:"policyDecisions"`
	Issues          int `json:"issues"`
}

// compatibilityV2 tracks migration-relevant metadata such as deprecated flag usage.
type compatibilityV2 struct {
	LegacyAliasesUsed legacyAliasesV2 `json:"legacyAliasesUsed"`
	MigrationHints    []string        `json:"migrationHints"`
}

// legacyAliasesV2 records deprecated CLI flags or aliases used during this run.
type legacyAliasesV2 struct {
	DeprecatedFlagsUsed []string `json:"deprecatedFlagsUsed,omitempty"`
}
