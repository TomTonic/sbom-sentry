package json

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// ReportV2 is the top-level canonical JSON report payload for schema 2.0.0.
//
// In slice 1 this is intentionally a skeleton model that establishes the
// stable envelope and migration hooks. Entities/projections are populated in
// later slices.
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

type reportSchemaV2 struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generatedAt"`
}

type runV2 struct {
	RunID     string `json:"runId"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
	Duration  string `json:"duration"`
	ExitCode  int    `json:"exitCode"`
}

type inputSummaryV2 struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
}

type generatorV2 struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

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

type rootMetadataV2 struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

type limitsV2 struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

type passwordInfoV2 struct {
	Count             int  `json:"count"`
	SensitiveRedacted bool `json:"sensitiveRedacted"`
}

type runtimeV2 struct {
	Sandbox      sandboxV2      `json:"sandbox"`
	ToolVersions toolVersionsV2 `json:"toolVersions"`
	Warnings     []warningV2    `json:"warnings"`
}

type sandboxV2 struct {
	Name           string `json:"name"`
	Available      bool   `json:"available"`
	UnsafeOverride bool   `json:"unsafeOverride"`
}

type toolVersionsV2 struct {
	SevenZip   string `json:"sevenZip,omitempty"`
	Unshield   string `json:"unshield,omitempty"`
	Unsquashfs string `json:"unsquashfs,omitempty"`
	Grype      string `json:"grype,omitempty"`
	GrypeDB    string `json:"grypeDb,omitempty"`
}

type warningV2 struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	RelatedNodeID string `json:"relatedNodeId,omitempty"`
}

type rawV2 struct {
	ExtractionTreeRaw   *extract.ExtractionNode      `json:"extractionTreeRaw"`
	ScansRaw            []rawScanV2                  `json:"scansRaw"`
	BOMRaw              *cdx.BOM                     `json:"bomRaw"`
	VulnerabilitiesRaw  *vulnscan.Result             `json:"vulnerabilitiesRaw"`
	PolicyDecisionsRaw  []policy.Decision            `json:"policyDecisionsRaw"`
	ProcessingIssuesRaw []ProcessingIssue            `json:"processingIssuesRaw"`
	SuppressionsRaw     []assembly.SuppressionRecord `json:"suppressionsRaw"`
	ArtifactPaths       artifactPathsV2              `json:"artifactPaths"`
}

type rawScanV2 struct {
	NodePath      string              `json:"nodePath"`
	BOM           *cdx.BOM            `json:"bom,omitempty"`
	EvidencePaths map[string][]string `json:"evidencePaths,omitempty"`
	Error         string              `json:"error,omitempty"`
}

type artifactPathsV2 struct {
	SBOMPath           string `json:"sbomPath"`
	MarkdownReportPath string `json:"markdownReportPath,omitempty"`
	JSONReportPath     string `json:"jsonReportPath,omitempty"`
	HTMLReportPath     string `json:"htmlReportPath,omitempty"`
	SARIFReportPath    string `json:"sarifReportPath,omitempty"`
}

type nodeEntityV2 struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Status   string   `json:"status"`
	ParentID string   `json:"parentId,omitempty"`
	ChildIDs []string `json:"childIds,omitempty"`
}

type scanTaskEntityV2 struct {
	ID           string   `json:"id"`
	NodeID       string   `json:"nodeId,omitempty"`
	NodePath     string   `json:"nodePath"`
	ComponentIDs []string `json:"componentIds,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type componentEntityV2 struct {
	ID      string `json:"id"`
	BOMRef  string `json:"bomRef,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Type    string `json:"type,omitempty"`
}

type packageGroupEntityV2 struct {
	ID           string   `json:"id"`
	PURL         string   `json:"purl"`
	ComponentIDs []string `json:"componentIds"`
}

type vulnerabilityEntityV2 struct {
	ID              string `json:"id"`
	VulnerabilityID string `json:"vulnerabilityId"`
	ComponentID     string `json:"componentId,omitempty"`
	Severity        string `json:"severity,omitempty"`
	BOMRef          string `json:"bomRef,omitempty"`
}

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

type policyDecisionEntityV2 struct {
	ID       string `json:"id"`
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath,omitempty"`
	NodeID   string `json:"nodeId,omitempty"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
}

type issueEntityV2 struct {
	ID      string `json:"id"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type projectionRowV2 struct {
	SourceRefs       []string `json:"sourceRefs"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`
}

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

type projectionsV2 struct {
	Generic  genericProjectionV2  `json:"generic"`
	Markdown markdownProjectionV2 `json:"markdown"`
	HTML     htmlProjectionV2     `json:"html"`
}

type genericProjectionV2 struct {
	Summary           map[string]any    `json:"summary"`
	ExtractionRows    []projectionRowV2 `json:"extractionRows"`
	VulnerabilityRows []projectionRowV2 `json:"vulnerabilityRows"`
	IssueRows         []projectionRowV2 `json:"issueRows"`
	ComponentIndex    []projectionRowV2 `json:"componentIndex"`
}

type markdownProjectionV2 struct {
	Sections []projectionRowV2 `json:"sections"`
	TOC      []projectionRowV2 `json:"toc"`
	Anchors  []projectionRowV2 `json:"anchors"`
}

type htmlProjectionV2 struct {
	SummaryCards []projectionRowV2 `json:"summaryCards"`
	TableModels  []projectionRowV2 `json:"tableModels"`
}

type integrityV2 struct {
	Counts                 integrityCountsV2 `json:"counts"`
	DanglingReferenceCount int               `json:"danglingReferenceCount"`
	ValidationState        string            `json:"validationState"`
	ValidationErrors       []string          `json:"validationErrors"`
}

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

type compatibilityV2 struct {
	LegacyAliasesUsed legacyAliasesV2 `json:"legacyAliasesUsed"`
	MigrationHints    []string        `json:"migrationHints"`
}

type legacyAliasesV2 struct {
	ReportSelectionAlias string   `json:"reportSelectionAlias,omitempty"`
	DeprecatedFlagsUsed  []string `json:"deprecatedFlagsUsed,omitempty"`
}
