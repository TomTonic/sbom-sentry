// Package report generates audit reports from the processing state.
// It supports human-readable Markdown output and machine-readable JSON output,
// in English or German. The report documents everything that was processed,
// how, and with what limitations — enabling a third party to assess the
// completeness and reliability of the inspection.
package report

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// InputSummary describes the input file for the report.
type InputSummary struct {
	Filename string
	Size     int64
	SHA256   string
	SHA512   string
}

// SandboxSummary describes the sandbox configuration used.
type SandboxSummary struct {
	Name      string
	Available bool
	UnsafeOvr bool // whether --unsafe was used
}

// ProcessingIssue captures a non-nil error encountered in a pipeline stage.
// The orchestrator collects these so reports document failures deterministically.
type ProcessingIssue struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// ReportData holds all information needed to generate the audit report.
// It is a read-only snapshot of the processing state taken after all
// extraction, scanning, and assembly is complete.
type ReportData struct { //nolint:revive // stuttering is acceptable for clarity
	Input            InputSummary
	Generator        buildinfo.Info
	Config           config.Config
	Tree             *extract.ExtractionNode
	Scans            []scan.ScanResult
	PolicyDecisions  []policy.Decision
	SandboxInfo      SandboxSummary
	ProcessingIssues []ProcessingIssue
	StartTime        time.Time
	EndTime          time.Time
	BOM              *cdx.BOM
	SBOMPath         string
	// Suppressions records every component that assembly removed from the SBOM
	// during normalization or deduplication. The report must document each one.
	Suppressions []assembly.SuppressionRecord
}

// componentOccurrence is one normalized, reportable view of an SBOM component
// with delivery/evidence provenance already flattened for Markdown output.
type componentOccurrence struct {
	ObjectID       string
	ComponentType  cdx.ComponentType
	PackageName    string
	Version        string
	PURL           string
	DeliveryPaths  []string
	EvidencePaths  []string
	EvidenceSource string
	FoundBy        string
}

// componentIndexStats tracks filtering and indexing counters used to explain
// why certain SBOM components are absent from the occurrence appendix.
type componentIndexStats struct {
	TotalComponents               int
	MissingDeliveryPath           int
	FilteredContainerNodes        int
	FilteredAbsolutePathNames     int
	FilteredLowValueFileArtifacts int
	DuplicateMerged               int
	IndexedComponents             int
	IndexedWithPURL               int
	IndexedWithoutPURL            int
	IndexedWithEvidencePath       int
	IndexedWithEvidenceSourceOnly int
	IndexedWithoutEvidence        int
}

// extractionStats summarizes extraction outcomes and records relevant paths for
// each non-success category.
type extractionStats struct {
	Total                  int
	Extracted              int
	SyftNative             int
	Failed                 int
	Skipped                int
	ToolMissing            int
	SecurityBlocked        int
	Pending                int
	Other                  int
	ExtensionFiltered      int
	ExtensionFilteredPaths []string

	FailedPaths          []string
	ToolMissingPaths     []string
	SecurityBlockedPaths []string
}

// scanStats summarizes per-node scan outcomes and scan-level coverage gaps.
type scanStats struct {
	Total            int
	Successful       int
	Errors           int
	TotalComponents  int
	NoComponentTasks int
	ErrorPaths       []string
	NoComponentPaths []string
}

// suppressionStats groups assembly suppression records by normalization reason.
type suppressionStats struct {
	FSArtifacts   int
	LowValueFiles int
	WeakDuplicate int
	PURLDuplicate int
}

// policyStats aggregates policy engine decisions for summary tables.
type policyStats struct {
	Total    int
	Continue int
	Skip     int
	Abort    int
}

// processingEntry is a flattened log row used in the processing-issues table.
type processingEntry struct {
	Source   string
	Location string
	Detail   string
}

// reportSection defines one TOC entry and heading anchor in the human report.
type reportSection struct {
	title  string
	anchor string
	level  int // 0 = main section (##), 1 = subsection (###), 2 = sub-subsection (####)
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

// ComputeInputSummary computes the file hashes and metadata for the input file.
// This is called once by the orchestrator before any processing begins.
//
// Parameters:
//   - path: the filesystem path to the input file
//
// Returns an InputSummary with filename, size, SHA-256, and SHA-512 hashes,
// or an error if the file cannot be read.
func ComputeInputSummary(path string) (InputSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: open input: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: stat input: %w", err)
	}

	h256 := sha256.New()
	h512 := sha512.New()
	w := io.MultiWriter(h256, h512)

	if _, err := io.Copy(w, f); err != nil {
		return InputSummary{}, fmt.Errorf("report: hash input: %w", err)
	}

	return InputSummary{
		Filename: info.Name(),
		Size:     info.Size(),
		SHA256:   hex.EncodeToString(h256.Sum(nil)),
		SHA512:   hex.EncodeToString(h512.Sum(nil)),
	}, nil
}

// GenerateHuman writes a human-readable Markdown audit report to the writer.
// The report follows the structure required by DESIGN.md §10.4.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - lang: the output language ("en" or "de")
//   - w: the writer to write the Markdown report to
//
// Returns an error if writing fails.
func GenerateHuman(data ReportData, lang string, w io.Writer) error {
	t := getTranslations(lang)
	sections := reportSections(t)
	occurrences, indexStats := collectComponentOccurrences(data.BOM)
	extStats := collectExtractionStats(data.Tree)
	scnStats := collectScanStats(data.Scans)
	polStats := collectPolicyStats(data.PolicyDecisions)
	fmt.Fprintf(w, "# %s\n\n", t.title)
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	// Executive summary and reader guidance.
	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, data, extStats, scnStats, polStats, indexStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.howToUseSection, anchorHowToUse)
	writeHowToUseReport(w, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
	writeMethodOverview(w, t)
	fmt.Fprintln(w)

	// Actionable limitations and known blind spots.
	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, data, extStats, scnStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, data, extStats, scnStats, indexStats, t)
	fmt.Fprintln(w)

	// Appendix: complete raw audit trail.
	writeSectionHeading(w, t.appendixSection, anchorAppendix)
	fmt.Fprintln(w, t.appendixLead)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, occurrences, indexStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
	writeSuppressionReport(w, data.Suppressions, data.BOM, t)
	fmt.Fprintln(w)

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	writeSectionHeading(w, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, data.Config.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, data.Config.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, data.Config.Language)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, data.Config.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, data.Config.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(data.Config.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
	fmt.Fprintln(w)

	// Extension filter section: configured list and files excluded in this run.
	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, data, extStats, t)
	fmt.Fprintln(w)

	// Root SBOM metadata.
	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, data, t)

	// Sandbox information.
	writeSectionHeading(w, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
	if data.SandboxInfo.UnsafeOvr {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, data.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	fmt.Fprintln(w, t.scanSectionLead)
	fmt.Fprintln(w)
	for _, sr := range data.Scans {
		evidencePaths := scan.FlattenEvidencePaths(sr)
		switch {
		case sr.Error != nil:
			fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
		case sr.BOM != nil && sr.BOM.Components != nil:
			fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
			for _, evidencePath := range evidencePaths {
				fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, evidencePath)
			}
		default:
			fmt.Fprintf(w, "- **%s**: %s\n", sr.NodePath, t.noComponents)
		}
	}
	fmt.Fprintln(w)
	writeScanNoPackageIdentitiesSubsection(w, scnStats, t)
	fmt.Fprintln(w)

	// Extraction log.
	writeSectionHeading(w, t.extractionSection, anchorExtraction)
	writeExtractionTree(w, data.Tree, 0, t)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", t.endOfReport)

	return nil
}

// GenerateMachine writes a structured JSON audit report to the writer.
// The JSON schema matches the human-readable report sections for
// downstream automation.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - w: the writer to write the JSON report to
//
// Returns an error if writing fails.
func GenerateMachine(data ReportData, w io.Writer) error {
	report := machineReport{
		SchemaVersion: "1.0.0",
		Input:         data.Input,
		Generator: machineGenerator{
			Version:  data.Generator.Version,
			Revision: data.Generator.Revision,
			Time:     data.Generator.Time,
			Modified: data.Generator.Modified,
			Display:  data.Generator.String(),
		},
		Config: machineConfig{
			PolicyMode:    data.Config.PolicyMode.String(),
			InterpretMode: data.Config.InterpretMode.String(),
			Language:      data.Config.Language,
			Limits: machineLimits{
				MaxDepth:     data.Config.Limits.MaxDepth,
				MaxFiles:     data.Config.Limits.MaxFiles,
				MaxTotalSize: data.Config.Limits.MaxTotalSize,
				MaxEntrySize: data.Config.Limits.MaxEntrySize,
				MaxRatio:     data.Config.Limits.MaxRatio,
				Timeout:      data.Config.Limits.Timeout.String(),
			},
		},
		RootMetadata: machineRootMetadata{
			Manufacturer: data.Config.RootMetadata.Manufacturer,
			Name:         data.Config.RootMetadata.Name,
			Version:      data.Config.RootMetadata.Version,
			DeliveryDate: data.Config.RootMetadata.DeliveryDate,
			Properties:   data.Config.RootMetadata.Properties,
		},
		Sandbox: machineSandbox{
			Name:      data.SandboxInfo.Name,
			Available: data.SandboxInfo.Available,
			Unsafe:    data.SandboxInfo.UnsafeOvr,
		},
		Extraction: buildMachineTree(data.Tree),
		Scans:      buildMachineScans(data.Scans),
		Decisions:  buildMachineDecisions(data.PolicyDecisions),
		Issues:     data.ProcessingIssues,
		StartTime:  data.StartTime.UTC().Format(time.RFC3339),
		EndTime:    data.EndTime.UTC().Format(time.RFC3339),
		Duration:   data.EndTime.Sub(data.StartTime).String(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// --- Machine-readable report types ---

// machineReport is the JSON root schema written by GenerateMachine.
type machineReport struct {
	SchemaVersion string              `json:"schemaVersion"`
	Input         InputSummary        `json:"input"`
	Generator     machineGenerator    `json:"generator"`
	Config        machineConfig       `json:"config"`
	RootMetadata  machineRootMetadata `json:"rootMetadata"`
	Sandbox       machineSandbox      `json:"sandbox"`
	Extraction    *machineNode        `json:"extraction"`
	Scans         []machineScan       `json:"scans"`
	Decisions     []machineDecision   `json:"decisions"`
	Issues        []ProcessingIssue   `json:"issues,omitempty"`
	StartTime     string              `json:"startTime"`
	EndTime       string              `json:"endTime"`
	Duration      string              `json:"duration"`
}

// machineConfig captures the runtime configuration snapshot for machine output.
type machineConfig struct {
	PolicyMode    string        `json:"policyMode"`
	InterpretMode string        `json:"interpretMode"`
	Language      string        `json:"language"`
	Limits        machineLimits `json:"limits"`
}

// machineGenerator represents extract-sbom build metadata shown in JSON output.
type machineGenerator struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

// machineLimits is the serialized representation of configured safety limits.
type machineLimits struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

// machineRootMetadata stores root component metadata supplied or derived.
type machineRootMetadata struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// machineSandbox captures sandbox availability and unsafe override state.
type machineSandbox struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Unsafe    bool   `json:"unsafe"`
}

// machineNode is one extraction-tree node in machine report format.
type machineNode struct {
	Path         string         `json:"path"`
	Format       string         `json:"format"`
	Status       string         `json:"status"`
	StatusDetail string         `json:"statusDetail,omitempty"`
	Tool         string         `json:"tool,omitempty"`
	SandboxUsed  string         `json:"sandboxUsed,omitempty"`
	Duration     string         `json:"duration,omitempty"`
	EntriesCount int            `json:"entriesCount,omitempty"`
	TotalSize    int64          `json:"totalSize,omitempty"`
	Children     []*machineNode `json:"children,omitempty"`
}

// machineScan is one flattened scan result entry for machine output.
type machineScan struct {
	NodePath       string   `json:"nodePath"`
	ComponentCount int      `json:"componentCount"`
	EvidencePaths  []string `json:"evidencePaths,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// machineDecision is one policy-engine decision in machine-readable form.
type machineDecision struct {
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

// buildMachineTree converts the extraction tree to the JSON report node model.
func buildMachineTree(node *extract.ExtractionNode) *machineNode {
	if node == nil {
		return nil
	}

	mn := &machineNode{
		Path:         node.Path,
		Format:       node.Format.Format.String(),
		Status:       node.Status.String(),
		StatusDetail: node.StatusDetail,
		Tool:         node.Tool,
		SandboxUsed:  node.SandboxUsed,
		Duration:     node.Duration.String(),
		EntriesCount: node.EntriesCount,
		TotalSize:    node.TotalSize,
	}

	for _, child := range node.Children {
		mn.Children = append(mn.Children, buildMachineTree(child))
	}

	return mn
}

// buildMachineScans projects scan results into a stable machine-report schema.
func buildMachineScans(scans []scan.ScanResult) []machineScan {
	result := make([]machineScan, len(scans))
	for i, s := range scans {
		ms := machineScan{NodePath: s.NodePath}
		if s.Error != nil {
			ms.Error = s.Error.Error()
		}
		if s.BOM != nil && s.BOM.Components != nil {
			ms.ComponentCount = len(*s.BOM.Components)
		}
		ms.EvidencePaths = scan.FlattenEvidencePaths(s)
		result[i] = ms
	}
	return result
}

// buildMachineDecisions converts policy decisions to machine-report entries.
func buildMachineDecisions(decisions []policy.Decision) []machineDecision {
	result := make([]machineDecision, len(decisions))
	for i, d := range decisions {
		result[i] = machineDecision{
			Trigger:  d.Trigger,
			NodePath: d.NodePath,
			Action:   d.Action.String(),
			Detail:   d.Detail,
		}
	}
	return result
}
