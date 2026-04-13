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
	"path"
	"sort"
	"strings"
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

type scanStats struct {
	Total            int
	Successful       int
	Errors           int
	TotalComponents  int
	NoComponentTasks int
	ErrorPaths       []string
	NoComponentPaths []string
}

type suppressionStats struct {
	FSArtifacts   int
	LowValueFiles int
	WeakDuplicate int
	PURLDuplicate int
}

type policyStats struct {
	Total    int
	Continue int
	Skip     int
	Abort    int
}

type processingEntry struct {
	Source   string
	Location string
	Detail   string
}

type reportSection struct {
	title  string
	anchor string
}

const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

	anchorHowToUse              = "how-to-use-this-report"
	anchorMethodOverview        = "method-at-a-glance"
	anchorAppendix              = "appendix"
	anchorInputFile             = "input-file"
	anchorConfig                = "configuration"
	anchorExtensionFilter       = "extension-filter"
	anchorRootMetadata          = "root-sbom-metadata"
	anchorSandbox               = "sandbox-configuration"
	anchorSummary               = "summary"
	anchorProcessingErrors      = "processing-errors"
	anchorResidualRisk          = "residual-risk-and-limitations"
	anchorPolicy                = "policy-decisions"
	anchorComponentIndex        = "component-occurrence-index"
	anchorComponentsWithPURL    = "components-with-purl"
	anchorComponentsWithoutPURL = "components-without-purl"
	anchorSuppression           = "component-normalization"
	anchorScan                  = "scan-results"
	anchorExtraction            = "extraction-log"
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
	writeSuppressionReport(w, data.Suppressions, t)
	fmt.Fprintln(w)

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d bytes |\n", t.filesize, data.Input.Size)
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
	fmt.Fprintf(w, "| %s | %d bytes |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize)
	fmt.Fprintf(w, "| %s | %d bytes |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
	fmt.Fprintf(w, "| skip-extensions | %s |\n", configSkipExtensionsDisplay(data.Config.SkipExtensions))
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

type machineConfig struct {
	PolicyMode    string        `json:"policyMode"`
	InterpretMode string        `json:"interpretMode"`
	Language      string        `json:"language"`
	Limits        machineLimits `json:"limits"`
}

type machineGenerator struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

type machineLimits struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

type machineRootMetadata struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

type machineSandbox struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Unsafe    bool   `json:"unsafe"`
}

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

type machineScan struct {
	NodePath       string   `json:"nodePath"`
	ComponentCount int      `json:"componentCount"`
	EvidencePaths  []string `json:"evidencePaths,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type machineDecision struct {
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

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

// --- Translation support ---

type translations struct {
	title                            string
	inputSection                     string
	configSection                    string
	rootMetadataSection              string
	sandboxSection                   string
	extractionSection                string
	scanSection                      string
	scanSectionLead                  string
	scanTaskEvidenceLabel            string
	policySection                    string
	summarySection                   string
	residualRiskSection              string
	processingIssuesSection          string
	field                            string
	value                            string
	setting                          string
	filename                         string
	filesize                         string
	policyMode                       string
	interpretMode                    string
	language                         string
	maxDepth                         string
	maxFiles                         string
	maxTotalSize                     string
	maxEntrySize                     string
	maxRatio                         string
	timeout                          string
	progressLevel                    string
	generator                        string
	sandboxName                      string
	sandboxAvail                     string
	unsafeWarning                    string
	unsafeActive                     string
	tableOfContentsSection           string
	howToUseSection                  string
	methodOverviewSection            string
	appendixSection                  string
	componentIndexSection            string
	componentIndexLead               string
	noIndexedComponents              string
	objectID                         string
	packageName                      string
	version                          string
	purl                             string
	evidencePath                     string
	foundBy                          string
	noEvidenceRecorded               string
	processingTime                   string
	scanError                        string
	componentsFound                  string
	noComponents                     string
	deliveryPath                     string
	status                           string
	tool                             string
	duration                         string
	suppliedBy                       string
	derived                          string
	residualRiskText                 string
	residualRiskProfileLead          string
	residualRiskAbsenceHint          string
	residualRiskPURLCoverage         string
	residualRiskEvidenceCoverage     string
	residualRiskNoComponentTasks     string
	residualRiskFileArtifactCoverage string
	residualRiskExtractionGap        string
	residualRiskToolGap              string
	residualRiskScanGap              string
	residualRiskMoreDetails          string
	noPolicyDecisions                string
	noProcessingIssues               string
	summaryLead                      string
	summaryAssemblyMath              string
	summaryNextStepTemplate          string
	howToUseLead                     string
	howToUseStep1                    string
	howToUseStep2Template            string
	howToUseStep3                    string
	howToUseStep4Template            string
	methodLead                       string
	methodBulletTwoPhases            string
	methodBulletEvidence             string
	methodBulletDedup                string
	methodBulletTrust                string
	methodMoreDetails                string
	appendixLead                     string
	summaryExtraction                string
	summaryScan                      string
	summaryComponents                string
	summaryPolicies                  string
	summaryProcessingIssues          string
	summaryFindings                  string
	endOfReport                      string

	componentNormalizationSection  string
	componentNormalizationLead     string
	noSuppressions                 string
	suppressionReasonFSArtifact    string
	suppressionReasonLowValueFile  string
	suppressionReasonWeakDuplicate string
	suppressionReasonPURLDuplicate string
	suppressionReplacedBy          string

	extensionFilterSection              string
	extensionFilterLead                 string
	extensionFilterExtensionsLabel      string
	extensionFilterSkippedLabel         string
	noExtensionFilteredFiles            string
	componentIndexWithPURLSubsection    string
	componentIndexWithoutPURLSubsection string
}

func getTranslations(lang string) translations {
	switch lang {
	case "de":
		return translations{
			title:                            "extract-sbom Prüfbericht",
			inputSection:                     "Eingabedatei",
			configSection:                    "Konfiguration",
			rootMetadataSection:              "SBOM Stammdaten",
			sandboxSection:                   "Sandbox-Konfiguration",
			extractionSection:                "Extraktionsprotokoll",
			scanSection:                      "Scan-Task-Protokoll",
			policySection:                    "Richtlinienentscheidungen",
			summarySection:                   "Zusammenfassung",
			residualRiskSection:              "Restrisiko und Einschränkungen",
			processingIssuesSection:          "Verarbeitungsfehler",
			field:                            "Feld",
			value:                            "Wert",
			setting:                          "Einstellung",
			filename:                         "Dateiname",
			filesize:                         "Dateigröße",
			policyMode:                       "Richtlinienmodus",
			interpretMode:                    "Interpretationsmodus",
			language:                         "Sprache",
			maxDepth:                         "Maximale Tiefe",
			maxFiles:                         "Maximale Dateien",
			maxTotalSize:                     "Maximale Gesamtgröße",
			maxEntrySize:                     "Maximale Eintragsgröße",
			maxRatio:                         "Maximales Verhältnis",
			timeout:                          "Zeitlimit",
			progressLevel:                    "Fortschritt",
			generator:                        "extract-sbom Build",
			sandboxName:                      "Sandbox",
			sandboxAvail:                     "Verfügbar",
			unsafeWarning:                    "WARNUNG",
			unsafeActive:                     "Unsicherer Modus aktiv — keine Sandbox-Isolation",
			tableOfContentsSection:           "Inhaltsverzeichnis",
			howToUseSection:                  "So benutzt man diesen Bericht",
			methodOverviewSection:            "Verfahren im Kurzüberblick",
			appendixSection:                  "Anhang",
			componentIndexSection:            "Komponentenindex",
			componentIndexLead:               "Die Einträge sind nach Lieferpfad sortiert. Die Objekt-ID entspricht der bom-ref im SBOM und der artifact.id in Grype. `Delivery path` zeigt, wo die Komponente in der Lieferdatei vorkommt. `Evidence path` zeigt die konkrete Datei oder Metadatenquelle, auf der die Identifikation beruht. Wenn mehrere Delivery Paths unter einer Objekt-ID stehen, wurden identische PURLs bewusst zusammengeführt und alle konkreten Blattpfade beibehalten.",
			noIndexedComponents:              "Keine Komponenten-Vorkommen indexiert.",
			objectID:                         "Objekt-ID",
			packageName:                      "Paket",
			version:                          "Version",
			purl:                             "PURL",
			evidencePath:                     "Belegpfad",
			foundBy:                          "Erkannt durch",
			noEvidenceRecorded:               "kein komponentenspezifischer Beleg erfasst",
			processingTime:                   "Verarbeitungszeit",
			scanError:                        "Fehler:",
			componentsFound:                  "Komponenten gefunden",
			noComponents:                     "keine Komponenten gefunden",
			scanSectionLead:                  "Dies ist das Protokoll der einzelnen Scan-Aufgaben. Die hier aufgeführten Evidenzpfade sind task-bezogene Beobachtungen und können mehrere finale Komponenten abdecken. Die maßgebliche komponentenspezifische Evidenz steht im Komponentenindex.",
			scanTaskEvidenceLabel:            "Im Scan beobachtete Evidenz",
			deliveryPath:                     "Lieferpfad",
			status:                           "Status",
			tool:                             "Werkzeug",
			duration:                         "Dauer",
			suppliedBy:                       "Durch Benutzer angegeben",
			derived:                          "Automatisch abgeleitet",
			residualRiskText:                 "Die folgenden Punkte beschreiben Abdeckungsgrenzen und Auslegungsrisiken für die Verwendung des SBOM in der Schwachstellenbewertung:",
			residualRiskProfileLead:          "Das Verfahren ist manifest- und metadatenbasiert. Besonders belastbar sind Formate mit expliziten Paketmetadaten, etwa RPM, DEB oder Java-Archive mit Maven- bzw. Manifest-Metadaten. Schwächer ist die Abdeckung bei bloßen Dateien, gebündelten Kopien ohne Manifest und Windows-Binärdateien mit knappen oder fehlenden Versionsressourcen.",
			residualRiskAbsenceHint:          "Das Fehlen einer Komponente im SBOM ist kein Beleg dafür, dass der zugrunde liegende Code nicht vorhanden ist; es bedeutet nur, dass dafür keine verwertbare Paketmetadaten-Evidenz beobachtet wurde.",
			residualRiskPURLCoverage:         "%d von %d indexierten Komponenten-Vorkommen tragen eine PURL. %d indexierte Vorkommen haben keine PURL und lassen sich deshalb typischerweise nur eingeschränkt oder gar nicht automatisch gegen CVE-Datenbanken korrelieren.",
			residualRiskEvidenceCoverage:     "%d indexierte Vorkommen haben einen konkreten Evidenzpfad. %d stützen sich nur auf einen allgemeinen Evidenzhinweis, und %d haben keine zusätzliche Evidenzangabe über den Komponenten-Datensatz hinaus.",
			residualRiskNoComponentTasks:     "%d von %d erfolgreichen Scan-Aufgaben lieferten keine Paketidentität. Das bedeutet: Der Inhalt wurde gesehen, aber es war keine verwertbare Paketmetadaten-Evidenz vorhanden. Beispielaufgaben: %s.",
			residualRiskFileArtifactCoverage: "Syft erzeugte außerdem %d dateibezogene Rohfunde ohne belastbare Paketkoordinaten. Diese Einträge dokumentieren beobachtete Dateien, eignen sich aber nicht als eigenständige Grundlage für CVE-Abgleiche und werden deshalb nicht als Paketbefund geführt.",
			residualRiskExtractionGap:        "%d Extraktionsknoten konnten nicht vollständig verarbeitet werden. Beispiele: %s.",
			residualRiskToolGap:              "%d Extraktionsknoten erfordern nicht verfügbare Hilfswerkzeuge. Beispiele: %s.",
			residualRiskScanGap:              "%d Scan-Aufgaben schlugen fehl. Beispiele: %s.",
			residualRiskMoreDetails:          "Hintergrund zur Zuverlässigkeit der Paketerkennung: %s.",
			noPolicyDecisions:                "Keine Richtlinienentscheidungen protokolliert.",
			noProcessingIssues:               "Keine Verarbeitungsfehler protokolliert.",
			summaryLead:                      "Dieser Bericht dokumentiert die beobachteten Paketbefunde, ihre Nachverfolgbarkeit und die Verarbeitungsgrenzen eines einzelnen Prüfungsdurchlaufs über die gelieferte Datei. Er soll die technische Prüfung von SBOM-basierten Schwachstellenbefunden und die Reproduzierbarkeit der zugrunde liegenden Evidenz unterstützen.",
			summaryAssemblyMath:              "Die Assembly behielt nach Normalisierung und Deduplikation %d Paketkomponenten und fügte %d strukturelle Container-Komponenten hinzu. Dadurch entstehen insgesamt %d CycloneDX-Komponenten.",
			summaryNextStepTemplate:          "Ein sinnvoller Einstieg ist %s, anschließend die zugehörige Objekt-ID im %s.",
			howToUseLead:                     "Der folgende Ablauf zeigt exemplarisch, wie Ergebnisse eines externen Vulnerability-Scans mit dem SBOM und diesem Bericht korreliert werden können. Das JSON-Beispiel verwendet Grype, weil dort die SBOM-Objekt-ID erhalten bleibt; bei anderen Werkzeugen sind die sinngemäß entsprechenden Felder zu verwenden.",
			howToUseStep1:                    "Wenn eine Grype-JSON-Ausgabe vorliegt, extrahieren Sie die für die Triage relevanten Felder und filtern Sie zunächst auf hohe und kritische Befunde. Beispiel:",
			howToUseStep2Template:            "Öffnen Sie den %s und suchen Sie nach dem Wert aus `artifact_id`. Die Überschrift `### <artifact_id>` entspricht der `bom-ref` im SBOM und der `artifact.id` in Grype.",
			howToUseStep3:                    "Verwenden Sie `Delivery path`, um die Fundstelle in der Lieferdatei nachzuvollziehen. Verwenden Sie `Evidence path` oder den Evidenzhinweistext, um die konkrete Grundlage der Paketidentifikation zu benennen.",
			howToUseStep4Template:            "Wenn unter einer Objekt-ID mehrere Delivery Paths aufgeführt sind, beschreibt der Bericht mehrere physische Vorkommen derselben Paketidentität, die bewusst zu einer Komponente zusammengeführt wurden. Die Zusammenführungslogik ist in %s erläutert. Fragen zu Abdeckungsgrenzen lassen sich über %s und %s einordnen.",
			methodLead:                       "Hier steht nur die Kurzfassung. Die vollständige operator-orientierte Erläuterung steht in SCAN_APPROACH.md auf GitHub.",
			methodBulletTwoPhases:            "Die Lieferung wird zunächst entpackt und in konkrete Artefakte gegliedert. Anschließend werden Paketmetadaten aus extrahierten Verzeichnisbäumen und aus direkt lesbaren Paketdateien gesammelt.",
			methodBulletEvidence:             "Paketidentitäten werden nur dann behauptet, wenn dafür beobachtbare Evidenz vorliegt, etwa Paketmanifeste, JAR-Metadaten, MSI-Property-Tabellen oder Binär-Metadaten.",
			methodBulletDedup:                "Deduplikation ist nachvollziehbar: schwache Platzhalter und wiederholte PURLs werden entfernt, aber die überlebende Komponente behält die konkreten Blatt-Delivery- und Evidence-Pfade.",
			methodBulletTrust:                "Der Lauf ist deterministisch: Die Eingabedatei ist gehasht, die Lieferpfade sind stabil und Fehler oder Abdeckungsgrenzen werden explizit protokolliert statt verborgen.",
			methodMoreDetails:                "Vertiefung in SCAN_APPROACH.md:",
			appendixLead:                     "Die folgenden Abschnitte enthalten die vollständige Rohspur für Stichproben, vertiefte technische Prüfung und Belegexport. Sie sind bewusst ausführlich und werden typischerweise erst benötigt, wenn die relevante Objekt-ID oder der relevante Lieferpfad bereits feststeht.",
			summaryExtraction:                "Extraktion",
			summaryScan:                      "Scans",
			summaryComponents:                "Komponentenindex",
			summaryPolicies:                  "Richtlinienentscheidungen",
			summaryProcessingIssues:          "Verarbeitungsfehler",
			summaryFindings:                  "Wesentliche Befunde",
			endOfReport:                      "Ende des Berichts.",

			componentNormalizationSection:  "Komponentennormalisierung",
			componentNormalizationLead:     "Alle Komponenten, die aus dem SBOM entfernt wurden, sind hier mit Begründung aufgeführt. Dies gewährleistet die vollständige Nachverfolgbarkeit zwischen SBOM und Prüfbericht.",
			noSuppressions:                 "Keine Komponenten entfernt.",
			suppressionReasonFSArtifact:    "FS-Cataloger-Artefakt",
			suppressionReasonLowValueFile:  "Datei ohne Identifikationsmerkmale",
			suppressionReasonWeakDuplicate: "Schwaches Duplikat",
			suppressionReasonPURLDuplicate: "PURL-Duplikat",
			suppressionReplacedBy:          "Ersetzt durch",

			extensionFilterSection:              "Dateiendungsfilter",
			extensionFilterLead:                 "Die folgenden Dateiendungen sind so konfiguriert, dass sie von der rekursiven Extraktion und Syft-Analyse ausgeschlossen werden. Dateien, die diesen Endungen entsprechen, werden im Extraktionsprotokoll nicht aufgeführt und nicht auf Softwarekomponenten untersucht. Die vollständige Abdeckbarkeit der SBOM ist für gefilterte Dateien nicht gewährleistet.",
			extensionFilterExtensionsLabel:      "Konfigurierter Dateiendungsfilter",
			extensionFilterSkippedLabel:         "Durch diesen Filter ausgeschlossene Dateien",
			noExtensionFilteredFiles:            "In diesem Durchlauf wurden keine Dateien durch den Dateiendungsfilter ausgeschlossen.",
			componentIndexWithPURLSubsection:    "Komponenten mit PURL",
			componentIndexWithoutPURLSubsection: "Komponenten ohne PURL",
		}
	default:
		return translations{
			title:                            "extract-sbom Audit Report",
			inputSection:                     "Input File",
			configSection:                    "Configuration",
			rootMetadataSection:              "Root SBOM Metadata",
			sandboxSection:                   "Sandbox Configuration",
			extractionSection:                "Extraction Log",
			scanSection:                      "Scan Task Log",
			policySection:                    "Policy Decisions",
			summarySection:                   "Summary",
			residualRiskSection:              "Residual Risk and Limitations",
			processingIssuesSection:          "Processing Errors",
			field:                            "Field",
			value:                            "Value",
			setting:                          "Setting",
			filename:                         "Filename",
			filesize:                         "File size",
			policyMode:                       "Policy mode",
			interpretMode:                    "Interpretation mode",
			language:                         "Language",
			maxDepth:                         "Max depth",
			maxFiles:                         "Max files",
			maxTotalSize:                     "Max total size",
			maxEntrySize:                     "Max entry size",
			maxRatio:                         "Max ratio",
			timeout:                          "Timeout",
			progressLevel:                    "Progress",
			generator:                        "extract-sbom build",
			sandboxName:                      "Sandbox",
			sandboxAvail:                     "Available",
			unsafeWarning:                    "WARNING",
			unsafeActive:                     "Unsafe mode active — no sandbox isolation",
			tableOfContentsSection:           "Table of Contents",
			howToUseSection:                  "How To Use This Report",
			methodOverviewSection:            "Method At A Glance",
			appendixSection:                  "Appendix",
			componentIndexSection:            "Component Occurrence Index",
			componentIndexLead:               "Entries are sorted by delivery path. The object ID matches the SBOM bom-ref and Grype artifact.id. `Delivery path` shows where the component occurs in the supplier delivery. `Evidence path` shows the concrete file or metadata source that supported the identification. If several delivery paths appear under one object ID, identical PURLs were intentionally merged and every concrete leaf-most occurrence path was retained.",
			noIndexedComponents:              "No component occurrences indexed.",
			objectID:                         "Object ID",
			packageName:                      "Package",
			version:                          "Version",
			purl:                             "PURL",
			evidencePath:                     "Evidence path",
			foundBy:                          "Found by",
			noEvidenceRecorded:               "no component-specific evidence recorded",
			processingTime:                   "Processing time",
			scanError:                        "Error:",
			componentsFound:                  "components found",
			noComponents:                     "no components found",
			scanSectionLead:                  "This is a per-scan-task execution log. Evidence lines in this section are task-level observations and may cover several final components. The authoritative per-component evidence statements are in the Component Occurrence Index.",
			scanTaskEvidenceLabel:            "Observed evidence",
			deliveryPath:                     "Delivery path",
			status:                           "Status",
			tool:                             "Tool",
			duration:                         "Duration",
			suppliedBy:                       "User-supplied",
			derived:                          "Auto-derived",
			residualRiskText:                 "The following points describe coverage boundaries and interpretation risks that matter when the SBOM is used for vulnerability assessment:",
			residualRiskProfileLead:          "The method is manifest- and metadata-based. Reliability is highest for formats with explicit package metadata, such as RPM, DEB, or Java archives with Maven or manifest metadata. Coverage is weaker for plain files, bundled copies without manifests, and Windows binaries with sparse or missing VERSIONINFO.",
			residualRiskAbsenceHint:          "The absence of a component from the SBOM is not proof that the underlying code is absent; it means only that no usable package-metadata evidence was observed for it.",
			residualRiskPURLCoverage:         "%d of %d indexed component occurrences carry a PURL. %d indexed occurrences do not carry a PURL and therefore usually correlate poorly or not at all with vulnerability databases.",
			residualRiskEvidenceCoverage:     "%d indexed occurrences carry a concrete evidence path. %d rely only on a generic evidence-source statement, and %d have no additional evidence detail beyond the component record.",
			residualRiskNoComponentTasks:     "%d of %d successful scan tasks produced no package identities. This means the content was seen, but no usable package metadata was present. Example tasks: %s.",
			residualRiskFileArtifactCoverage: "Syft also emitted %d file-level records without actionable package coordinates. These records show that files were observed, but they do not by themselves support CVE matching and are therefore not listed as package findings.",
			residualRiskExtractionGap:        "%d extraction nodes could not be processed completely. Examples: %s.",
			residualRiskToolGap:              "%d extraction nodes require unavailable helper tools. Examples: %s.",
			residualRiskScanGap:              "%d scan tasks failed. Examples: %s.",
			residualRiskMoreDetails:          "Background on package-detection reliability: %s.",
			noPolicyDecisions:                "No policy decisions recorded.",
			noProcessingIssues:               "No processing issues recorded.",
			summaryLead:                      "This report documents the observed package findings, their traceability, and the processing limits of a single inspection run over the supplied delivery. Its purpose is to support technical review of SBOM-based vulnerability findings and reproducibility of the underlying evidence.",
			summaryAssemblyMath:              "Assembly retained %d package components after normalization and deduplication and added %d structural container components, resulting in %d CycloneDX components overall.",
			summaryNextStepTemplate:          "A practical starting point is %s, followed by the corresponding object in the %s.",
			howToUseLead:                     "The workflow below illustrates how results from an external vulnerability scan can be correlated with the SBOM and this report. The JSON example uses Grype because it preserves the SBOM object identifier; analogous fields can be taken from other tools.",
			howToUseStep1:                    "If Grype JSON output is available, extract the fields needed for triage and restrict the view to high and critical findings. Example:",
			howToUseStep2Template:            "Open the %s and search for the value from `artifact_id`. The heading `### <artifact_id>` corresponds to the SBOM `bom-ref` and to Grype `artifact.id`.",
			howToUseStep3:                    "Use `Delivery path` to locate the finding in the supplier delivery. Use `Evidence path` or the evidence-source text to identify the concrete manifest, metadata file, or cataloger basis behind the package identification.",
			howToUseStep4Template:            "If one object lists several delivery paths, the report is describing several physical occurrences that were consolidated into one package component because they share the same package identity. The consolidation logic is summarized in %s. Questions about coverage boundaries can be assessed with %s and %s.",
			methodLead:                       "This section is the compressed version. The full operator-oriented explanation lives in SCAN_APPROACH.md on GitHub.",
			methodBulletTwoPhases:            "The delivery is first unpacked and classified into concrete artifacts. Package metadata is then collected from extracted directory trees and from directly readable package files.",
			methodBulletEvidence:             "A package identity is asserted only when observable evidence exists, such as package manifests, JAR metadata, MSI property tables, or binary metadata.",
			methodBulletDedup:                "Deduplication is traceable: weak placeholders and repeated PURLs are removed, but the surviving component keeps the concrete leaf-most delivery and evidence paths.",
			methodBulletTrust:                "The run is deterministic: the input file is hash-pinned, logical delivery paths are stable, and errors or coverage limits are recorded instead of hidden.",
			methodMoreDetails:                "Deep links into SCAN_APPROACH.md:",
			appendixLead:                     "The sections below preserve the detailed audit trail for spot checks, deeper technical review, and evidence export. They are intentionally exhaustive and are usually only needed once the relevant object id or delivery path is already known.",
			summaryExtraction:                "Extraction",
			summaryScan:                      "Scans",
			summaryComponents:                "Component index",
			summaryPolicies:                  "Policy decisions",
			summaryProcessingIssues:          "Processing issues",
			summaryFindings:                  "Key findings",
			endOfReport:                      "End of report.",

			componentNormalizationSection:  "Component Normalization",
			componentNormalizationLead:     "Every component removed from the SBOM during normalization or deduplication is listed here with its reason. This ensures full traceability between the SBOM and the audit report.",
			noSuppressions:                 "No components removed.",
			suppressionReasonFSArtifact:    "FS-cataloger artifact",
			suppressionReasonLowValueFile:  "File with no identification metadata",
			suppressionReasonWeakDuplicate: "Weak duplicate",
			suppressionReasonPURLDuplicate: "PURL duplicate",
			suppressionReplacedBy:          "Replaced by",

			extensionFilterSection:              "Extension Filter",
			extensionFilterLead:                 "The following file extensions are configured to be excluded from recursive extraction and Syft scanning. Files matching these extensions are not examined for software components and are therefore not reflected in the component inventory. Full SBOM coverage cannot be guaranteed for filtered file types.",
			extensionFilterExtensionsLabel:      "Configured extension filter",
			extensionFilterSkippedLabel:         "Files excluded by this filter",
			noExtensionFilteredFiles:            "No files were excluded by the extension filter in this run.",
			componentIndexWithPURLSubsection:    "Components with PURL",
			componentIndexWithoutPURLSubsection: "Components without PURL",
		}
	}
}

func writeRootMetadata(w io.Writer, data ReportData, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.field, t.value, "Source")
	fmt.Fprintf(w, "|---|---|---|\n")

	rm := data.Config.RootMetadata

	nameSource := t.derived
	if rm.Name != "" {
		nameSource = t.suppliedBy
	}
	name := rm.Name
	if name == "" {
		name = data.Input.Filename
	}
	fmt.Fprintf(w, "| Name | %s | %s |\n", name, nameSource)

	if rm.Manufacturer != "" {
		fmt.Fprintf(w, "| Manufacturer | %s | %s |\n", rm.Manufacturer, t.suppliedBy)
	}
	if rm.Version != "" {
		fmt.Fprintf(w, "| Version | %s | %s |\n", rm.Version, t.suppliedBy)
	}
	if rm.DeliveryDate != "" {
		fmt.Fprintf(w, "| Delivery Date | %s | %s |\n", rm.DeliveryDate, t.suppliedBy)
	}

	propertyKeys := make([]string, 0, len(rm.Properties))
	for key := range rm.Properties {
		propertyKeys = append(propertyKeys, key)
	}
	sort.Strings(propertyKeys)
	for _, key := range propertyKeys {
		fmt.Fprintf(w, "| %s | %s | %s |\n", key, rm.Properties[key], t.suppliedBy)
	}
	fmt.Fprintln(w)
}

func reportSections(t translations) []reportSection {
	return []reportSection{
		{title: t.summarySection, anchor: anchorSummary},
		{title: t.howToUseSection, anchor: anchorHowToUse},
		{title: t.methodOverviewSection, anchor: anchorMethodOverview},
		{title: t.processingIssuesSection, anchor: anchorProcessingErrors},
		{title: t.residualRiskSection, anchor: anchorResidualRisk},
		{title: t.appendixSection, anchor: anchorAppendix},
		{title: t.componentIndexSection, anchor: anchorComponentIndex},
		{title: t.componentNormalizationSection, anchor: anchorSuppression},
		{title: t.inputSection, anchor: anchorInputFile},
		{title: t.configSection, anchor: anchorConfig},
		{title: t.extensionFilterSection, anchor: anchorExtensionFilter},
		{title: t.rootMetadataSection, anchor: anchorRootMetadata},
		{title: t.sandboxSection, anchor: anchorSandbox},
		{title: t.policySection, anchor: anchorPolicy},
		{title: t.scanSection, anchor: anchorScan},
		{title: t.extractionSection, anchor: anchorExtraction},
	}
}

func writeSectionHeading(w io.Writer, title, anchor string) {
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n## %s\n\n", anchor, title)
}

func writeTableOfContents(w io.Writer, sections []reportSection) {
	for _, section := range sections {
		fmt.Fprintf(w, "- [%s](#%s)\n", section.title, section.anchor)
	}
}

func sectionLink(title, anchor string) string {
	return fmt.Sprintf("[%s](#%s)", title, anchor)
}

func scanApproachLink(label, anchor string) string {
	return fmt.Sprintf("[%s](%s#%s)", label, scanApproachGitHubURL, anchor)
}

func collectSuppressionStats(suppressions []assembly.SuppressionRecord) suppressionStats {
	stats := suppressionStats{}
	for _, s := range suppressions {
		switch s.Reason {
		case assembly.SuppressionFSArtifact:
			stats.FSArtifacts++
		case assembly.SuppressionLowValueFile:
			stats.LowValueFiles++
		case assembly.SuppressionWeakDuplicate:
			stats.WeakDuplicate++
		case assembly.SuppressionPURLDuplicate:
			stats.PURLDuplicate++
		}
	}
	return stats
}

func writeHowToUseReport(w io.Writer, t translations) {
	componentIndexLink := sectionLink(t.componentIndexSection, anchorComponentIndex)
	normalizationLink := sectionLink(t.componentNormalizationSection, anchorSuppression)
	processingLink := sectionLink(t.processingIssuesSection, anchorProcessingErrors)
	riskLink := sectionLink(t.residualRiskSection, anchorResidualRisk)

	fmt.Fprintln(w, t.howToUseLead)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "1. %s\n\n", t.howToUseStep1)
	fmt.Fprintln(w, "```sh")
	fmt.Fprintln(w, "jq '.matches[] | select((.vulnerability.severity == \"High\") or (.vulnerability.severity == \"Critical\")) | {artifact_id: .artifact.id, package: .artifact.name, version: .artifact.version, vulnerability: .vulnerability.id, severity: .vulnerability.severity}' grype.json")
	fmt.Fprintln(w, "```")
	fmt.Fprintf(w, "2. %s\n", fmt.Sprintf(t.howToUseStep2Template, componentIndexLink))
	fmt.Fprintf(w, "3. %s\n", t.howToUseStep3)
	fmt.Fprintf(w, "4. %s\n", fmt.Sprintf(t.howToUseStep4Template, normalizationLink, processingLink, riskLink))
}

func writeMethodOverview(w io.Writer, t translations) {
	fmt.Fprintln(w, t.methodLead)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s\n", t.methodBulletTwoPhases)
	fmt.Fprintf(w, "- %s\n", t.methodBulletEvidence)
	fmt.Fprintf(w, "- %s\n", t.methodBulletDedup)
	fmt.Fprintf(w, "- %s\n", t.methodBulletTrust)
	fmt.Fprintln(w)
	fmt.Fprintf(
		w,
		"%s %s, %s, %s, %s, %s\n",
		t.methodMoreDetails,
		scanApproachLink("Two phases", "3-two-phases"),
		scanApproachLink("Scan detail", "7-how-the-scan-phase-works-in-detail"),
		scanApproachLink("Final SBOM build", "8-how-the-final-sbom-is-built"),
		scanApproachLink("Deduplication", "81-how-deduplication-works"),
		scanApproachLink("Package detection reliability", "6-package-detection-reliability"),
	)
}

func writePolicyDecisions(w io.Writer, decisions []policy.Decision, t translations) {
	if len(decisions) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noPolicyDecisions)
		return
	}

	for _, d := range decisions {
		fmt.Fprintf(w, "- **%s** at `%s`: %s -> %s\n", d.Trigger, d.NodePath, d.Detail, d.Action)
	}
}

func writeSummary(w io.Writer, data ReportData, ext extractionStats, scn scanStats, pol policyStats, idx componentIndexStats, t translations) {
	duration := data.EndTime.Sub(data.StartTime).Round(time.Millisecond)
	retainedPackages := scn.TotalComponents - len(data.Suppressions)
	if retainedPackages < 0 {
		retainedPackages = 0
	}
	structuralComponents := idx.TotalComponents - retainedPackages
	if structuralComponents < 0 {
		structuralComponents = 0
	}
	suppression := collectSuppressionStats(data.Suppressions)

	fmt.Fprintln(w, t.summaryLead)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "- %s: %s\n", t.processingTime, duration)
	fmt.Fprintf(
		w,
		"- %s: total=%d extracted=%d syft-native=%d failed=%d tool-missing=%d skipped=%d extension-filtered=%d ([details](#%s)) security-blocked=%d pending=%d\n",
		t.summaryExtraction,
		ext.Total,
		ext.Extracted,
		ext.SyftNative,
		ext.Failed,
		ext.ToolMissing,
		ext.Skipped,
		ext.ExtensionFiltered,
		anchorExtensionFilter,
		ext.SecurityBlocked,
		ext.Pending,
	)
	fmt.Fprintf(w, "- %s: total=%d successful=%d errors=%d components-found=%d\n", t.summaryScan, scn.Total, scn.Successful, scn.Errors, scn.TotalComponents)
	fmt.Fprintf(
		w,
		"- %s: %d raw -> removed %d (fs-artifacts=%d, low-value=%d, weak-duplicates=%d, purl-duplicates=%d) -> %d in BOM -> filtered %d (abs-path=%d, low-value=%d, merged=%d) -> indexed %d\n",
		t.summaryComponents,
		scn.TotalComponents,
		len(data.Suppressions),
		suppression.FSArtifacts,
		suppression.LowValueFiles,
		suppression.WeakDuplicate,
		suppression.PURLDuplicate,
		idx.TotalComponents,
		idx.FilteredAbsolutePathNames+idx.FilteredLowValueFileArtifacts+idx.DuplicateMerged,
		idx.FilteredAbsolutePathNames,
		idx.FilteredLowValueFileArtifacts,
		idx.DuplicateMerged,
		idx.IndexedComponents,
	)
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.summaryAssemblyMath, retainedPackages, structuralComponents, idx.TotalComponents))
	fmt.Fprintf(w, "- %s: total=%d continue=%d skip=%d abort=%d\n", t.summaryPolicies, pol.Total, pol.Continue, pol.Skip, pol.Abort)
	fmt.Fprintf(w, "- %s: pipeline=%d\n", t.summaryProcessingIssues, len(data.ProcessingIssues))
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.summaryNextStepTemplate, sectionLink(t.howToUseSection, anchorHowToUse), sectionLink(t.componentIndexSection, anchorComponentIndex)))

	fmt.Fprintf(w, "\n%s:\n", t.summaryFindings)
	findings := summarizeFindings(ext, scn, idx)
	for _, finding := range findings {
		fmt.Fprintf(w, "- %s\n", finding)
	}
}

func summarizeFindings(ext extractionStats, scn scanStats, idx componentIndexStats) []string {
	findings := make([]string, 0, 8)
	if ext.ToolMissing > 0 {
		findings = append(findings, fmt.Sprintf("%d extraction nodes require unavailable external tools. Examples: %s.", ext.ToolMissing, samplePaths(ext.ToolMissingPaths, 3)))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf("%d extraction nodes failed or were blocked. Examples: %s.", ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), 3)))
	}
	if scn.Errors > 0 {
		findings = append(findings, fmt.Sprintf("%d Syft scan tasks failed. Examples: %s.", scn.Errors, samplePaths(scn.ErrorPaths, 3)))
	} else if scn.Total > 0 {
		findings = append(findings, fmt.Sprintf("All %d Syft scan tasks completed successfully.", scn.Total))
	}
	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			"%d of %d indexed component occurrences [carry a PURL](#%s); [%d do not](#%s).",
			idx.IndexedWithPURL, idx.IndexedComponents, anchorComponentsWithPURL,
			idx.IndexedWithoutPURL, anchorComponentsWithoutPURL,
		))
	}
	if scn.NoComponentTasks > 0 {
		findings = append(findings, fmt.Sprintf("%d successful scan tasks produced no package identities. Examples: %s.", scn.NoComponentTasks, samplePaths(scn.NoComponentPaths, 3)))
	}
	if idx.FilteredAbsolutePathNames > 0 || idx.FilteredLowValueFileArtifacts > 0 || idx.DuplicateMerged > 0 {
		findings = append(
			findings,
			fmt.Sprintf(
				"Index quality controls removed %d absolute-path artifacts, %d low-value file artifacts, and merged %d duplicate placeholders.",
				idx.FilteredAbsolutePathNames,
				idx.FilteredLowValueFileArtifacts,
				idx.DuplicateMerged,
			),
		)
	}
	if len(findings) == 0 {
		findings = append(findings, "No critical processing limitations detected in this run.")
	}
	return findings
}

func writeProcessingIssues(w io.Writer, data ReportData, ext extractionStats, scn scanStats, t translations) {
	entries := collectProcessingEntries(data)

	fmt.Fprintf(w, "- pipeline: %d\n", len(data.ProcessingIssues))
	fmt.Fprintf(w, "- extraction-failed: %d\n", ext.Failed)
	fmt.Fprintf(w, "- extraction-security-blocked: %d\n", ext.SecurityBlocked)
	fmt.Fprintf(w, "- extraction-tool-missing: %d\n", ext.ToolMissing)
	fmt.Fprintf(w, "- scan-errors: %d\n", scn.Errors)

	if len(entries) == 0 {
		fmt.Fprintf(w, "\n- %s\n", t.noProcessingIssues)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Source | Location | Detail |")
	fmt.Fprintln(w, "|---|---|---|")

	maxRows := 25
	for i, entry := range entries {
		if i >= maxRows {
			remaining := len(entries) - maxRows
			fmt.Fprintf(w, "| ... | ... | %d additional entries omitted for brevity |\n", remaining)
			break
		}
		fmt.Fprintf(
			w,
			"| %s | %s | %s |\n",
			escapeMarkdownCell(entry.Source),
			escapeMarkdownCell(entry.Location),
			escapeMarkdownCell(entry.Detail),
		)
	}
}

func collectProcessingEntries(data ReportData) []processingEntry {
	entries := make([]processingEntry, 0, len(data.ProcessingIssues)+len(data.Scans))

	for _, issue := range data.ProcessingIssues {
		entries = append(entries, processingEntry{
			Source:   "pipeline",
			Location: issue.Stage,
			Detail:   issue.Message,
		})
	}

	var walk func(node *extract.ExtractionNode)
	walk = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if node.Status == extract.StatusFailed || node.Status == extract.StatusToolMissing || node.Status == extract.StatusSecurityBlocked {
			detail := node.StatusDetail
			if detail == "" {
				detail = "status=" + node.Status.String()
			}
			entries = append(entries, processingEntry{
				Source:   "extraction",
				Location: node.Path,
				Detail:   detail,
			})
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(data.Tree)

	for _, sr := range data.Scans {
		if sr.Error == nil {
			continue
		}
		entries = append(entries, processingEntry{
			Source:   "scan",
			Location: sr.NodePath,
			Detail:   sr.Error.Error(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		return entries[i].Detail < entries[j].Detail
	})

	return entries
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func writeSuppressionReport(w io.Writer, suppressions []assembly.SuppressionRecord, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentNormalizationLead)

	if len(suppressions) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noSuppressions)
		return
	}

	// Group by reason for a structured overview.
	var fsArtifacts, lowValue, weakDups, purlDups []assembly.SuppressionRecord
	for i := range suppressions {
		switch suppressions[i].Reason {
		case assembly.SuppressionFSArtifact:
			fsArtifacts = append(fsArtifacts, suppressions[i])
		case assembly.SuppressionLowValueFile:
			lowValue = append(lowValue, suppressions[i])
		case assembly.SuppressionWeakDuplicate:
			weakDups = append(weakDups, suppressions[i])
		case assembly.SuppressionPURLDuplicate:
			purlDups = append(purlDups, suppressions[i])
		}
	}

	// Summary counts.
	fmt.Fprintf(w, "| %s | Count |\n", "Reason")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonFSArtifact, len(fsArtifacts))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonLowValueFile, len(lowValue))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonWeakDuplicate, len(weakDups))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonPURLDuplicate, len(purlDups))
	fmt.Fprintln(w)

	// FS-cataloger artifacts.
	if len(fsArtifacts) > 0 {
		fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonFSArtifact, len(fsArtifacts))
		fmt.Fprintln(w, "Operational meaning: these are file-level Syft records, not retained package findings. They normally require no action during vulnerability triage. They are listed here only so the normalization step remains auditable.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "When a package identity exists for the same file, the actionable record is the surviving component in the Component Occurrence Index.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Name (suppressed) | Delivery path |")
		fmt.Fprintln(w, "|---|---|")
		maxRows := 20
		for i := range fsArtifacts {
			if i >= maxRows {
				fmt.Fprintf(w, "| ... | %d additional entries omitted |\n", len(fsArtifacts)-maxRows)
				break
			}
			r := fsArtifacts[i]
			fmt.Fprintf(w, "| `%s` | `%s` |\n",
				escapeMarkdownCell(r.Component.Name),
				escapeMarkdownCell(r.DeliveryPath))
		}
		fmt.Fprintln(w)
	}

	// Low-value file artifacts.
	if len(lowValue) > 0 {
		fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonLowValueFile, len(lowValue))
		fmt.Fprintln(w, "Operational meaning: these raw file records had no PURL, no version, and no identifying cataloger metadata. They do not support package-level CVE correlation and are therefore excluded from the SBOM package view.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Name (suppressed) | Delivery path |")
		fmt.Fprintln(w, "|---|---|")
		maxRows := 20
		for i := range lowValue {
			if i >= maxRows {
				fmt.Fprintf(w, "| ... | %d additional entries omitted |\n", len(lowValue)-maxRows)
				break
			}
			r := lowValue[i]
			fmt.Fprintf(w, "| `%s` | `%s` |\n",
				escapeMarkdownCell(r.Component.Name),
				escapeMarkdownCell(r.DeliveryPath))
		}
		fmt.Fprintln(w)
	}

	// Weak duplicates.
	if len(weakDups) > 0 {
		fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonWeakDuplicate, len(weakDups))
		fmt.Fprintln(w, "Operational meaning: at the same delivery/evidence locus a stronger package record existed. The weaker placeholder was removed so that the final SBOM keeps the more attributable identity.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Name (suppressed) | Delivery path | "+t.suppressionReplacedBy+" |")
		fmt.Fprintln(w, "|---|---|---|")
		maxRows := 20
		for i := range weakDups {
			if i >= maxRows {
				fmt.Fprintf(w, "| ... | ... | %d additional entries omitted |\n", len(weakDups)-maxRows)
				break
			}
			r := weakDups[i]
			keptBy := r.KeptName
			if r.KeptFoundBy != "" {
				keptBy += " (" + r.KeptFoundBy + ")"
			}
			fmt.Fprintf(w, "| `%s` | `%s` | `%s` |\n",
				escapeMarkdownCell(r.Component.Name),
				escapeMarkdownCell(r.DeliveryPath),
				escapeMarkdownCell(keptBy))
		}
		fmt.Fprintln(w)
	}

	// PURL duplicates across scan nodes or evidence variants.
	if len(purlDups) > 0 {
		fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonPURLDuplicate, len(purlDups))
		fmt.Fprintln(w, "Operational meaning: several raw observations described the same package identity. One representative was kept, and the surviving component in the Component Occurrence Index carries the retained leaf-most delivery and evidence paths. Use this table only when you need to audit why duplicate raw observations collapsed into one package component.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Name (suppressed) | Delivery path | "+t.suppressionReplacedBy+" |")
		fmt.Fprintln(w, "|---|---|---|")
		maxRows := 20
		for i := range purlDups {
			if i >= maxRows {
				fmt.Fprintf(w, "| ... | ... | %d additional entries omitted |\n", len(purlDups)-maxRows)
				break
			}
			r := purlDups[i]
			keptBy := r.KeptName
			if r.KeptFoundBy != "" {
				keptBy = keptBy + " (`" + escapeMarkdownCell(r.KeptFoundBy) + "`)"
			}
			fmt.Fprintf(w, "| `%s` | `%s` | %s |\n",
				escapeMarkdownCell(r.Component.Name),
				escapeMarkdownCell(r.DeliveryPath),
				escapeMarkdownCell(keptBy))
		}
		fmt.Fprintln(w)
	}
}

func writeExtensionFilterSection(w io.Writer, data ReportData, ext extractionStats, t translations) {
	fmt.Fprintln(w, t.extensionFilterLead)
	fmt.Fprintln(w)

	if len(data.Config.SkipExtensions) > 0 {
		extensions := make([]string, len(data.Config.SkipExtensions))
		copy(extensions, data.Config.SkipExtensions)
		sort.Strings(extensions)
		quoted := make([]string, len(extensions))
		for i, e := range extensions {
			quoted[i] = "`" + e + "`"
		}
		fmt.Fprintf(w, "**%s:** %s\n\n", t.extensionFilterExtensionsLabel, strings.Join(quoted, ", "))
	} else {
		fmt.Fprintln(w, t.noExtensionFilteredFiles)
		return
	}

	fmt.Fprintf(w, "**%s (%d):**\n\n", t.extensionFilterSkippedLabel, ext.ExtensionFiltered)
	if ext.ExtensionFiltered == 0 {
		fmt.Fprintf(w, "- %s\n", t.noExtensionFilteredFiles)
		return
	}

	paths := make([]string, len(ext.ExtensionFilteredPaths))
	copy(paths, ext.ExtensionFilteredPaths)
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

func writeComponentOccurrenceIndex(w io.Writer, occurrences []componentOccurrence, idx componentIndexStats, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentIndexLead)

	if len(occurrences) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noIndexedComponents)
		return
	}

	// Split occurrences into with-PURL and without-PURL groups.
	var withPURL, withoutPURL []componentOccurrence
	for i := range occurrences {
		if occurrences[i].PURL != "" {
			withPURL = append(withPURL, occurrences[i])
		} else {
			withoutPURL = append(withoutPURL, occurrences[i])
		}
	}

	// Write with-PURL subsection.
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchorComponentsWithPURL)
	fmt.Fprintf(w, "### %s (%d)\n\n", t.componentIndexWithPURLSubsection, idx.IndexedWithPURL)
	if len(withPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withPURL {
			writeOccurrenceEntry(w, withPURL[i], t)
		}
	}

	// Write without-PURL subsection.
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchorComponentsWithoutPURL)
	fmt.Fprintf(w, "### %s (%d)\n\n", t.componentIndexWithoutPURLSubsection, idx.IndexedWithoutPURL)
	if len(withoutPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withoutPURL {
			writeOccurrenceEntry(w, withoutPURL[i], t)
		}
	}
}

func writeOccurrenceEntry(w io.Writer, occ componentOccurrence, t translations) {
	fmt.Fprintf(w, "### %s\n\n", occ.ObjectID)
	fmt.Fprintf(w, "- %s: `%s`\n", t.packageName, occ.PackageName)
	if occ.Version != "" {
		fmt.Fprintf(w, "- %s: `%s`\n", t.version, occ.Version)
	}
	if occ.PURL != "" {
		fmt.Fprintf(w, "- %s: `%s`\n", t.purl, occ.PURL)
	}
	for _, dp := range occ.DeliveryPaths {
		fmt.Fprintf(w, "- %s: `%s`\n", t.deliveryPath, dp)
	}
	if len(occ.EvidencePaths) > 0 {
		for _, evidencePath := range occ.EvidencePaths {
			fmt.Fprintf(w, "- %s: `%s`\n", t.evidencePath, evidencePath)
		}
	} else if occ.EvidenceSource != "" {
		fmt.Fprintf(w, "- %s: %s\n", t.evidencePath, occ.EvidenceSource)
	} else {
		fmt.Fprintf(w, "- %s: %s\n", t.evidencePath, t.noEvidenceRecorded)
	}
	if occ.FoundBy != "" {
		fmt.Fprintf(w, "- %s: `%s`\n", t.foundBy, occ.FoundBy)
	}
	fmt.Fprintln(w)
}

func collectComponentOccurrences(bom *cdx.BOM) ([]componentOccurrence, componentIndexStats) {
	stats := componentIndexStats{}
	if bom == nil || bom.Components == nil {
		return nil, stats
	}

	occurrences := make([]componentOccurrence, 0, len(*bom.Components))
	for i := range *bom.Components {
		comp := (*bom.Components)[i]
		stats.TotalComponents++
		deliveryPaths := componentPropertyValues(comp, "extract-sbom:delivery-path")
		if len(deliveryPaths) == 0 {
			stats.MissingDeliveryPath++
			continue
		}
		if len(componentPropertyValues(comp, "extract-sbom:extraction-status")) > 0 {
			stats.FilteredContainerNodes++
			continue
		}

		foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
		if strings.HasPrefix(comp.Name, "/") {
			stats.FilteredAbsolutePathNames++
			continue
		}
		if isLowValueFileArtifact(comp, foundBy) {
			stats.FilteredLowValueFileArtifacts++
			continue
		}

		occurrences = append(occurrences, componentOccurrence{
			ObjectID:       comp.BOMRef,
			ComponentType:  comp.Type,
			PackageName:    comp.Name,
			Version:        comp.Version,
			PURL:           comp.PackageURL,
			DeliveryPaths:  deliveryPaths,
			EvidencePaths:  componentPropertyValues(comp, "extract-sbom:evidence-path"),
			EvidenceSource: firstComponentPropertyValue(comp, "extract-sbom:evidence-source"),
			FoundBy:        foundBy,
		})
	}

	occurrences = mergeDuplicateOccurrences(occurrences, &stats)

	sort.Slice(occurrences, func(i, j int) bool {
		return compareOccurrence(occurrences[i], occurrences[j]) < 0
	})
	stats.IndexedComponents = len(occurrences)
	for i := range occurrences {
		occ := occurrences[i]
		if occ.PURL != "" {
			stats.IndexedWithPURL++
		} else {
			stats.IndexedWithoutPURL++
		}
		switch {
		case len(occ.EvidencePaths) > 0:
			stats.IndexedWithEvidencePath++
		case occ.EvidenceSource != "":
			stats.IndexedWithEvidenceSourceOnly++
		default:
			stats.IndexedWithoutEvidence++
		}
	}

	return occurrences, stats
}

func compareOccurrence(a, b componentOccurrence) int {
	aPrimary := firstString(a.DeliveryPaths)
	bPrimary := firstString(b.DeliveryPaths)
	if aPrimary != bPrimary {
		if aPrimary < bPrimary {
			return -1
		}
		return 1
	}
	aEvidence := firstString(a.EvidencePaths)
	bEvidence := firstString(b.EvidencePaths)
	if aEvidence != bEvidence {
		if aEvidence < bEvidence {
			return -1
		}
		return 1
	}
	if a.PackageName != b.PackageName {
		if a.PackageName < b.PackageName {
			return -1
		}
		return 1
	}
	if a.Version != b.Version {
		if a.Version < b.Version {
			return -1
		}
		return 1
	}
	if a.PURL != b.PURL {
		if a.PURL < b.PURL {
			return -1
		}
		return 1
	}
	if a.FoundBy != b.FoundBy {
		if a.FoundBy < b.FoundBy {
			return -1
		}
		return 1
	}
	if a.ObjectID < b.ObjectID {
		return -1
	}
	if a.ObjectID > b.ObjectID {
		return 1
	}
	return 0
}

func mergeDuplicateOccurrences(occurrences []componentOccurrence, stats *componentIndexStats) []componentOccurrence {
	if len(occurrences) < 2 {
		return occurrences
	}

	groups := make(map[string][]componentOccurrence)
	keys := make([]string, 0)
	for i := range occurrences {
		occ := occurrences[i]
		key := occurrenceLocusKey(occ)
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], occ)
	}
	sort.Strings(keys)

	merged := make([]componentOccurrence, 0, len(occurrences))
	for _, key := range keys {
		group := groups[key]
		if len(group) == 1 {
			merged = append(merged, group[0])
			continue
		}

		best := pickBestOccurrence(group)
		if shouldCollapseDuplicateGroup(group, best) {
			merged = append(merged, best)
			stats.DuplicateMerged += len(group) - 1
			continue
		}

		merged = append(merged, group...)
	}

	return merged
}

func occurrenceLocusKey(occ componentOccurrence) string {
	dp := append([]string(nil), occ.DeliveryPaths...)
	sort.Strings(dp)
	evidence := append([]string(nil), occ.EvidencePaths...)
	sort.Strings(evidence)
	return strings.Join(dp, "\x1e") + "\x00" + strings.Join(evidence, "\x1f")
}

func pickBestOccurrence(group []componentOccurrence) componentOccurrence {
	best := group[0]
	bestScore := occurrenceQualityScore(best)
	for i := 1; i < len(group); i++ {
		score := occurrenceQualityScore(group[i])
		if score > bestScore || (score == bestScore && compareOccurrence(group[i], best) < 0) {
			best = group[i]
			bestScore = score
		}
	}
	return best
}

func occurrenceQualityScore(occ componentOccurrence) int {
	score := 0
	if occ.PURL != "" {
		score += 4
	}
	if occ.FoundBy != "" {
		score += 3
	}
	if occ.Version != "" {
		score += 2
	}
	if occ.PackageName != "" && !strings.Contains(occ.PackageName, "/") {
		score++
	}
	return score
}

func shouldCollapseDuplicateGroup(group []componentOccurrence, best componentOccurrence) bool {
	if occurrenceQualityScore(best) < 4 {
		return false
	}

	for i := range group {
		occ := group[i]
		if occ.ObjectID == best.ObjectID {
			continue
		}
		if !isWeakArtifactOccurrence(occ) {
			return false
		}
	}

	return true
}

func isWeakArtifactOccurrence(occ componentOccurrence) bool {
	if occ.PURL != "" || occ.FoundBy != "" || occ.Version != "" {
		return false
	}
	if occ.PackageName == "" {
		return true
	}
	if strings.Contains(occ.PackageName, "/") {
		return true
	}

	base := path.Base(firstString(occ.DeliveryPaths))
	baseNoExt := strings.TrimSuffix(base, path.Ext(base))
	return strings.EqualFold(occ.PackageName, base) || strings.EqualFold(occ.PackageName, baseNoExt)
}

func isLowValueFileArtifact(comp cdx.Component, foundBy string) bool {
	if comp.Type != cdx.ComponentTypeFile {
		return false
	}
	return comp.PackageURL == "" && comp.Version == "" && foundBy == ""
}

func componentPropertyValues(comp cdx.Component, name string) []string {
	if comp.Properties == nil {
		return nil
	}

	values := make([]string, 0)
	seen := make(map[string]struct{})
	for _, prop := range *comp.Properties {
		if prop.Name != name || prop.Value == "" {
			continue
		}
		if _, ok := seen[prop.Value]; ok {
			continue
		}
		seen[prop.Value] = struct{}{}
		values = append(values, prop.Value)
	}
	if name == "extract-sbom:delivery-path" || name == "extract-sbom:evidence-path" {
		return leafMostLogicalPaths(values)
	}
	return values
}

func leafMostLogicalPaths(values []string) []string {
	if len(values) < 2 {
		return values
	}

	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		cleaned = append(cleaned, path.Clean(value))
	}
	sort.Strings(cleaned)

	kept := make([]string, 0, len(cleaned))
	for i, candidate := range cleaned {
		redundant := false
		for j, other := range cleaned {
			if i == j {
				continue
			}
			if isAncestorLogicalPath(candidate, other) {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func isAncestorLogicalPath(ancestor, descendant string) bool {
	ancestor = strings.TrimSuffix(path.Clean(ancestor), "/")
	descendant = path.Clean(descendant)
	if ancestor == "" || ancestor == "." || ancestor == descendant {
		return false
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

func firstComponentPropertyValue(comp cdx.Component, name string) string {
	values := componentPropertyValues(comp, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func writeExtractionTree(w io.Writer, node *extract.ExtractionNode, depth int, t translations) {
	if node == nil {
		return
	}

	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(w, "%s- **%s** [%s] %s=%s", indent, node.Path, node.Format.Format, t.status, node.Status)

	if node.Tool != "" {
		fmt.Fprintf(w, " %s=%s", t.tool, node.Tool)
	}
	if node.SandboxUsed != "" {
		fmt.Fprintf(w, " sandbox=%s", node.SandboxUsed)
	}
	if node.Duration > 0 {
		fmt.Fprintf(w, " %s=%s", t.duration, node.Duration.Round(time.Millisecond))
	}
	if node.StatusDetail != "" {
		fmt.Fprintf(w, " (%s)", node.StatusDetail)
	}
	fmt.Fprintln(w)

	for _, child := range node.Children {
		writeExtractionTree(w, child, depth+1, t)
	}
}

func writeResidualRisk(w io.Writer, data ReportData, ext extractionStats, scn scanStats, idx componentIndexStats, t translations) {
	fmt.Fprintln(w, t.residualRiskText)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s\n", t.residualRiskProfileLead)
	fmt.Fprintf(w, "- %s\n", t.residualRiskAbsenceHint)
	if idx.IndexedComponents > 0 {
		// PURL coverage with links to the two component index subsections.
		purlLine := fmt.Sprintf(t.residualRiskPURLCoverage, idx.IndexedWithPURL, idx.IndexedComponents, idx.IndexedWithoutPURL)
		// Replace plain number references with hyperlinked equivalents.
		withPURLLink := fmt.Sprintf("[%d](%s)", idx.IndexedWithPURL, "#"+anchorComponentsWithPURL)
		withoutPURLLink := fmt.Sprintf("[%d](%s)", idx.IndexedWithoutPURL, "#"+anchorComponentsWithoutPURL)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d of %d indexed", idx.IndexedWithPURL, idx.IndexedComponents),
			fmt.Sprintf("%s of %d indexed", withPURLLink, idx.IndexedComponents), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexed occurrences do not", idx.IndexedWithoutPURL),
			fmt.Sprintf("%s indexed occurrences do not", withoutPURLLink), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexierte Vorkommen haben keine PURL", idx.IndexedWithoutPURL),
			fmt.Sprintf("%s indexierte Vorkommen haben keine PURL", withoutPURLLink), 1)
		fmt.Fprintf(w, "- %s\n", purlLine)
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskEvidenceCoverage, idx.IndexedWithEvidencePath, idx.IndexedWithEvidenceSourceOnly, idx.IndexedWithoutEvidence))
	}
	if scn.Successful > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskNoComponentTasks, scn.NoComponentTasks, scn.Successful, samplePaths(scn.NoComponentPaths, 3)))
	}
	suppression := collectSuppressionStats(data.Suppressions)
	fileArtifactCount := suppression.FSArtifacts + suppression.LowValueFiles
	if fileArtifactCount > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskFileArtifactCoverage, fileArtifactCount))
	}
	if ext.ExtensionFiltered > 0 {
		fmt.Fprintf(w, "- %s %d %s [%s](#%s).\n",
			"Extension filter excluded", ext.ExtensionFiltered,
			"files from examination; these are not reflected in the component inventory. See",
			t.extensionFilterSection, anchorExtensionFilter)
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtractionGap, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), 3)))
	}
	if ext.ToolMissing > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskToolGap, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, 3)))
	}
	if scn.Errors > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskScanGap, scn.Errors, samplePaths(scn.ErrorPaths, 3)))
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskMoreDetails, scanApproachLink("Package Detection Reliability", "6-package-detection-reliability")))
}

// configSkipExtensionsDisplay returns a compact one-liner for the configuration
// table showing the active skip list, capped to keep the table cell readable.
func configSkipExtensionsDisplay(exts []string) string {
	if len(exts) == 0 {
		return "(none)"
	}
	sorted := make([]string, len(exts))
	copy(sorted, exts)
	sort.Strings(sorted)
	const maxShow = 200
	if len(sorted) <= maxShow {
		return strings.Join(sorted, " ")
	}
	return strings.Join(sorted[:maxShow], " ") + fmt.Sprintf(" (+%d more)", len(sorted)-maxShow)
}

func samplePaths(paths []string, maxCount int) string {
	if len(paths) == 0 {
		return "none"
	}

	unique := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}

	sort.Strings(unique)
	if len(unique) <= maxCount {
		return strings.Join(unique, "; ")
	}
	return strings.Join(unique[:maxCount], "; ") + fmt.Sprintf(" (+%d more)", len(unique)-maxCount)
}

func collectExtractionStats(node *extract.ExtractionNode) extractionStats {
	stats := extractionStats{}

	var walk func(n *extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}

		stats.Total++
		switch n.Status {
		case extract.StatusExtracted:
			stats.Extracted++
		case extract.StatusSyftNative:
			stats.SyftNative++
		case extract.StatusFailed:
			stats.Failed++
			stats.FailedPaths = append(stats.FailedPaths, n.Path)
		case extract.StatusSkipped:
			stats.Skipped++
		case extract.StatusToolMissing:
			stats.ToolMissing++
			stats.ToolMissingPaths = append(stats.ToolMissingPaths, n.Path)
		case extract.StatusSecurityBlocked:
			stats.SecurityBlocked++
			stats.SecurityBlockedPaths = append(stats.SecurityBlockedPaths, n.Path)
		case extract.StatusPending:
			stats.Pending++
		default:
			stats.Other++
		}

		// Aggregate extension-filtered files recorded at each node.
		stats.ExtensionFiltered += len(n.ExtensionFilteredPaths)
		stats.ExtensionFilteredPaths = append(stats.ExtensionFilteredPaths, n.ExtensionFilteredPaths...)

		for _, child := range n.Children {
			walk(child)
		}
	}

	walk(node)
	return stats
}

func collectScanStats(scans []scan.ScanResult) scanStats {
	stats := scanStats{Total: len(scans)}
	for _, sr := range scans {
		if sr.Error != nil {
			stats.Errors++
			stats.ErrorPaths = append(stats.ErrorPaths, sr.NodePath)
			continue
		}
		stats.Successful++
		componentCount := 0
		if sr.BOM != nil && sr.BOM.Components != nil {
			componentCount = len(*sr.BOM.Components)
			stats.TotalComponents += componentCount
		}
		if componentCount == 0 {
			stats.NoComponentTasks++
			stats.NoComponentPaths = append(stats.NoComponentPaths, sr.NodePath)
		}
	}
	return stats
}

func collectPolicyStats(decisions []policy.Decision) policyStats {
	stats := policyStats{Total: len(decisions)}
	for _, d := range decisions {
		switch d.Action {
		case policy.ActionContinue:
			stats.Continue++
		case policy.ActionSkip:
			stats.Skip++
		case policy.ActionAbort:
			stats.Abort++
		}
	}
	return stats
}
