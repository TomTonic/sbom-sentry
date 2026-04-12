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
}

type componentOccurrence struct {
	ObjectID      string
	ComponentType cdx.ComponentType
	PackageName   string
	Version       string
	PURL          string
	DeliveryPath  string
	EvidencePaths []string
	FoundBy       string
}

type componentIndexStats struct {
	TotalComponents               int
	MissingDeliveryPath           int
	FilteredContainerNodes        int
	FilteredAbsolutePathNames     int
	FilteredLowValueFileArtifacts int
	DuplicateMerged               int
	IndexedComponents             int
}

type extractionStats struct {
	Total           int
	Extracted       int
	SyftNative      int
	Failed          int
	Skipped         int
	ToolMissing     int
	SecurityBlocked int
	Pending         int
	Other           int

	FailedPaths          []string
	ToolMissingPaths     []string
	SecurityBlockedPaths []string
}

type scanStats struct {
	Total      int
	Successful int
	Errors     int
	ErrorPaths []string
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
	anchorInputFile        = "input-file"
	anchorConfig           = "configuration"
	anchorRootMetadata     = "root-sbom-metadata"
	anchorSandbox          = "sandbox-configuration"
	anchorSummary          = "summary"
	anchorProcessingErrors = "processing-errors"
	anchorResidualRisk     = "residual-risk-and-limitations"
	anchorPolicy           = "policy-decisions"
	anchorComponentIndex   = "component-occurrence-index"
	anchorScan             = "scan-results"
	anchorExtraction       = "extraction-log"
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
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
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

	// Summary.
	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, data, extStats, scnStats, polStats, indexStats, t)
	fmt.Fprintln(w)

	// Processing issues.
	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, data, extStats, scnStats, t)
	fmt.Fprintln(w)

	// Residual risk.
	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, data, extStats, scnStats, indexStats, t)
	fmt.Fprintln(w)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, data.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Component occurrence index.
	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, occurrences, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	for _, sr := range data.Scans {
		evidencePaths := scan.FlattenEvidencePaths(sr)
		switch {
		case sr.Error != nil:
			fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
		case sr.BOM != nil && sr.BOM.Components != nil:
			fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
			for _, evidencePath := range evidencePaths {
				fmt.Fprintf(w, "  - evidence-path: `%s`\n", evidencePath)
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
	title                   string
	inputSection            string
	configSection           string
	rootMetadataSection     string
	sandboxSection          string
	extractionSection       string
	scanSection             string
	policySection           string
	summarySection          string
	residualRiskSection     string
	processingIssuesSection string
	field                   string
	value                   string
	setting                 string
	filename                string
	filesize                string
	policyMode              string
	interpretMode           string
	language                string
	maxDepth                string
	maxFiles                string
	maxTotalSize            string
	maxEntrySize            string
	maxRatio                string
	timeout                 string
	progressLevel           string
	generator               string
	sandboxName             string
	sandboxAvail            string
	unsafeWarning           string
	unsafeActive            string
	tableOfContentsSection  string
	componentIndexSection   string
	componentIndexLead      string
	noIndexedComponents     string
	objectID                string
	packageName             string
	version                 string
	purl                    string
	evidencePath            string
	foundBy                 string
	noEvidenceRecorded      string
	processingTime          string
	scanError               string
	componentsFound         string
	noComponents            string
	deliveryPath            string
	status                  string
	tool                    string
	duration                string
	suppliedBy              string
	derived                 string
	residualRiskText        string
	noPolicyDecisions       string
	noProcessingIssues      string
	summaryExtraction       string
	summaryScan             string
	summaryComponents       string
	summaryPolicies         string
	summaryProcessingIssues string
	summaryFindings         string
	endOfReport             string
}

func getTranslations(lang string) translations {
	switch lang {
	case "de":
		return translations{
			title:                   "extract-sbom Prüfbericht",
			inputSection:            "Eingabedatei",
			configSection:           "Konfiguration",
			rootMetadataSection:     "SBOM Stammdaten",
			sandboxSection:          "Sandbox-Konfiguration",
			extractionSection:       "Extraktionsprotokoll",
			scanSection:             "Scan-Ergebnisse",
			policySection:           "Richtlinienentscheidungen",
			summarySection:          "Zusammenfassung",
			residualRiskSection:     "Restrisiko und Einschränkungen",
			processingIssuesSection: "Verarbeitungsfehler",
			field:                   "Feld",
			value:                   "Wert",
			setting:                 "Einstellung",
			filename:                "Dateiname",
			filesize:                "Dateigröße",
			policyMode:              "Richtlinienmodus",
			interpretMode:           "Interpretationsmodus",
			language:                "Sprache",
			maxDepth:                "Maximale Tiefe",
			maxFiles:                "Maximale Dateien",
			maxTotalSize:            "Maximale Gesamtgröße",
			maxEntrySize:            "Maximale Eintragsgröße",
			maxRatio:                "Maximales Verhältnis",
			timeout:                 "Zeitlimit",
			progressLevel:           "Fortschritt",
			generator:               "extract-sbom Build",
			sandboxName:             "Sandbox",
			sandboxAvail:            "Verfügbar",
			unsafeWarning:           "WARNUNG",
			unsafeActive:            "Unsicherer Modus aktiv — keine Sandbox-Isolation",
			tableOfContentsSection:  "Inhaltsverzeichnis",
			componentIndexSection:   "Komponentenindex",
			componentIndexLead:      "Die Einträge sind nach Lieferpfad sortiert. Die Objekt-ID entspricht der bom-ref im SBOM und der artifact.id in Grype.",
			noIndexedComponents:     "Keine Komponenten-Vorkommen indexiert.",
			objectID:                "Objekt-ID",
			packageName:             "Paket",
			version:                 "Version",
			purl:                    "PURL",
			evidencePath:            "Belegpfad",
			foundBy:                 "Erkannt durch",
			noEvidenceRecorded:      "kein komponentenspezifischer Beleg erfasst",
			processingTime:          "Verarbeitungszeit",
			scanError:               "Fehler:",
			componentsFound:         "Komponenten gefunden",
			noComponents:            "keine Komponenten gefunden",
			deliveryPath:            "Lieferpfad",
			status:                  "Status",
			tool:                    "Werkzeug",
			duration:                "Dauer",
			suppliedBy:              "Durch Benutzer angegeben",
			derived:                 "Automatisch abgeleitet",
			residualRiskText:        "Die folgenden Einschränkungen können die Vollständigkeit der Ergebnisse beeinflussen:",
			noPolicyDecisions:       "Keine Richtlinienentscheidungen protokolliert.",
			noProcessingIssues:      "Keine Verarbeitungsfehler protokolliert.",
			summaryExtraction:       "Extraktion",
			summaryScan:             "Scans",
			summaryComponents:       "Komponentenindex",
			summaryPolicies:         "Richtlinienentscheidungen",
			summaryProcessingIssues: "Verarbeitungsfehler",
			summaryFindings:         "Wesentliche Befunde",
			endOfReport:             "Ende des Berichts.",
		}
	default:
		return translations{
			title:                   "extract-sbom Audit Report",
			inputSection:            "Input File",
			configSection:           "Configuration",
			rootMetadataSection:     "Root SBOM Metadata",
			sandboxSection:          "Sandbox Configuration",
			extractionSection:       "Extraction Log",
			scanSection:             "Scan Results",
			policySection:           "Policy Decisions",
			summarySection:          "Summary",
			residualRiskSection:     "Residual Risk and Limitations",
			processingIssuesSection: "Processing Errors",
			field:                   "Field",
			value:                   "Value",
			setting:                 "Setting",
			filename:                "Filename",
			filesize:                "File size",
			policyMode:              "Policy mode",
			interpretMode:           "Interpretation mode",
			language:                "Language",
			maxDepth:                "Max depth",
			maxFiles:                "Max files",
			maxTotalSize:            "Max total size",
			maxEntrySize:            "Max entry size",
			maxRatio:                "Max ratio",
			timeout:                 "Timeout",
			progressLevel:           "Progress",
			generator:               "extract-sbom build",
			sandboxName:             "Sandbox",
			sandboxAvail:            "Available",
			unsafeWarning:           "WARNING",
			unsafeActive:            "Unsafe mode active — no sandbox isolation",
			tableOfContentsSection:  "Table of Contents",
			componentIndexSection:   "Component Occurrence Index",
			componentIndexLead:      "Entries are sorted by delivery path. The object ID matches the SBOM bom-ref and Grype artifact.id.",
			noIndexedComponents:     "No component occurrences indexed.",
			objectID:                "Object ID",
			packageName:             "Package",
			version:                 "Version",
			purl:                    "PURL",
			evidencePath:            "Evidence path",
			foundBy:                 "Found by",
			noEvidenceRecorded:      "no component-specific evidence recorded",
			processingTime:          "Processing time",
			scanError:               "Error:",
			componentsFound:         "components found",
			noComponents:            "no components found",
			deliveryPath:            "Delivery path",
			status:                  "Status",
			tool:                    "Tool",
			duration:                "Duration",
			suppliedBy:              "User-supplied",
			derived:                 "Auto-derived",
			residualRiskText:        "The following limitations may affect the completeness of the results:",
			noPolicyDecisions:       "No policy decisions recorded.",
			noProcessingIssues:      "No processing issues recorded.",
			summaryExtraction:       "Extraction",
			summaryScan:             "Scans",
			summaryComponents:       "Component index",
			summaryPolicies:         "Policy decisions",
			summaryProcessingIssues: "Processing issues",
			summaryFindings:         "Key findings",
			endOfReport:             "End of report.",
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
		{title: t.inputSection, anchor: anchorInputFile},
		{title: t.configSection, anchor: anchorConfig},
		{title: t.rootMetadataSection, anchor: anchorRootMetadata},
		{title: t.sandboxSection, anchor: anchorSandbox},
		{title: t.summarySection, anchor: anchorSummary},
		{title: t.processingIssuesSection, anchor: anchorProcessingErrors},
		{title: t.residualRiskSection, anchor: anchorResidualRisk},
		{title: t.policySection, anchor: anchorPolicy},
		{title: t.componentIndexSection, anchor: anchorComponentIndex},
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

	fmt.Fprintf(w, "- %s: %s\n", t.processingTime, duration)
	fmt.Fprintf(
		w,
		"- %s: total=%d extracted=%d syft-native=%d failed=%d tool-missing=%d skipped=%d security-blocked=%d pending=%d\n",
		t.summaryExtraction,
		ext.Total,
		ext.Extracted,
		ext.SyftNative,
		ext.Failed,
		ext.ToolMissing,
		ext.Skipped,
		ext.SecurityBlocked,
		ext.Pending,
	)
	fmt.Fprintf(w, "- %s: total=%d successful=%d errors=%d\n", t.summaryScan, scn.Total, scn.Successful, scn.Errors)
	fmt.Fprintf(
		w,
		"- %s: indexed=%d total-bom-components=%d filtered-abs-path=%d filtered-low-value-files=%d merged-duplicates=%d\n",
		t.summaryComponents,
		idx.IndexedComponents,
		idx.TotalComponents,
		idx.FilteredAbsolutePathNames,
		idx.FilteredLowValueFileArtifacts,
		idx.DuplicateMerged,
	)
	fmt.Fprintf(w, "- %s: total=%d continue=%d skip=%d abort=%d\n", t.summaryPolicies, pol.Total, pol.Continue, pol.Skip, pol.Abort)
	fmt.Fprintf(w, "- %s: pipeline=%d\n", t.summaryProcessingIssues, len(data.ProcessingIssues))

	fmt.Fprintf(w, "\n%s:\n", t.summaryFindings)
	findings := summarizeFindings(data, ext, scn, idx)
	for _, finding := range findings {
		fmt.Fprintf(w, "- %s\n", finding)
	}
}

func summarizeFindings(data ReportData, ext extractionStats, scn scanStats, idx componentIndexStats) []string {
	findings := make([]string, 0, 6)
	if ext.ToolMissing > 0 {
		findings = append(findings, fmt.Sprintf("%d extraction nodes require unavailable external tools.", ext.ToolMissing))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf("%d extraction nodes failed or were blocked.", ext.Failed+ext.SecurityBlocked))
	}
	if scn.Errors > 0 {
		findings = append(findings, fmt.Sprintf("%d Syft scan targets failed.", scn.Errors))
	}
	if data.SandboxInfo.UnsafeOvr {
		findings = append(findings, "Run executed with --unsafe; process isolation was not enforced.")
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
	fmt.Fprintf(w, "- extraction-failed: %d\n", ext.Failed+ext.SecurityBlocked)
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

func writeComponentOccurrenceIndex(w io.Writer, occurrences []componentOccurrence, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentIndexLead)

	if len(occurrences) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noIndexedComponents)
		return
	}

	for i := range occurrences {
		occ := occurrences[i]
		fmt.Fprintf(w, "### %s\n\n", occ.ObjectID)
		fmt.Fprintf(w, "- %s: `%s`\n", t.packageName, occ.PackageName)
		if occ.Version != "" {
			fmt.Fprintf(w, "- %s: `%s`\n", t.version, occ.Version)
		}
		if occ.PURL != "" {
			fmt.Fprintf(w, "- %s: `%s`\n", t.purl, occ.PURL)
		}
		fmt.Fprintf(w, "- %s: `%s`\n", t.deliveryPath, occ.DeliveryPath)
		if len(occ.EvidencePaths) == 0 {
			fmt.Fprintf(w, "- %s: %s\n", t.evidencePath, t.noEvidenceRecorded)
		} else {
			for _, evidencePath := range occ.EvidencePaths {
				fmt.Fprintf(w, "- %s: `%s`\n", t.evidencePath, evidencePath)
			}
		}
		if occ.FoundBy != "" {
			fmt.Fprintf(w, "- %s: `%s`\n", t.foundBy, occ.FoundBy)
		}
		fmt.Fprintln(w)
	}
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
			ObjectID:      comp.BOMRef,
			ComponentType: comp.Type,
			PackageName:   comp.Name,
			Version:       comp.Version,
			PURL:          comp.PackageURL,
			DeliveryPath:  deliveryPaths[0],
			EvidencePaths: componentPropertyValues(comp, "extract-sbom:evidence-path"),
			FoundBy:       foundBy,
		})
	}

	occurrences = mergeDuplicateOccurrences(occurrences, &stats)

	sort.Slice(occurrences, func(i, j int) bool {
		return compareOccurrence(occurrences[i], occurrences[j]) < 0
	})
	stats.IndexedComponents = len(occurrences)

	return occurrences, stats
}

func compareOccurrence(a, b componentOccurrence) int {
	if a.DeliveryPath != b.DeliveryPath {
		if a.DeliveryPath < b.DeliveryPath {
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
	evidence := append([]string(nil), occ.EvidencePaths...)
	sort.Strings(evidence)
	return occ.DeliveryPath + "\x00" + strings.Join(evidence, "\x1f")
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

	base := path.Base(occ.DeliveryPath)
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
	for _, prop := range *comp.Properties {
		if prop.Name != name || prop.Value == "" {
			continue
		}
		values = append(values, prop.Value)
	}
	return values
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

	risks := []string{}

	if ext.ToolMissing > 0 {
		risks = append(
			risks,
			fmt.Sprintf(
				"%d extraction nodes require unavailable tools (e.g. 7zz or unshield). Examples: %s.",
				ext.ToolMissing,
				samplePaths(ext.ToolMissingPaths, 3),
			),
		)
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		risks = append(
			risks,
			fmt.Sprintf(
				"%d extraction nodes failed or were security-blocked. Examples: %s.",
				ext.Failed+ext.SecurityBlocked,
				samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), 3),
			),
		)
	}
	if scn.Errors > 0 {
		risks = append(
			risks,
			fmt.Sprintf(
				"%d Syft scan targets failed. Example nodes: %s.",
				scn.Errors,
				samplePaths(scn.ErrorPaths, 3),
			),
		)
	}
	if data.SandboxInfo.UnsafeOvr {
		risks = append(risks, "Extraction ran without sandbox isolation (--unsafe). Process-level containment was not enforced.")
	}
	if idx.FilteredAbsolutePathNames > 0 || idx.FilteredLowValueFileArtifacts > 0 || idx.DuplicateMerged > 0 {
		risks = append(
			risks,
			fmt.Sprintf(
				"Component index quality filters removed %d absolute-path artifacts, %d low-value file artifacts, and merged %d duplicate placeholders.",
				idx.FilteredAbsolutePathNames,
				idx.FilteredLowValueFileArtifacts,
				idx.DuplicateMerged,
			),
		)
	}

	if len(risks) == 0 {
		risks = append(risks, "No significant residual risks identified for this inspection run.")
	}

	for _, r := range risks {
		fmt.Fprintf(w, "- %s\n", r)
	}
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
