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
	"sort"
	"strings"
	"time"

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
	SBOMPath         string
}

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

	fmt.Fprintf(w, "# %s\n\n", t.title)

	// Input identification.
	fmt.Fprintf(w, "## %s\n\n", t.inputSection)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d bytes |\n", t.filesize, data.Input.Size)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	fmt.Fprintf(w, "## %s\n\n", t.configSection)
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
	fmt.Fprintln(w)

	// Root SBOM metadata.
	fmt.Fprintf(w, "## %s\n\n", t.rootMetadataSection)
	writeRootMetadata(w, data, t)

	// Sandbox information.
	fmt.Fprintf(w, "## %s\n\n", t.sandboxSection)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
	if data.SandboxInfo.UnsafeOvr {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

	// Extraction log.
	fmt.Fprintf(w, "## %s\n\n", t.extractionSection)
	writeExtractionTree(w, data.Tree, 0, t)
	fmt.Fprintln(w)

	// Scan results.
	fmt.Fprintf(w, "## %s\n\n", t.scanSection)
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

	// Policy decisions.
	if len(data.PolicyDecisions) > 0 {
		fmt.Fprintf(w, "## %s\n\n", t.policySection)
		for _, d := range data.PolicyDecisions {
			fmt.Fprintf(w, "- **%s** at `%s`: %s → %s\n", d.Trigger, d.NodePath, d.Detail, d.Action)
		}
		fmt.Fprintln(w)
	}

	// Summary.
	fmt.Fprintf(w, "## %s\n\n", t.summarySection)
	duration := data.EndTime.Sub(data.StartTime)
	fmt.Fprintf(w, "%s: %s\n\n", t.processingTime, duration.Round(time.Millisecond))

	if len(data.ProcessingIssues) > 0 {
		fmt.Fprintf(w, "## %s\n\n", t.processingIssuesSection)
		for _, issue := range data.ProcessingIssues {
			fmt.Fprintf(w, "- **%s**: %s\n", issue.Stage, issue.Message)
		}
		fmt.Fprintln(w)
	}

	// Residual risk.
	fmt.Fprintf(w, "## %s\n\n", t.residualRiskSection)
	writeResidualRisk(w, data, t)

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
	generator               string
	sandboxName             string
	sandboxAvail            string
	unsafeWarning           string
	unsafeActive            string
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
			generator:               "extract-sbom Build",
			sandboxName:             "Sandbox",
			sandboxAvail:            "Verfügbar",
			unsafeWarning:           "WARNUNG",
			unsafeActive:            "Unsicherer Modus aktiv — keine Sandbox-Isolation",
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
			generator:               "extract-sbom build",
			sandboxName:             "Sandbox",
			sandboxAvail:            "Available",
			unsafeWarning:           "WARNING",
			unsafeActive:            "Unsafe mode active — no sandbox isolation",
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

func writeResidualRisk(w io.Writer, data ReportData, t translations) {
	fmt.Fprintln(w, t.residualRiskText)
	fmt.Fprintln(w)

	risks := []string{}

	// Check for incomplete extractions.
	if hasIncomplete(data.Tree) {
		risks = append(risks, "Some archive subtrees could not be fully extracted or scanned.")
	}

	// Check for missing tools.
	if hasToolMissing(data.Tree) {
		risks = append(risks, "Required extraction tools are missing for some archive formats.")
	}

	// Check for scan errors.
	for _, sr := range data.Scans {
		if sr.Error != nil {
			risks = append(risks, "One or more Syft scans produced errors; some components may be missing.")
			break
		}
	}

	// Check for unsafe mode.
	if data.SandboxInfo.UnsafeOvr {
		risks = append(risks, "Extraction ran without sandbox isolation (--unsafe). Process-level containment was not enforced.")
	}

	if len(risks) == 0 {
		risks = append(risks, "No significant residual risks identified for this inspection run.")
	}

	for _, r := range risks {
		fmt.Fprintf(w, "- %s\n", r)
	}
}

func hasIncomplete(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	if node.Status == extract.StatusFailed || node.Status == extract.StatusSkipped ||
		node.Status == extract.StatusSecurityBlocked {
		return true
	}
	for _, child := range node.Children {
		if hasIncomplete(child) {
			return true
		}
	}
	return false
}

func hasToolMissing(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	if node.Status == extract.StatusToolMissing {
		return true
	}
	for _, child := range node.Children {
		if hasToolMissing(child) {
			return true
		}
	}
	return false
}
