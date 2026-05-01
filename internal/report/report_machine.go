// This file implements the machine-readable JSON report. GenerateMachine and
// all supporting types and builder functions for JSON serialization live here
// so that report.go stays focused on human-readable output.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

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
		Extraction:      buildMachineTree(data.Tree),
		Scans:           buildMachineScans(data.Scans),
		Vulnerabilities: buildMachineVulnerabilities(data.Vulnerabilities),
		Decisions:       buildMachineDecisions(data.PolicyDecisions),
		Issues:          data.ProcessingIssues,
		StartTime:       data.StartTime.UTC().Format(time.RFC3339),
		EndTime:         data.EndTime.UTC().Format(time.RFC3339),
		Duration:        data.EndTime.Sub(data.StartTime).String(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// --- Machine-readable report types ---

// machineReport is the JSON root schema written by GenerateMachine.
type machineReport struct {
	// SchemaVersion is the machine-report schema version string.
	SchemaVersion string `json:"schemaVersion"`
	// Input is the input artifact fingerprint used for this run.
	Input InputSummary `json:"input"`
	// Generator is extract-sbom build metadata.
	Generator machineGenerator `json:"generator"`
	// Config is the effective runtime configuration snapshot.
	Config machineConfig `json:"config"`
	// RootMetadata is user-supplied/derived SBOM root metadata.
	RootMetadata machineRootMetadata `json:"rootMetadata"`
	// Sandbox describes sandbox runtime state for the run.
	Sandbox machineSandbox `json:"sandbox"`
	// Extraction is the extraction tree root; nil if not available.
	Extraction *machineNode `json:"extraction"`
	// Scans contains one flattened entry per scan task.
	Scans []machineScan `json:"scans"`
	// Vulnerabilities contains optional Grype enrichment details.
	Vulnerabilities *machineVulnerabilities `json:"vulnerabilities,omitempty"`
	// Decisions contains policy decisions in processing order.
	Decisions []machineDecision `json:"decisions"`
	// Issues contains additional processing issues. It is omitted when empty.
	Issues []ProcessingIssue `json:"issues,omitempty"`
	// StartTime is UTC RFC3339 text.
	StartTime string `json:"startTime"`
	// EndTime is UTC RFC3339 text.
	EndTime string `json:"endTime"`
	// Duration is Go duration text, for example "1.25s".
	Duration string `json:"duration"`
}

// machineConfig captures the runtime configuration snapshot for machine output.
type machineConfig struct {
	// PolicyMode is policy mode text from config.PolicyMode.String().
	PolicyMode string `json:"policyMode"`
	// InterpretMode is interpretation mode text from config.InterpretMode.String().
	InterpretMode string `json:"interpretMode"`
	// Language is the configured report language code ("en" or "de").
	Language string `json:"language"`
	// Limits is the serialized limits snapshot.
	Limits machineLimits `json:"limits"`
}

// machineGenerator represents extract-sbom build metadata shown in JSON output.
type machineGenerator struct {
	// Version is the build version string.
	Version string `json:"version"`
	// Revision is the VCS revision string; omitted when unknown.
	Revision string `json:"revision,omitempty"`
	// Time is the build timestamp text; omitted when unknown.
	Time string `json:"time,omitempty"`
	// Modified reports whether the build tree was dirty.
	Modified bool `json:"modified"`
	// Display is a human-friendly combined build string.
	Display string `json:"display"`
}

// machineLimits is the serialized representation of configured safety limits.
type machineLimits struct {
	// MaxDepth is the recursion depth limit. Valid range: >= 0.
	MaxDepth int `json:"maxDepth"`
	// MaxFiles is the max-files limit. Valid range: >= 0.
	MaxFiles int `json:"maxFiles"`
	// MaxTotalSize is the aggregate extraction size limit in bytes. >= 0.
	MaxTotalSize int64 `json:"maxTotalSize"`
	// MaxEntrySize is the per-entry extraction size limit in bytes. >= 0.
	MaxEntrySize int64 `json:"maxEntrySize"`
	// MaxRatio is the compression/expansion ratio limit. Valid range: >= 0.
	MaxRatio int `json:"maxRatio"`
	// Timeout is Go duration text from config limits, for example "30s".
	Timeout string `json:"timeout"`
}

// machineRootMetadata stores root component metadata supplied or derived.
type machineRootMetadata struct {
	// Manufacturer is optional root component manufacturer text.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Name is optional root component name text.
	Name string `json:"name,omitempty"`
	// Version is optional root component version text.
	Version string `json:"version,omitempty"`
	// DeliveryDate is optional delivery date text as configured.
	DeliveryDate string `json:"deliveryDate,omitempty"`
	// Properties is optional user-defined key/value metadata.
	Properties map[string]string `json:"properties,omitempty"`
}

// machineSandbox captures sandbox availability and unsafe override state.
type machineSandbox struct {
	// Name is the sandbox strategy identifier.
	Name string `json:"name"`
	// Available reports whether the selected sandbox backend was available.
	Available bool `json:"available"`
	// Unsafe is true when --unsafe disabled isolation.
	Unsafe bool `json:"unsafe"`
}

// machineNode is one extraction-tree node in machine report format.
type machineNode struct {
	// Path is the logical extraction path in supplier-delivery notation.
	Path string `json:"path"`
	// Format is identify.FormatInfo.Format.String().
	Format string `json:"format"`
	// Status is extract status text, for example "extracted" or "failed".
	Status string `json:"status"`
	// StatusDetail is optional plain-text detail for status interpretation.
	StatusDetail string `json:"statusDetail,omitempty"`
	// Tool is the helper/tool name used for this node, when known.
	Tool string `json:"tool,omitempty"`
	// SandboxUsed is the sandbox mode actually used for this node.
	SandboxUsed string `json:"sandboxUsed,omitempty"`
	// Duration is Go duration text for this node.
	Duration string `json:"duration,omitempty"`
	// EntriesCount is the extracted child-entry count. Valid range: >= 0.
	EntriesCount int `json:"entriesCount,omitempty"`
	// TotalSize is the node payload size in bytes. Valid range: >= 0.
	TotalSize int64 `json:"totalSize,omitempty"`
	// Children contains nested extracted nodes. Omitted when empty.
	Children []*machineNode `json:"children,omitempty"`
}

// machineScan is one flattened scan result entry for machine output.
type machineScan struct {
	// NodePath is the logical extraction node path that was scanned.
	NodePath string `json:"nodePath"`
	// ComponentCount is the number of BOM components emitted by this scan task.
	// Valid range: >= 0.
	ComponentCount int `json:"componentCount"`
	// EvidencePaths contains task-level logical evidence paths ("/"-separated).
	// It is omitted when no task-level evidence paths were recorded.
	EvidencePaths []string `json:"evidencePaths,omitempty"`
	// Error contains plain-text task error content. Empty means success.
	Error string `json:"error,omitempty"`
}

// machineDecision is one policy-engine decision in machine-readable form.
type machineDecision struct {
	// Trigger is the policy trigger identifier.
	Trigger string `json:"trigger"`
	// NodePath is the logical extraction node path where trigger fired.
	NodePath string `json:"nodePath"`
	// Action is the policy action string, for example "continue", "skip", "abort".
	Action string `json:"action"`
	// Detail is plain-text diagnostic context for the decision.
	Detail string `json:"detail"`
}

// machineVulnerabilities is the JSON schema for Grype enrichment data in the
// machine report. It mirrors vulnscan.Result but uses plain string types for
// stable JSON serialization independently of the internal vulnscan model.
type machineVulnerabilities struct {
	// State is the enrichment outcome: "not-requested", "completed",
	// "completed-with-errors", or "unavailable".
	State string `json:"state"`
	// Requested is true when --grype was passed by the caller.
	Requested bool `json:"requested"`
	// GrypeVersion is the Grype binary version string. Omitted when unavailable.
	GrypeVersion string `json:"grypeVersion,omitempty"`
	// DBSchemaVersion is the Grype vulnerability DB schema version. Omitted when
	// unavailable.
	DBSchemaVersion string `json:"dbSchemaVersion,omitempty"`
	// DBBuilt is the Grype DB build timestamp text. Omitted when unavailable.
	DBBuilt string `json:"dbBuilt,omitempty"`
	// DBUpdated is the Grype descriptor timestamp (used as DB-updated proxy).
	// Omitted when unavailable.
	DBUpdated string `json:"dbUpdated,omitempty"`
	// MatchesByBOMRef maps each CycloneDX bom-ref to its matched vulnerability
	// entries. Omitted when empty.
	MatchesByBOMRef map[string][]vulnscan.VMatch `json:"matchesByBomRef,omitempty"`
	// CoverageByBOMRef maps each bom-ref to a coverage state ("found", "none",
	// "not-assessable"). Omitted when empty.
	CoverageByBOMRef map[string]vulnscan.CoverageState `json:"coverageByBomRef,omitempty"`
	// Errors lists non-fatal enrichment diagnostics. Omitted when empty.
	Errors []vulnscan.Issue `json:"errors,omitempty"`
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

// buildMachineVulnerabilities converts a vulnscan.Result to the machine-report
// schema. Returns nil when v is nil so the JSON field is omitted entirely for
// non-grype runs.
func buildMachineVulnerabilities(v *vulnscan.Result) *machineVulnerabilities {
	if v == nil {
		return nil
	}
	return &machineVulnerabilities{
		State:            string(v.State),
		Requested:        v.Requested,
		GrypeVersion:     v.GrypeVersion,
		DBSchemaVersion:  v.DBSchemaVersion,
		DBBuilt:          v.DBBuilt,
		DBUpdated:        v.DBUpdated,
		MatchesByBOMRef:  v.MatchesByBOMRef,
		CoverageByBOMRef: v.CoverageByBOMRef,
		Errors:           v.Errors,
	}
}
