// Package json implements the structured JSON audit report renderer.
package json

import (
	"encoding/json"
	"io"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// InputSummary aliases the shared report input summary contract.
type InputSummary = model.InputSummary

// ToolVersions aliases the shared report tool-version contract.
type ToolVersions = model.ToolVersions

// SandboxSummary aliases the shared sandbox summary contract.
type SandboxSummary = model.SandboxSummary

// ProcessingIssue aliases the shared structured processing issue contract.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract.
type ReportData = model.ReportData

// Generate writes a structured JSON audit report to the writer.
func Generate(data ReportData, w io.Writer) error {
	report := jsonReport{
		SchemaVersion: "1.0.0",
		Input:         data.Input,
		Generator: jsonGenerator{
			Version:  data.Generator.Version,
			Revision: data.Generator.Revision,
			Time:     data.Generator.Time,
			Modified: data.Generator.Modified,
			Display:  data.Generator.String(),
		},
		Config: jsonConfig{
			PolicyMode:    data.Config.PolicyMode.String(),
			InterpretMode: data.Config.InterpretMode.String(),
			Language:      data.Config.Language,
			Limits: jsonLimits{
				MaxDepth:     data.Config.Limits.MaxDepth,
				MaxFiles:     data.Config.Limits.MaxFiles,
				MaxTotalSize: data.Config.Limits.MaxTotalSize,
				MaxEntrySize: data.Config.Limits.MaxEntrySize,
				MaxRatio:     data.Config.Limits.MaxRatio,
				Timeout:      data.Config.Limits.Timeout.String(),
			},
		},
		RootMetadata: jsonRootMetadata{
			Manufacturer: data.Config.RootMetadata.Manufacturer,
			Name:         data.Config.RootMetadata.Name,
			Version:      data.Config.RootMetadata.Version,
			DeliveryDate: data.Config.RootMetadata.DeliveryDate,
			Properties:   data.Config.RootMetadata.Properties,
		},
		Sandbox: jsonSandbox{
			Name:      data.SandboxInfo.Name,
			Available: data.SandboxInfo.Available,
			Unsafe:    data.SandboxInfo.UnsafeOvr,
		},
		Extraction:      buildTree(data.Tree),
		Scans:           buildScans(data.Scans),
		Vulnerabilities: buildVulnerabilities(data.Vulnerabilities),
		Decisions:       buildDecisions(data.PolicyDecisions),
		Issues:          data.ProcessingIssues,
		StartTime:       data.StartTime.UTC().Format(time.RFC3339),
		EndTime:         data.EndTime.UTC().Format(time.RFC3339),
		Duration:        data.EndTime.Sub(data.StartTime).String(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

type jsonReport struct {
	SchemaVersion   string               `json:"schemaVersion"`
	Input           InputSummary         `json:"input"`
	Generator       jsonGenerator        `json:"generator"`
	Config          jsonConfig           `json:"config"`
	RootMetadata    jsonRootMetadata     `json:"rootMetadata"`
	Sandbox         jsonSandbox          `json:"sandbox"`
	Extraction      *jsonNode            `json:"extraction"`
	Scans           []jsonScan           `json:"scans"`
	Vulnerabilities *jsonVulnerabilities `json:"vulnerabilities,omitempty"`
	Decisions       []jsonDecision       `json:"decisions"`
	Issues          []ProcessingIssue    `json:"issues,omitempty"`
	StartTime       string               `json:"startTime"`
	EndTime         string               `json:"endTime"`
	Duration        string               `json:"duration"`
}

type jsonConfig struct {
	PolicyMode    string     `json:"policyMode"`
	InterpretMode string     `json:"interpretMode"`
	Language      string     `json:"language"`
	Limits        jsonLimits `json:"limits"`
}

type jsonGenerator struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

type jsonLimits struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

type jsonRootMetadata struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

type jsonSandbox struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Unsafe    bool   `json:"unsafe"`
}

type jsonNode struct {
	Path         string      `json:"path"`
	Format       string      `json:"format"`
	Status       string      `json:"status"`
	StatusDetail string      `json:"statusDetail,omitempty"`
	Tool         string      `json:"tool,omitempty"`
	SandboxUsed  string      `json:"sandboxUsed,omitempty"`
	Duration     string      `json:"duration,omitempty"`
	EntriesCount int         `json:"entriesCount,omitempty"`
	TotalSize    int64       `json:"totalSize,omitempty"`
	Children     []*jsonNode `json:"children,omitempty"`
}

type jsonScan struct {
	NodePath       string   `json:"nodePath"`
	ComponentCount int      `json:"componentCount"`
	EvidencePaths  []string `json:"evidencePaths,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type jsonDecision struct {
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

type jsonVulnerabilities struct {
	State            string                            `json:"state"`
	Requested        bool                              `json:"requested"`
	GrypeVersion     string                            `json:"grypeVersion,omitempty"`
	DBSchemaVersion  string                            `json:"dbSchemaVersion,omitempty"`
	DBBuilt          string                            `json:"dbBuilt,omitempty"`
	DBUpdated        string                            `json:"dbUpdated,omitempty"`
	MatchesByBOMRef  map[string][]vulnscan.VMatch      `json:"matchesByBomRef,omitempty"`
	CoverageByBOMRef map[string]vulnscan.CoverageState `json:"coverageByBomRef,omitempty"`
	Errors           []vulnscan.Issue                  `json:"errors,omitempty"`
}

func buildTree(node *extract.ExtractionNode) *jsonNode {
	if node == nil {
		return nil
	}

	jn := &jsonNode{
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
		jn.Children = append(jn.Children, buildTree(child))
	}

	return jn
}

func buildScans(scans []scan.ScanResult) []jsonScan {
	result := make([]jsonScan, len(scans))
	for i, s := range scans {
		js := jsonScan{NodePath: s.NodePath}
		if s.Error != nil {
			js.Error = s.Error.Error()
		}
		if s.BOM != nil && s.BOM.Components != nil {
			js.ComponentCount = len(*s.BOM.Components)
		}
		js.EvidencePaths = scan.FlattenEvidencePaths(s)
		result[i] = js
	}
	return result
}

func buildDecisions(decisions []policy.Decision) []jsonDecision {
	result := make([]jsonDecision, len(decisions))
	for i, d := range decisions {
		result[i] = jsonDecision{
			Trigger:  d.Trigger,
			NodePath: d.NodePath,
			Action:   d.Action.String(),
			Detail:   d.Detail,
		}
	}
	return result
}

func buildVulnerabilities(v *vulnscan.Result) *jsonVulnerabilities {
	if v == nil {
		return nil
	}
	state, requested := normalizedVulnEnrichmentState(v)
	return &jsonVulnerabilities{
		State:            string(state),
		Requested:        requested,
		GrypeVersion:     v.GrypeVersion,
		DBSchemaVersion:  v.DBSchemaVersion,
		DBBuilt:          v.DBBuilt,
		DBUpdated:        v.DBUpdated,
		MatchesByBOMRef:  v.MatchesByBOMRef,
		CoverageByBOMRef: v.CoverageByBOMRef,
		Errors:           v.Errors,
	}
}

func normalizedVulnEnrichmentState(v *vulnscan.Result) (vulnscan.State, bool) {
	state := vulnscan.StateNotRequested
	requested := false
	if v != nil {
		requested = v.Requested
		if v.State != "" {
			state = v.State
		}
	}
	return state, requested
}
