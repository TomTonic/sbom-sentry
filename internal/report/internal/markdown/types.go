// Package markdown implements the active Markdown-based markdown report renderer.
package markdown

import (
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
)

// ToolVersions aliases the shared report tool-version contract from model.
type ToolVersions = model.ToolVersions

// InputSummary aliases the shared input summary contract from model.
type InputSummary = model.InputSummary

// SandboxSummary aliases the shared sandbox summary contract from model.
type SandboxSummary = model.SandboxSummary

// ProcessingIssue aliases the shared processing-issue contract from model.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract from model.
type ReportData = model.ReportData

// componentOccurrence aliases the JSON-facade occurrence view.
type componentOccurrence = reportjson.ComponentOccurrence

// packageOccurrenceGroup aliases the JSON-facade occurrence grouping view.
type packageOccurrenceGroup = reportjson.PackageOccurrenceGroup

// componentIndexStats aliases the occurrence indexing statistics view.
type componentIndexStats = reportjson.ComponentIndexStats

// extractionStats aliases extraction aggregation counters.
type extractionStats = reportjson.ExtractionStats

// scanStats aliases scan aggregation counters.
type scanStats = reportjson.ScanStats

// policyStats aliases policy aggregation counters.
type policyStats = reportjson.PolicyStats

// processingEntry is a flattened log row for the processing-issues table.
type processingEntry struct {
	Source         string
	Location       string
	Classification string
	Status         string
	DetectedFormat string
	Tool           string
	ArchiveType    string
	ArchiveMethod  string
	Encrypted      string
	PhysicalSize   string
	Detail         string
}

// reportSection defines one TOC entry and heading anchor in the markdown report.
type reportSection struct {
	title  string
	anchor string
	level  int
}

const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

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
	anchorScanNoPackageIDs       = "content-items-without-package-identities"
	anchorExtraction             = "extraction-log"
	anchorSummaryAnalysis        = "analysis-overview"
	anchorSummaryKeyFindings     = "key-findings"
	anchorSummaryVuln            = "vulnerability-summary"
)
