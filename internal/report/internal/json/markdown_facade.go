package json

import (
	"errors"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// ComponentOccurrence exposes the normalized component-occurrence view for renderers.
type ComponentOccurrence = domain.ComponentOccurrence

// PackageOccurrenceGroup exposes deterministic package grouping for renderers.
type PackageOccurrenceGroup = domain.PackageOccurrenceGroup

// ComponentIndexStats exposes indexed-component coverage counters.
type ComponentIndexStats = domain.ComponentIndexStats

// ExtractionStats exposes extraction aggregate counters.
type ExtractionStats = domain.ExtractionStats

// ScanStats exposes scan aggregate counters.
type ScanStats = domain.ScanStats

// PolicyStats exposes policy aggregate counters.
type PolicyStats = domain.PolicyStats

// SuppressionStats exposes suppression aggregate counters.
type SuppressionStats = domain.SuppressionStats

// CollectComponentOccurrences returns normalized component occurrences and index stats.
func CollectComponentOccurrences(bom *cdx.BOM) ([]ComponentOccurrence, ComponentIndexStats) {
	return domain.CollectComponentOccurrences(bom)
}

// BuildPackageOccurrenceGroups groups occurrences by package identity.
func BuildPackageOccurrenceGroups(occurrences []ComponentOccurrence) []PackageOccurrenceGroup {
	return domain.BuildPackageOccurrenceGroups(occurrences)
}

// OccurrenceAnchorID returns a stable markdown anchor ID for one component occurrence.
func OccurrenceAnchorID(objectID string) string {
	return domain.OccurrenceAnchorID(objectID)
}

// OccurrenceQualityScore returns a deterministic score for replacement selection.
func OccurrenceQualityScore(occ ComponentOccurrence) int {
	return domain.OccurrenceQualityScore(occ)
}

// CollectExtractionStats aggregates extraction-tree coverage and issue counters.
func CollectExtractionStats(tree *extract.ExtractionNode) ExtractionStats {
	return domain.CollectExtractionStats(tree)
}

// CollectScanStats aggregates scan-task counters.
func CollectScanStats(scans []scan.ScanResult) ScanStats {
	return domain.CollectScanStats(scans)
}

// CollectPolicyStats aggregates policy decision counters.
func CollectPolicyStats(decisions []policy.Decision) PolicyStats {
	return domain.CollectPolicyStats(decisions)
}

// CollectSuppressionStats aggregates suppression counters.
func CollectSuppressionStats(records []assembly.SuppressionRecord) SuppressionStats {
	return domain.CollectSuppressionStats(records)
}

// CollectVulnStats aggregates vulnerability match counters.
func CollectVulnStats(v *vulnscan.Result) (int, int, int) {
	return domain.CollectVulnStats(v)
}

// SortedUniqueNonEmptyStrings deduplicates and sorts non-empty strings.
func SortedUniqueNonEmptyStrings(in []string) []string {
	return domain.SortedUniqueNonEmptyStrings(in)
}

// ReportDataFromV2 reconstructs the shared report snapshot from the canonical JSON model.
func ReportDataFromV2(report ReportV2) ReportData {
	limits := config.DefaultLimits()
	if parsedTimeout, err := time.ParseDuration(report.Config.Limits.Timeout); err == nil {
		limits.Timeout = parsedTimeout
	}
	limits.MaxDepth = report.Config.Limits.MaxDepth
	limits.MaxFiles = report.Config.Limits.MaxFiles
	limits.MaxTotalSize = report.Config.Limits.MaxTotalSize
	limits.MaxEntrySize = report.Config.Limits.MaxEntrySize
	limits.MaxRatio = report.Config.Limits.MaxRatio

	policyMode, err := config.ParsePolicyMode(report.Config.PolicyMode)
	if err != nil {
		policyMode = config.PolicyPartial
	}
	interpretMode, err := config.ParseInterpretMode(report.Config.InterpretMode)
	if err != nil {
		interpretMode = config.InterpretPhysical
	}
	reportSelection, err := config.ParseReportSelection(report.Config.ReportSelection)
	if err != nil {
		reportSelection = config.ReportMarkdown
	}
	progressLevel, err := config.ParseProgressLevel(report.Config.ProgressLevel)
	if err != nil {
		progressLevel = config.ProgressNormal
	}

	scans := make([]scan.ScanResult, 0, len(report.Raw.ScansRaw))
	for i := range report.Raw.ScansRaw {
		sr := scan.ScanResult{
			NodePath:      report.Raw.ScansRaw[i].NodePath,
			BOM:           report.Raw.ScansRaw[i].BOM,
			EvidencePaths: report.Raw.ScansRaw[i].EvidencePaths,
		}
		if report.Raw.ScansRaw[i].Error != "" {
			sr.Error = errors.New(report.Raw.ScansRaw[i].Error)
		}
		scans = append(scans, sr)
	}

	startTime := parseRFC3339OrZero(report.Run.StartTime)
	endTime := parseRFC3339OrZero(report.Run.EndTime)

	return ReportData{
		Input: InputSummary{
			Filename: report.Input.Filename,
			Size:     report.Input.Size,
			SHA256:   report.Input.SHA256,
			SHA512:   report.Input.SHA512,
		},
		Generator: buildinfo.Info{
			Version:  report.Generator.Version,
			Revision: report.Generator.Revision,
			Time:     report.Generator.Time,
			Modified: report.Generator.Modified,
		},
		Config: config.Config{
			SBOMFormat:           report.Config.SBOMFormat,
			PolicyMode:           policyMode,
			InterpretMode:        interpretMode,
			ReportSelection:      reportSelection,
			ProgressLevel:        progressLevel,
			Language:             report.Config.Language,
			MarkdownRenderEngine: report.Config.MarkdownRenderEngine,
			MarkdownTemplateFile: report.Config.MarkdownTemplateFile,
			GrypeEnabled:         report.Config.GrypeEnabled,
			RootMetadata: config.RootMetadata{
				Manufacturer: report.Config.RootMetadata.Manufacturer,
				Name:         report.Config.RootMetadata.Name,
				Version:      report.Config.RootMetadata.Version,
				DeliveryDate: report.Config.RootMetadata.DeliveryDate,
				Properties:   report.Config.RootMetadata.Properties,
			},
			Unsafe:           report.Config.Unsafe,
			Limits:           limits,
			ParallelScanners: report.Config.ParallelScanners,
			SkipExtensions:   append([]string(nil), report.Config.SkipExtensions...),
		},
		Tree:            report.Raw.ExtractionTreeRaw,
		Scans:           scans,
		Vulnerabilities: report.Raw.VulnerabilitiesRaw,
		PolicyDecisions: append([]policy.Decision(nil), report.Raw.PolicyDecisionsRaw...),
		SandboxInfo: SandboxSummary{
			Name:      report.Runtime.Sandbox.Name,
			Available: report.Runtime.Sandbox.Available,
			UnsafeOvr: report.Runtime.Sandbox.UnsafeOverride,
		},
		ProcessingIssues: append([]ProcessingIssue(nil), report.Raw.ProcessingIssuesRaw...),
		StartTime:        startTime,
		EndTime:          endTime,
		BOM:              report.Raw.BOMRaw,
		SBOMPath:         report.Raw.ArtifactPaths.SBOMPath,
		Suppressions:     append([]assembly.SuppressionRecord(nil), report.Raw.SuppressionsRaw...),
		ToolVersions: ToolVersions{
			SevenZip:   report.Runtime.ToolVersions.SevenZip,
			Unshield:   report.Runtime.ToolVersions.Unshield,
			Unsquashfs: report.Runtime.ToolVersions.Unsquashfs,
			Grype:      report.Runtime.ToolVersions.Grype,
			GrypeDB:    report.Runtime.ToolVersions.GrypeDB,
		},
	}
}

func parseRFC3339OrZero(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
