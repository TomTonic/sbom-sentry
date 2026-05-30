package json

import (
	"errors"
	"fmt"
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

// NormalizeSeverity canonicalizes vulnerability severity strings.
func NormalizeSeverity(raw string) string {
	return domain.NormalizeSeverity(raw)
}

// ReportDataFromV2 reconstructs the shared report snapshot from the canonical JSON model.
//
// The second return value lists any fields that could not be parsed exactly;
// defaults are substituted and callers may log or surface the warnings for diagnostics.
func ReportDataFromV2(report ReportV2) (ReportData, []string) {
	var warnings []string

	limits := config.DefaultLimits()
	if parsedTimeout, err := time.ParseDuration(report.Config.Limits.Timeout); err == nil {
		limits.Timeout = parsedTimeout
	} else if report.Config.Limits.Timeout != "" {
		warnings = append(warnings, fmt.Sprintf("config.limits.timeout %q could not be parsed, using default: %v", report.Config.Limits.Timeout, err))
	}
	limits.MaxDepth = report.Config.Limits.MaxDepth
	limits.MaxFiles = report.Config.Limits.MaxFiles
	limits.MaxTotalSize = report.Config.Limits.MaxTotalSize
	limits.MaxEntrySize = report.Config.Limits.MaxEntrySize
	limits.MaxRatio = report.Config.Limits.MaxRatio

	policyMode, err := config.ParsePolicyMode(report.Config.PolicyMode)
	if err != nil {
		policyMode = config.PolicyPartial
		warnings = append(warnings, fmt.Sprintf("config.policyMode %q not recognized, using default: %v", report.Config.PolicyMode, err))
	}
	interpretMode, err := config.ParseInterpretMode(report.Config.InterpretMode)
	if err != nil {
		interpretMode = config.InterpretPhysical
		warnings = append(warnings, fmt.Sprintf("config.interpretMode %q not recognized, using default: %v", report.Config.InterpretMode, err))
	}
	reportSelection, err := config.ParseReportSelection(report.Config.ReportSelection)
	if err != nil {
		reportSelection = config.ReportMarkdown
		warnings = append(warnings, fmt.Sprintf("config.reportSelection %q not recognized, using default: %v", report.Config.ReportSelection, err))
	}
	progressLevel, err := config.ParseProgressLevel(report.Config.ProgressLevel)
	if err != nil {
		progressLevel = config.ProgressNormal
		warnings = append(warnings, fmt.Sprintf("config.progressLevel %q not recognized, using default: %v", report.Config.ProgressLevel, err))
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
	if startTime.IsZero() && report.Run.StartTime != "" {
		warnings = append(warnings, fmt.Sprintf("run.startTime %q could not be parsed as RFC3339, using zero time", report.Run.StartTime))
	}
	endTime := parseRFC3339OrZero(report.Run.EndTime)
	if endTime.IsZero() && report.Run.EndTime != "" {
		warnings = append(warnings, fmt.Sprintf("run.endTime %q could not be parsed as RFC3339, using zero time", report.Run.EndTime))
	}

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
		Vulnerabilities: fromVulnerabilityResultV2(report.Raw.VulnerabilitiesRaw),
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
	}, warnings
}

func parseRFC3339OrZero(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// fromVulnerabilityResultV2 reconstructs a vulnscan.Result from the canonical report snapshot.
//
// This is the single coupling point where the json package maps the report schema back to
// vulnscan types for downstream markdown/html renderers. It is the inverse of toVulnerabilityResultV2.
func fromVulnerabilityResultV2(v *vulnerabilityResultV2) *vulnscan.Result {
	if v == nil {
		return nil
	}
	out := &vulnscan.Result{
		State:            vulnscan.State(v.State),
		Requested:        v.Requested,
		GrypeVersion:     v.GrypeVersion,
		DBSchemaVersion:  v.DBSchemaVersion,
		DBBuilt:          v.DBBuilt,
		DBUpdated:        v.DBUpdated,
		MatchesByBOMRef:  map[string][]vulnscan.VMatch{},
		CoverageByBOMRef: map[string]vulnscan.CoverageState{},
	}
	for ref, matches := range v.MatchesByBOMRef {
		native := make([]vulnscan.VMatch, len(matches))
		for i := range matches {
			m := &matches[i]
			native[i] = vulnscan.VMatch{
				VulnerabilityID: m.VulnerabilityID,
				Severity:        m.Severity,
				CVSSScore:       m.CVSSScore,
				CVSSVersion:     m.CVSSVersion,
				CVSSVector:      m.CVSSVector,
				Description:     m.Description,
				Namespace:       m.Namespace,
				DataSource:      m.DataSource,
				URLs:            append([]string(nil), m.URLs...),
				FixState:        m.FixState,
				FixVersions:     append([]string(nil), m.FixVersions...),
				Matcher:         m.Matcher,
				MatchType:       m.MatchType,
				ArtifactName:    m.ArtifactName,
				ArtifactVersion: m.ArtifactVersion,
				ArtifactType:    m.ArtifactType,
				ArtifactPURL:    m.ArtifactPURL,
				EPSS:            m.EPSS,
				EPSSPercentile:  m.EPSSPercentile,
				Risk:            m.Risk,
				KEV:             m.KEV,
			}
		}
		out.MatchesByBOMRef[ref] = native
	}
	for ref, cov := range v.CoverageByBOMRef {
		out.CoverageByBOMRef[ref] = vulnscan.CoverageState(cov)
	}
	for _, e := range v.Errors {
		out.Errors = append(out.Errors, vulnscan.Issue{Code: e.Code, Message: e.Message})
	}
	return out
}
