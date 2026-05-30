package json

import (
	"fmt"
	"sort"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// MarkdownSummaryTemplates contains localized text templates for summary rendering.
type MarkdownSummaryTemplates struct {
	SummaryAnalysisProseTemplate           string
	FindingDeliveryCompositionTemplate     string
	FindingExtractionStatusFailureTemplate string
	FindingExtractionStatusSuccessTemplate string
	FindingVulnMatchesTemplate             string
	FindingVulnNoMatches                   string
	FindingToolMissingTemplate             string
	FindingExtractionGapTemplate           string
	FindingScanFailedTemplate              string
	FindingPURLCoverageTemplate            string
	FindingNoPackageIdentityTemplate       string
	FindingPolicyDecisionsTemplate         string
	FindingProcessingIssuesTemplate        string
	FindingNoCriticalLimitations           string
	NoneValue                              string
}

// MarkdownSummaryLinks contains prebuilt section links and anchors used in findings.
type MarkdownSummaryLinks struct {
	SummaryVulnerabilityLink      string
	ScanNoPackageIdentitiesLink   string
	PolicyLink                    string
	ProcessingIssuesLink          string
	ComponentsWithPURLAnchorID    string
	ComponentsWithoutPURLAnchorID string
}

// BuildMarkdownSummaryAnalysis returns the localized analysis overview sentence.
func BuildMarkdownSummaryAnalysis(ext ExtractionStats, idx ComponentIndexStats, tmpl MarkdownSummaryTemplates) string {
	return fmt.Sprintf(
		tmpl.SummaryAnalysisProseTemplate,
		ext.Total, idx.IndexedComponents, idx.IndexedWithPURL, idx.IndexedWithoutPURL,
	)
}

// BuildMarkdownSummaryFindings computes localized findings lines from report aggregates.
func BuildMarkdownSummaryFindings(data ReportData, ext ExtractionStats, scn ScanStats, pol PolicyStats, idx ComponentIndexStats, occurrences []ComponentOccurrence, pipelineIssues int, tmpl MarkdownSummaryTemplates, links MarkdownSummaryLinks) []string {
	findings := make([]string, 0, 12)
	vulnMatches, vulnUnique, vulnAffected := domain.CollectVulnStats(data.Vulnerabilities)
	distinctPackages := countDistinctPackages(occurrences)

	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			tmpl.FindingDeliveryCompositionTemplate,
			ext.Extracted, ext.TotalFileEntries, idx.IndexedComponents, distinctPackages,
		))
	}

	if ext.Failed+ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf(
			tmpl.FindingExtractionStatusFailureTemplate,
			ext.Failed+ext.SecurityBlocked,
		))
	} else if ext.Total > 0 {
		findings = append(findings, tmpl.FindingExtractionStatusSuccessTemplate)
	}

	if vulnerabilityRequested(data.Vulnerabilities) {
		if vulnMatches > 0 {
			findings = append(findings, fmt.Sprintf(
				tmpl.FindingVulnMatchesTemplate,
				vulnMatches, vulnAffected, vulnUnique,
				links.SummaryVulnerabilityLink,
			))
		} else if data.Vulnerabilities != nil && (data.Vulnerabilities.State == vulnscan.StateCompleted || data.Vulnerabilities.State == vulnscan.StateCompletedWithErrors) {
			findings = append(findings, tmpl.FindingVulnNoMatches)
		}
	}
	if ext.ToolMissing > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingToolMissingTemplate, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, tmpl.NoneValue)))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingExtractionGapTemplate, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), tmpl.NoneValue)))
	}
	if scn.Errors > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingScanFailedTemplate, scn.Errors, samplePaths(scn.ErrorPaths, tmpl.NoneValue)))
	}
	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			tmpl.FindingPURLCoverageTemplate,
			idx.IndexedWithPURL, idx.IndexedComponents, links.ComponentsWithPURLAnchorID,
			idx.IndexedWithoutPURL, links.ComponentsWithoutPURLAnchorID,
		))
	}
	if scn.NoComponentTasks > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingNoPackageIdentityTemplate, scn.NoComponentTasks, links.ScanNoPackageIdentitiesLink, samplePaths(scn.NoComponentPaths, tmpl.NoneValue)))
	}
	if pol.Total > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingPolicyDecisionsTemplate, pol.Total, links.PolicyLink))
	}
	if pipelineIssues > 0 {
		findings = append(findings, fmt.Sprintf(tmpl.FindingProcessingIssuesTemplate, pipelineIssues, links.ProcessingIssuesLink))
	}
	if len(findings) == 0 {
		findings = append(findings, tmpl.FindingNoCriticalLimitations)
	}
	return findings
}

// MarkdownResidualRiskTemplates contains localized text templates for residual-risk rendering.
type MarkdownResidualRiskTemplates struct {
	ResidualRiskPURLCoverage         string
	ResidualRiskEvidenceCoverage     string
	ResidualRiskNoComponentTasks     string
	ResidualRiskFileArtifactCoverage string
	ResidualRiskExtensionFilter      string
	ResidualRiskExtractionGap        string
	ResidualRiskToolGap              string
	ResidualRiskScanGap              string
	ResidualRiskMoreDetails          string
	NoneValue                        string
}

// MarkdownResidualRiskLinks contains prebuilt section links for residual risk lines.
type MarkdownResidualRiskLinks struct {
	ScanNoPackageIdentitiesLink     string
	SuppressionFSArtifactsLink      string
	SuppressionLowValueLink         string
	ExtensionFilterLink             string
	PackageDetectionReliabilityLink string
	ComponentsWithPURLAnchorID      string
	ComponentsWithoutPURLAnchorID   string
}

// MarkdownResidualRiskModel is the precomputed residual-risk detail payload.
type MarkdownResidualRiskModel struct {
	PURLLine          string
	EvidenceLine      string
	NoComponentLine   string
	FileArtifactLine  string
	ExtensionLine     string
	ExtractionGapLine string
	ToolGapLine       string
	ScanGapLine       string
	MoreDetailsLine   string
}

// BuildMarkdownResidualRiskModel precomputes residual-risk section detail lines.
func BuildMarkdownResidualRiskModel(data ReportData, ext ExtractionStats, scn ScanStats, idx ComponentIndexStats, tmpl MarkdownResidualRiskTemplates, links MarkdownResidualRiskLinks) MarkdownResidualRiskModel {
	model := MarkdownResidualRiskModel{}

	if idx.IndexedComponents > 0 {
		purlLine := fmt.Sprintf(tmpl.ResidualRiskPURLCoverage, idx.IndexedWithPURL, idx.IndexedComponents, idx.IndexedWithoutPURL)
		withPURLLink := fmt.Sprintf("[%d](#%s)", idx.IndexedWithPURL, links.ComponentsWithPURLAnchorID)
		withoutPURLLink := fmt.Sprintf("[%d](#%s)", idx.IndexedWithoutPURL, links.ComponentsWithoutPURLAnchorID)
		// Keep compatibility with existing EN/DE template phrases.
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d of %d indexed", idx.IndexedWithPURL, idx.IndexedComponents), fmt.Sprintf("%s of %d indexed", withPURLLink, idx.IndexedComponents), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexed occurrences do not", idx.IndexedWithoutPURL), fmt.Sprintf("%s indexed occurrences do not", withoutPURLLink), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexierte Vorkommen haben keine PURL", idx.IndexedWithoutPURL), fmt.Sprintf("%s indexierte Vorkommen haben keine PURL", withoutPURLLink), 1)
		model.PURLLine = purlLine
		model.EvidenceLine = fmt.Sprintf(tmpl.ResidualRiskEvidenceCoverage, idx.IndexedWithEvidencePath, idx.IndexedWithEvidenceSourceOnly, idx.IndexedWithoutEvidence)
	}
	if scn.Successful > 0 {
		model.NoComponentLine = fmt.Sprintf("%s %s", fmt.Sprintf(tmpl.ResidualRiskNoComponentTasks, scn.NoComponentTasks, scn.Successful, samplePaths(scn.NoComponentPaths, tmpl.NoneValue)), links.ScanNoPackageIdentitiesLink)
	}
	suppression := CollectSuppressionStats(data.Suppressions)
	fileArtifactCount := suppression.FSArtifacts + suppression.LowValueFiles
	if fileArtifactCount > 0 {
		linkParts := make([]string, 0, 2)
		if suppression.FSArtifacts > 0 {
			linkParts = append(linkParts, links.SuppressionFSArtifactsLink)
		}
		if suppression.LowValueFiles > 0 {
			linkParts = append(linkParts, links.SuppressionLowValueLink)
		}
		model.FileArtifactLine = fmt.Sprintf("%s %s", fmt.Sprintf(tmpl.ResidualRiskFileArtifactCoverage, fileArtifactCount), strings.Join(linkParts, ", "))
	}
	if ext.ExtensionFiltered > 0 {
		model.ExtensionLine = fmt.Sprintf(tmpl.ResidualRiskExtensionFilter, ext.ExtensionFiltered, links.ExtensionFilterLink)
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		model.ExtractionGapLine = fmt.Sprintf(tmpl.ResidualRiskExtractionGap, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), tmpl.NoneValue))
	}
	if ext.ToolMissing > 0 {
		model.ToolGapLine = fmt.Sprintf(tmpl.ResidualRiskToolGap, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, tmpl.NoneValue))
	}
	if scn.Errors > 0 {
		model.ScanGapLine = fmt.Sprintf(tmpl.ResidualRiskScanGap, scn.Errors, samplePaths(scn.ErrorPaths, tmpl.NoneValue))
	}
	model.MoreDetailsLine = fmt.Sprintf(tmpl.ResidualRiskMoreDetails, links.PackageDetectionReliabilityLink)
	return model
}

// FormatMarkdownConfigSkipExtensions returns the compact config table value for skip extensions.
func FormatMarkdownConfigSkipExtensions(exts []string) string {
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

func vulnerabilityRequested(v *vulnscan.Result) bool {
	return v != nil && v.Requested && v.State != vulnscan.StateNotRequested
}

func countDistinctPackages(occurrences []ComponentOccurrence) int {
	seen := make(map[string]bool)
	for i := range occurrences {
		key := occurrences[i].PackageName + "|" + occurrences[i].Version
		seen[key] = true
	}
	return len(seen)
}

func samplePaths(paths []string, noneValue string) string {
	const maxCount = 3
	if len(paths) == 0 {
		return noneValue
	}

	unique := SortedUniqueNonEmptyStrings(paths)
	if len(unique) <= maxCount {
		return strings.Join(unique, "; ")
	}
	return strings.Join(unique[:maxCount], "; ") + fmt.Sprintf(" (+%d more)", len(unique)-maxCount)
}

// SamplePathsForMarkdown returns a compact sample-path string for renderer output.
func SamplePathsForMarkdown(paths []string, noneValue string) string {
	return samplePaths(paths, noneValue)
}
