package markdown

import (
	"fmt"
	"io"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// writeMethodOverview writes a concise explanation of pipeline method and
// links to the detailed scan-approach document.
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
		scanApproachLink(t.linkTwoPhases, "3-two-phases"),
		scanApproachLink(t.linkScanDetail, "7-how-the-scan-phase-works-in-detail"),
		scanApproachLink(t.linkFinalSBOMBuild, "8-how-the-final-sbom-is-built"),
		scanApproachLink(t.linkDeduplication, "81-how-deduplication-works"),
		scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability"),
	)
}

// writeSummary renders the executive summary with sub-sections for analysis
// overview, key findings, and vulnerability summary.
func writeSummary(w io.Writer, data ReportData, ext extractionStats, scn scanStats, pol policyStats, idx componentIndexStats, occurrences []componentOccurrence, t translations) {
	if vulnerabilityRequested(data.Vulnerabilities) {
		fmt.Fprintln(w, t.summaryLead)
	} else {
		fmt.Fprintln(w, t.summaryLeadNoVuln)
	}
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryAnalysisSection, anchorSummaryAnalysis)
	writeAnalysisOverview(w, ext, idx, t)
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryKeyFindingsSection, anchorSummaryKeyFindings)
	vulnMatches, vulnUnique, vulnAffected := reportjson.CollectVulnStats(data.Vulnerabilities)
	distinctPackages := countDistinctPackages(occurrences)
	findings := summarizeFindings(ext, scn, idx, pol, len(data.ProcessingIssues), data.Vulnerabilities, vulnMatches, vulnUnique, vulnAffected, distinctPackages, t)
	for _, finding := range findings {
		fmt.Fprintf(w, "- %s\n\n", finding)
	}

	writeAnchoredHeading(w, 3, t.summaryVulnSection, anchorSummaryVuln)
	writeVulnerabilitySummary(w, data, occurrences, t)
}

// writeAnalysisOverview writes the prose paragraph that describes what was
// found, using user-domain language (delivery, packages, PURL).
func writeAnalysisOverview(w io.Writer, ext extractionStats, idx componentIndexStats, t translations) {
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(
		t.summaryAnalysisProseTemplate,
		ext.Total, idx.IndexedComponents, idx.IndexedWithPURL, idx.IndexedWithoutPURL,
	))
	fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.summaryAnalysisMethodRef, sectionLink(t.methodOverviewSection, anchorMethodOverview)))
}

// summarizeFindings derives short, operator-friendly findings from collected
// extraction, scan, component-index, policy, and pipeline statistics.
// When vulnerability enrichment actually ran, a vulnerability finding bullet
// is prepended.
func summarizeFindings(ext extractionStats, scn scanStats, idx componentIndexStats, pol policyStats, pipelineIssues int, v *vulnscan.Result, vulnMatches, vulnUnique, vulnAffected int, distinctPackages int, t translations) []string {
	findings := make([]string, 0, 12)

	// Delivery composition finding
	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			t.findingDeliveryCompositionTemplate,
			ext.Extracted, ext.TotalFileEntries, idx.IndexedComponents, distinctPackages,
		))
	}

	// Extraction status finding
	if ext.Failed+ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf(
			t.findingExtractionStatusFailureTemplate,
			ext.Failed+ext.SecurityBlocked,
		))
	} else if ext.Total > 0 {
		findings = append(findings, t.findingExtractionStatusSuccessTemplate)
	}

	if vulnerabilityRequested(v) {
		if vulnMatches > 0 {
			findings = append(findings, fmt.Sprintf(
				t.findingVulnMatchesTemplate,
				vulnMatches, vulnAffected, vulnUnique,
				sectionLink(t.summaryVulnSection, anchorSummaryVuln),
			))
		} else if v.State == vulnscan.StateCompleted || v.State == vulnscan.StateCompletedWithErrors {
			findings = append(findings, t.findingVulnNoMatches)
		}
	}
	if ext.ToolMissing > 0 {
		findings = append(findings, fmt.Sprintf(t.findingToolMissingTemplate, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, t.noneValue)))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf(t.findingExtractionGapTemplate, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), t.noneValue)))
	}
	if scn.Errors > 0 {
		findings = append(findings, fmt.Sprintf(t.findingScanFailedTemplate, scn.Errors, samplePaths(scn.ErrorPaths, t.noneValue)))
	}
	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			t.findingPURLCoverageTemplate,
			idx.IndexedWithPURL, idx.IndexedComponents, anchorComponentsWithPURL,
			idx.IndexedWithoutPURL, anchorComponentsWithoutPURL,
		))
	}
	if scn.NoComponentTasks > 0 {
		findings = append(findings, fmt.Sprintf(t.findingNoPackageIdentityTemplate, scn.NoComponentTasks, sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs), samplePaths(scn.NoComponentPaths, t.noneValue)))
	}
	if pol.Total > 0 {
		findings = append(findings, fmt.Sprintf(t.findingPolicyDecisionsTemplate, pol.Total, sectionLink(t.policySection, anchorPolicy)))
	}
	if pipelineIssues > 0 {
		findings = append(findings, fmt.Sprintf(t.findingProcessingIssuesTemplate, pipelineIssues, sectionLink(t.processingIssuesSection, anchorProcessingErrors)))
	}
	if len(findings) == 0 {
		findings = append(findings, t.findingNoCriticalLimitations)
	}
	return findings
}

func vulnerabilityRequested(v *vulnscan.Result) bool {
	return v != nil && v.Requested && v.State != vulnscan.StateNotRequested
}

// countDistinctPackages counts the number of distinct software packages
// (by name+version pair) in the occurrence list.
func countDistinctPackages(occurrences []componentOccurrence) int {
	seen := make(map[string]bool)
	for i := range occurrences {
		key := occurrences[i].PackageName + "|" + occurrences[i].Version
		seen[key] = true
	}
	return len(seen)
}
