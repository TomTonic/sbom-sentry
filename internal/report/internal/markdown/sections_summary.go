package markdown

import (
	"fmt"
	"io"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
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
	if data.Vulnerabilities != nil && data.Vulnerabilities.Requested {
		fmt.Fprintln(w, t.summaryLead)
	} else {
		fmt.Fprintln(w, t.summaryLeadNoVuln)
	}
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryAnalysisSection, anchorSummaryAnalysis)
	analysis := reportjson.BuildMarkdownSummaryAnalysis(ext, idx, reportjson.MarkdownSummaryTemplates{
		SummaryAnalysisProseTemplate: t.summaryAnalysisProseTemplate,
	})
	fmt.Fprintf(w, "%s\n\n", analysis)
	fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.summaryAnalysisMethodRef, sectionLink(t.methodOverviewSection, anchorMethodOverview)))
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryKeyFindingsSection, anchorSummaryKeyFindings)
	findings := reportjson.BuildMarkdownSummaryFindings(data, ext, scn, pol, idx, occurrences, len(data.ProcessingIssues), reportjson.MarkdownSummaryTemplates{
		FindingDeliveryCompositionTemplate:     t.findingDeliveryCompositionTemplate,
		FindingExtractionStatusFailureTemplate: t.findingExtractionStatusFailureTemplate,
		FindingExtractionStatusSuccessTemplate: t.findingExtractionStatusSuccessTemplate,
		FindingVulnMatchesTemplate:             t.findingVulnMatchesTemplate,
		FindingVulnNoMatches:                   t.findingVulnNoMatches,
		FindingToolMissingTemplate:             t.findingToolMissingTemplate,
		FindingExtractionGapTemplate:           t.findingExtractionGapTemplate,
		FindingScanFailedTemplate:              t.findingScanFailedTemplate,
		FindingPURLCoverageTemplate:            t.findingPURLCoverageTemplate,
		FindingNoPackageIdentityTemplate:       t.findingNoPackageIdentityTemplate,
		FindingPolicyDecisionsTemplate:         t.findingPolicyDecisionsTemplate,
		FindingProcessingIssuesTemplate:        t.findingProcessingIssuesTemplate,
		FindingNoCriticalLimitations:           t.findingNoCriticalLimitations,
		NoneValue:                              t.noneValue,
	}, reportjson.MarkdownSummaryLinks{
		SummaryVulnerabilityLink:      sectionLink(t.summaryVulnSection, anchorSummaryVuln),
		ScanNoPackageIdentitiesLink:   sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs),
		PolicyLink:                    sectionLink(t.policySection, anchorPolicy),
		ProcessingIssuesLink:          sectionLink(t.processingIssuesSection, anchorProcessingErrors),
		ComponentsWithPURLAnchorID:    anchorComponentsWithPURL,
		ComponentsWithoutPURLAnchorID: anchorComponentsWithoutPURL,
	})
	for _, finding := range findings {
		fmt.Fprintf(w, "- %s\n\n", finding)
	}

	writeAnchoredHeading(w, 3, t.summaryVulnSection, anchorSummaryVuln)
	writeVulnerabilitySummary(w, data, occurrences, t)
}
