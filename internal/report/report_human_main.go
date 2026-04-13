package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
)

// writeRootMetadata writes the root-component metadata table and marks whether
// each value was derived or explicitly supplied by the user.
func writeRootMetadata(w io.Writer, data ReportData, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.field, t.value, t.source)
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
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.nameLabel, name, nameSource)

	if rm.Manufacturer != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.manufacturerLabel, rm.Manufacturer, t.suppliedBy)
	}
	if rm.Version != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.version, rm.Version, t.suppliedBy)
	}
	if rm.DeliveryDate != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.deliveryDateLabel, rm.DeliveryDate, t.suppliedBy)
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

// reportSections returns the ordered human-report TOC and heading structure.
func reportSections(t translations) []reportSection {
	return []reportSection{
		{title: t.summarySection, anchor: anchorSummary, level: 0},
		{title: t.howToUseSection, anchor: anchorHowToUse, level: 0},
		{title: t.methodOverviewSection, anchor: anchorMethodOverview, level: 0},
		{title: t.processingIssuesSection, anchor: anchorProcessingErrors, level: 0},
		{title: t.residualRiskSection, anchor: anchorResidualRisk, level: 0},
		{title: t.appendixSection, anchor: anchorAppendix, level: 0},
		{title: t.componentIndexSection, anchor: anchorComponentIndex, level: 1},
		{title: t.componentNormalizationSection, anchor: anchorSuppression, level: 1},
		{title: t.suppressionReasonFSArtifact, anchor: anchorSuppressionFSArtifacts, level: 2},
		{title: t.suppressionReasonLowValueFile, anchor: anchorSuppressionLowValue, level: 2},
		{title: t.inputSection, anchor: anchorInputFile, level: 1},
		{title: t.configSection, anchor: anchorConfig, level: 1},
		{title: t.extensionFilterSection, anchor: anchorExtensionFilter, level: 1},
		{title: t.rootMetadataSection, anchor: anchorRootMetadata, level: 1},
		{title: t.sandboxSection, anchor: anchorSandbox, level: 1},
		{title: t.policySection, anchor: anchorPolicy, level: 1},
		{title: t.scanSection, anchor: anchorScan, level: 1},
		{title: t.scanNoPackageIDsSection, anchor: anchorScanNoPackageIDs, level: 1},
		{title: t.extractionSection, anchor: anchorExtraction, level: 1},
	}
}

// writeSectionHeading writes one anchored level-2 section heading.
func writeSectionHeading(w io.Writer, title, anchor string) {
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n## %s\n\n", anchor, title)
}

// writeTableOfContents renders the report TOC from section descriptors.
func writeTableOfContents(w io.Writer, sections []reportSection) {
	for _, section := range sections {
		indent := ""
		for i := 0; i < section.level; i++ {
			indent += "  "
		}
		fmt.Fprintf(w, "%s- [%s](#%s)\n", indent, section.title, section.anchor)
	}
}

// sectionLink builds an in-document anchor link.
func sectionLink(title, anchor string) string {
	return fmt.Sprintf("[%s](#%s)", title, anchor)
}

// scanApproachLink builds a link to a specific SCAN_APPROACH section.
func scanApproachLink(label, anchor string) string {
	return fmt.Sprintf("[%s](%s#%s)", label, scanApproachGitHubURL, anchor)
}

// collectSuppressionStats groups suppression records by suppression reason.
func collectSuppressionStats(suppressions []assembly.SuppressionRecord) suppressionStats {
	stats := suppressionStats{}
	for i := range suppressions {
		switch suppressions[i].Reason {
		case assembly.SuppressionFSArtifact:
			stats.FSArtifacts++
		case assembly.SuppressionLowValueFile:
			stats.LowValueFiles++
		case assembly.SuppressionWeakDuplicate:
			stats.WeakDuplicate++
		case assembly.SuppressionPURLDuplicate:
			stats.PURLDuplicate++
		}
	}
	return stats
}

// writeHowToUseReport writes the operator-facing triage workflow section.
func writeHowToUseReport(w io.Writer, t translations) {
	componentIndexLink := sectionLink(t.componentIndexSection, anchorComponentIndex)
	normalizationLink := sectionLink(t.componentNormalizationSection, anchorSuppression)
	processingLink := sectionLink(t.processingIssuesSection, anchorProcessingErrors)
	riskLink := sectionLink(t.residualRiskSection, anchorResidualRisk)

	fmt.Fprintln(w, t.howToUseLead)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "1. %s\n\n", t.howToUseStep1)
	fmt.Fprintln(w, "```sh")
	fmt.Fprintln(w, "jq '.matches[] | select((.vulnerability.severity == \"High\") or (.vulnerability.severity == \"Critical\")) | {artifact_id: .artifact.id, package: .artifact.name, version: .artifact.version, vulnerability: .vulnerability.id, severity: .vulnerability.severity}' grype.json")
	fmt.Fprintln(w, "```")
	fmt.Fprintf(w, "2. %s\n", fmt.Sprintf(t.howToUseStep2Template, componentIndexLink))
	fmt.Fprintf(w, "3. %s\n", t.howToUseStep3)
	fmt.Fprintf(w, "4. %s\n", fmt.Sprintf(t.howToUseStep4Template, normalizationLink, processingLink, riskLink))
}

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

// writePolicyDecisions lists policy-engine decisions captured during runtime.
func writePolicyDecisions(w io.Writer, decisions []policy.Decision, t translations) {
	if len(decisions) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noPolicyDecisions)
		return
	}

	for _, d := range decisions {
		fmt.Fprintf(w, "- **%s** %s `%s`: %s -> %s\n", d.Trigger, t.policyDecisionAt, d.NodePath, d.Detail, d.Action)
	}
}

// writeSummary renders the headline execution metrics and synthesized findings.
func writeSummary(w io.Writer, data ReportData, ext extractionStats, scn scanStats, pol policyStats, idx componentIndexStats, t translations) {
	duration := data.EndTime.Sub(data.StartTime).Round(time.Millisecond)
	retainedPackages := scn.TotalComponents - len(data.Suppressions)
	if retainedPackages < 0 {
		retainedPackages = 0
	}
	structuralComponents := idx.TotalComponents - retainedPackages
	if structuralComponents < 0 {
		structuralComponents = 0
	}
	suppression := collectSuppressionStats(data.Suppressions)

	fmt.Fprintln(w, t.summaryLead)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "- %s: %s\n", t.processingTime, duration)
	fmt.Fprintf(w, "- %s: %s\n", t.summaryExtraction, fmt.Sprintf(
		t.summaryExtractionStatsTemplate,
		ext.Total,
		ext.Extracted,
		ext.SyftNative,
		ext.Failed,
		ext.ToolMissing,
		ext.Skipped,
		ext.ExtensionFiltered,
		anchorExtensionFilter,
		ext.SecurityBlocked,
		ext.Pending,
	))
	fmt.Fprintf(w, "- %s: %s\n", t.summaryScan, fmt.Sprintf(
		t.summaryScanStatsTemplate,
		scn.Total,
		scn.Successful,
		scn.Errors,
		scn.TotalComponents,
	))
	fmt.Fprintf(w, "- %s: %s\n", t.summaryComponents, fmt.Sprintf(
		t.summaryComponentsStatsTemplate,
		scn.TotalComponents,
		len(data.Suppressions),
		suppression.FSArtifacts,
		suppression.LowValueFiles,
		suppression.WeakDuplicate,
		suppression.PURLDuplicate,
		idx.TotalComponents,
		idx.FilteredAbsolutePathNames+idx.FilteredLowValueFileArtifacts+idx.DuplicateMerged,
		idx.FilteredAbsolutePathNames,
		idx.FilteredLowValueFileArtifacts,
		idx.DuplicateMerged,
		idx.IndexedComponents,
	))
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.summaryAssemblyMath, retainedPackages, structuralComponents, idx.TotalComponents))
	fmt.Fprintf(w, "- %s: %s\n", t.summaryPolicies, fmt.Sprintf(t.summaryPoliciesStatsTemplate, pol.Total, pol.Continue, pol.Skip, pol.Abort))
	fmt.Fprintf(w, "- %s: %s\n", t.summaryProcessingIssues, fmt.Sprintf(t.summaryProcessingStatsTemplate, len(data.ProcessingIssues)))
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.summaryNextStepTemplate, sectionLink(t.howToUseSection, anchorHowToUse), sectionLink(t.componentIndexSection, anchorComponentIndex)))

	fmt.Fprintf(w, "\n%s:\n", t.summaryFindings)
	findings := summarizeFindings(ext, scn, idx, t)
	for _, finding := range findings {
		fmt.Fprintf(w, "- %s\n", finding)
	}
}

// summarizeFindings derives short, operator-friendly findings from collected
// extraction, scan, and component-index statistics.
func summarizeFindings(ext extractionStats, scn scanStats, idx componentIndexStats, t translations) []string {
	findings := make([]string, 0, 8)
	if ext.ToolMissing > 0 {
		findings = append(findings, fmt.Sprintf(t.findingToolMissingTemplate, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, t.noneValue)))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		findings = append(findings, fmt.Sprintf(t.findingExtractionGapTemplate, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), t.noneValue)))
	}
	if scn.Errors > 0 {
		findings = append(findings, fmt.Sprintf(t.findingScanFailedTemplate, scn.Errors, samplePaths(scn.ErrorPaths, t.noneValue)))
	} else if scn.Total > 0 {
		findings = append(findings, fmt.Sprintf(t.findingAllScansSuccessfulTemplate, scn.Total))
	}
	if idx.IndexedComponents > 0 {
		findings = append(findings, fmt.Sprintf(
			t.findingPURLCoverageTemplate,
			idx.IndexedWithPURL, idx.IndexedComponents, anchorComponentsWithPURL,
			idx.IndexedWithoutPURL, anchorComponentsWithoutPURL,
		))
	}
	if scn.NoComponentTasks > 0 {
		findings = append(findings, fmt.Sprintf(t.findingNoPackageIdentityTemplate, scn.NoComponentTasks, samplePaths(scn.NoComponentPaths, t.noneValue)))
	}
	if idx.FilteredAbsolutePathNames > 0 || idx.FilteredLowValueFileArtifacts > 0 || idx.DuplicateMerged > 0 {
		findings = append(
			findings,
			fmt.Sprintf(
				t.findingIndexQualityTemplate,
				idx.FilteredAbsolutePathNames,
				idx.FilteredLowValueFileArtifacts,
				idx.DuplicateMerged,
			),
		)
	}
	if len(findings) == 0 {
		findings = append(findings, t.findingNoCriticalLimitations)
	}
	return findings
}

// writeProcessingIssues prints a bounded table of pipeline/extraction/scan
// issues for auditable troubleshooting.
func writeProcessingIssues(w io.Writer, data ReportData, ext extractionStats, scn scanStats, t translations) {
	entries := collectProcessingEntries(data)

	fmt.Fprintf(w, "- %s: %d\n", t.processingPipelineLabel, len(data.ProcessingIssues))
	fmt.Fprintf(w, "- %s: %d\n", t.processingExtractionFailedLabel, ext.Failed)
	fmt.Fprintf(w, "- %s: %d\n", t.processingSecurityBlockedLabel, ext.SecurityBlocked)
	fmt.Fprintf(w, "- %s: %d\n", t.processingToolMissingLabel, ext.ToolMissing)
	fmt.Fprintf(w, "- %s: %d\n", t.processingScanErrorsLabel, scn.Errors)

	if len(entries) == 0 {
		fmt.Fprintf(w, "\n- %s\n", t.noProcessingIssues)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.processingSourceHeader, t.processingLocationHeader, t.processingDetailHeader)
	fmt.Fprintln(w, "|---|---|---|")

	maxRows := 25
	for i, entry := range entries {
		if i >= maxRows {
			remaining := len(entries) - maxRows
			fmt.Fprintf(w, "| ... | ... | %s |\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, remaining))
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

// collectProcessingEntries flattens processing issues from pipeline, extraction,
// and scan phases into a deterministically sorted table model.
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

// escapeMarkdownCell sanitizes table-cell content for Markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
