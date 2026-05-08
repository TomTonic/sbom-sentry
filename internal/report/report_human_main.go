package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
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
		{title: t.summaryAnalysisSection, anchor: anchorSummaryAnalysis, level: 1},
		{title: t.summaryKeyFindingsSection, anchor: anchorSummaryKeyFindings, level: 1},
		{title: t.summaryVulnSection, anchor: anchorSummaryVuln, level: 1},
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

// writeAnchoredHeading writes one Markdown heading and emits a separate HTML
// anchor only when the requested anchor differs from the heading's natural slug.
func writeAnchoredHeading(w io.Writer, level int, title, anchor string) {
	if anchor != "" && anchor != markdownHeadingAnchor(title) {
		fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchor)
	}
	fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", level), title)
}

// writeSectionHeading writes one anchored level-2 section heading.
func writeSectionHeading(w io.Writer, title, anchor string) {
	writeAnchoredHeading(w, 2, title, anchor)
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

// markdownHeadingAnchor approximates the auto-generated Markdown heading slug
// used by Pandoc/GitHub for plain ASCII headings.
func markdownHeadingAnchor(title string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(title) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == ' ' || r == '-':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
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
	vulnMatches, vulnUnique, vulnAffected := collectVulnStats(data.Vulnerabilities)
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
	fmt.Fprintf(
		w,
		"| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.processingSourceHeader,
		t.processingLocationHeader,
		t.processingClassHeader,
		t.processingStatusHeader,
		t.processingDetectedHeader,
		t.processingToolHeader,
		t.processingArchiveTypeHeader,
		t.processingArchiveMethodHeader,
		t.processingEncryptedHeader,
		t.processingPhysicalSizeHeader,
		t.processingDetailHeader,
	)
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|---|---|---|")

	maxRows := 25
	for i := range entries {
		entry := &entries[i]
		if i >= maxRows {
			remaining := len(entries) - maxRows
			fmt.Fprintf(w, "| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | %s |\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, remaining))
			break
		}
		fmt.Fprintf(
			w,
			"| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdownCell(entry.Source),
			escapeMarkdownCell(entry.Location),
			escapeMarkdownCell(entry.Classification),
			escapeMarkdownCell(entry.Status),
			escapeMarkdownCell(entry.DetectedFormat),
			escapeMarkdownCell(entry.Tool),
			escapeMarkdownCell(entry.ArchiveType),
			escapeMarkdownCell(entry.ArchiveMethod),
			escapeMarkdownCell(entry.Encrypted),
			escapeMarkdownCell(entry.PhysicalSize),
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
			Source:         "pipeline",
			Location:       issue.Stage,
			Classification: "pipeline-error",
			Detail:         issue.Message,
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
			metaType := ""
			metaMethod := ""
			metaEncrypted := ""
			metaPhysicalSize := ""
			if node.ArchiveMeta != nil {
				metaType = node.ArchiveMeta.Type
				if len(node.ArchiveMeta.Methods) > 0 {
					metaMethod = strings.Join(node.ArchiveMeta.Methods, " / ")
				}
				if node.ArchiveMeta.HasEncryptedItem {
					metaEncrypted = "yes"
				}
				metaPhysicalSize = node.ArchiveMeta.PhysicalSize
			}
			entries = append(entries, processingEntry{
				Source:         "extraction",
				Location:       node.Path,
				Classification: classifyExtractionIssue(node),
				Status:         node.Status.String(),
				DetectedFormat: node.Format.Format.String(),
				Tool:           node.Tool,
				ArchiveType:    metaType,
				ArchiveMethod:  metaMethod,
				Encrypted:      metaEncrypted,
				PhysicalSize:   metaPhysicalSize,
				Detail:         compactExtractionDetail(detail),
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
			Source:         "scan",
			Location:       sr.NodePath,
			Classification: "scan-error",
			Tool:           "syft",
			Detail:         sr.Error.Error(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		if entries[i].Classification != entries[j].Classification {
			return entries[i].Classification < entries[j].Classification
		}
		return entries[i].Detail < entries[j].Detail
	})

	return entries
}

func classifyExtractionIssue(node *extract.ExtractionNode) string {
	if node.Status == extract.StatusToolMissing {
		return "tool-missing"
	}
	if node.Status == extract.StatusSecurityBlocked {
		return "security-blocked"
	}
	lower := strings.ToLower(node.StatusDetail)
	switch {
	case strings.Contains(lower, "wrong password") || strings.Contains(lower, "encrypted archive"):
		return "password-required"
	case strings.Contains(lower, "timeout"):
		return "timeout"
	case strings.Contains(lower, "invalid tar header") || strings.Contains(lower, "headers error") || strings.Contains(lower, "unconfirmed start of archive") || strings.Contains(lower, "unexpected end of archive"):
		return "archive-corrupt-or-truncated"
	case strings.Contains(lower, "not a valid zip") || strings.Contains(lower, "can not open the file as archive") || strings.Contains(lower, "cannot open the file as") || strings.Contains(lower, "is not archive"):
		return "format-mismatch-or-invalid-archive"
	default:
		return "extraction-failed"
	}
}

func compactExtractionDetail(detail string) string {
	trimmed := strings.TrimSpace(detail)
	if idx := strings.Index(trimmed, ": "); idx != -1 {
		prefix := trimmed[:idx]
		if strings.Contains(prefix, " extraction failed") {
			trimmed = strings.TrimSpace(trimmed[idx+2:])
		}
	}
	return trimmed
}

// escapeMarkdownCell sanitizes table-cell content for Markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
