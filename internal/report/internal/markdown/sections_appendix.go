package markdown

import (
	"fmt"
	"io"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeRootMetadata writes the root-component metadata table and marks whether
// each value was derived or explicitly supplied by the user.
func writeRootMetadata(w io.Writer, data ReportData, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.field, t.value, t.source)
	fmt.Fprintf(w, "|---|---|---|\n")
	rows := reportjson.BuildMarkdownRootMetadataRows(data)
	for i := range rows {
		sourceLabel := t.suppliedBy
		if rows[i].SourceCode == reportjson.MarkdownRootMetadataSourceDerived {
			sourceLabel = t.derived
		}
		fieldLabel := rows[i].FieldKey
		switch rows[i].FieldKey {
		case "name":
			fieldLabel = t.nameLabel
		case "manufacturer":
			fieldLabel = t.manufacturerLabel
		case "version":
			fieldLabel = t.version
		case "deliveryDate":
			fieldLabel = t.deliveryDateLabel
		}
		fmt.Fprintf(w, "| %s | %s | %s |\n", fieldLabel, rows[i].FieldValue, sourceLabel)
	}
	fmt.Fprintln(w)
}

// reportSections returns the ordered markdown-report TOC and heading structure.
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
