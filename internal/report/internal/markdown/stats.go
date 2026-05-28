package markdown

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeExtractionTree renders the extraction tree as an indented Markdown list
// with status, tool, and timing metadata per node.
func writeExtractionTree(w io.Writer, node *extract.ExtractionNode, depth int, t translations) {
	if node == nil {
		return
	}

	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(w, "%s- **%s** [%s] %s=%s", indent, node.Path, node.Format.Format, t.status, node.Status)

	if node.Tool != "" {
		fmt.Fprintf(w, " %s=%s", t.tool, node.Tool)
	}
	if node.SandboxUsed != "" {
		fmt.Fprintf(w, " %s=%s", t.extractionSandboxLabel, node.SandboxUsed)
	}
	if node.Duration > 0 {
		fmt.Fprintf(w, " %s=%s", t.duration, node.Duration.Round(time.Millisecond))
	}
	if meta := formatArchiveMetaForLog(node); meta != "" {
		fmt.Fprintf(w, " %s", meta)
	}
	if node.StatusDetail != "" {
		fmt.Fprintf(w, " (%s)", node.StatusDetail)
	}
	fmt.Fprintln(w)

	for _, child := range node.Children {
		writeExtractionTree(w, child, depth+1, t)
	}
}

func formatArchiveMetaForLog(node *extract.ExtractionNode) string {
	if node == nil || node.ArchiveMeta == nil {
		return ""
	}
	meta := node.ArchiveMeta
	parts := make([]string, 0, 7)
	if meta.Type != "" {
		parts = append(parts, "type="+meta.Type)
	}
	if len(meta.Methods) > 0 {
		parts = append(parts, "method="+strings.Join(meta.Methods, " / "))
	}
	if meta.HasEncryptedItem {
		parts = append(parts, "encrypted=yes")
	}
	if meta.PhysicalSize != "" {
		parts = append(parts, "physical-size="+meta.PhysicalSize)
	}
	if meta.HeadersSize != "" {
		parts = append(parts, "headers-size="+meta.HeadersSize)
	}
	if meta.Solid != "" {
		parts = append(parts, "solid="+meta.Solid)
	}
	if meta.Blocks != "" {
		parts = append(parts, "blocks="+meta.Blocks)
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// writeResidualRisk writes the explicit limitations statement required for
// auditability when extraction/scan coverage is partial.
func writeResidualRisk(w io.Writer, data ReportData, ext extractionStats, scn scanStats, idx componentIndexStats, t translations) {
	fmt.Fprintln(w, t.residualRiskText)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s\n", t.residualRiskProfileLead)
	fmt.Fprintf(w, "- %s\n", t.residualRiskAbsenceHint)
	if idx.IndexedComponents > 0 {
		// PURL coverage with links to the two component index subsections.
		purlLine := fmt.Sprintf(t.residualRiskPURLCoverage, idx.IndexedWithPURL, idx.IndexedComponents, idx.IndexedWithoutPURL)
		// Replace plain number references with hyperlinked equivalents.
		withPURLLink := fmt.Sprintf("[%d](%s)", idx.IndexedWithPURL, "#"+anchorComponentsWithPURL)
		withoutPURLLink := fmt.Sprintf("[%d](%s)", idx.IndexedWithoutPURL, "#"+anchorComponentsWithoutPURL)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d of %d indexed", idx.IndexedWithPURL, idx.IndexedComponents),
			fmt.Sprintf("%s of %d indexed", withPURLLink, idx.IndexedComponents), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexed occurrences do not", idx.IndexedWithoutPURL),
			fmt.Sprintf("%s indexed occurrences do not", withoutPURLLink), 1)
		purlLine = strings.Replace(purlLine, fmt.Sprintf("%d indexierte Vorkommen haben keine PURL", idx.IndexedWithoutPURL),
			fmt.Sprintf("%s indexierte Vorkommen haben keine PURL", withoutPURLLink), 1)
		fmt.Fprintf(w, "- %s\n", purlLine)
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskEvidenceCoverage, idx.IndexedWithEvidencePath, idx.IndexedWithEvidenceSourceOnly, idx.IndexedWithoutEvidence))
	}
	if scn.Successful > 0 {
		fmt.Fprintf(w, "- %s %s\n",
			fmt.Sprintf(t.residualRiskNoComponentTasks, scn.NoComponentTasks, scn.Successful, samplePaths(scn.NoComponentPaths, t.noneValue)),
			sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs))
	}
	suppression := reportjson.CollectSuppressionStats(data.Suppressions)
	fileArtifactCount := suppression.FSArtifacts + suppression.LowValueFiles
	if fileArtifactCount > 0 {
		links := make([]string, 0, 2)
		if suppression.FSArtifacts > 0 {
			links = append(links, sectionLink(t.suppressionReasonFSArtifact, anchorSuppressionFSArtifacts))
		}
		if suppression.LowValueFiles > 0 {
			links = append(links, sectionLink(t.suppressionReasonLowValueFile, anchorSuppressionLowValue))
		}
		fmt.Fprintf(w, "- %s %s\n",
			fmt.Sprintf(t.residualRiskFileArtifactCoverage, fileArtifactCount),
			strings.Join(links, ", "))
	}
	if ext.ExtensionFiltered > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(
			t.residualRiskExtensionFilter,
			ext.ExtensionFiltered,
			sectionLink(t.extensionFilterSection, anchorExtensionFilter),
		))
	}
	if ext.Failed > 0 || ext.SecurityBlocked > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtractionGap, ext.Failed+ext.SecurityBlocked, samplePaths(append(append([]string{}, ext.FailedPaths...), ext.SecurityBlockedPaths...), t.noneValue)))
	}
	if ext.ToolMissing > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskToolGap, ext.ToolMissing, samplePaths(ext.ToolMissingPaths, t.noneValue)))
	}
	if scn.Errors > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskScanGap, scn.Errors, samplePaths(scn.ErrorPaths, t.noneValue)))
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskMoreDetails, scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability")))
}

// configSkipExtensionsDisplay returns a compact one-liner for the configuration
// table showing the active skip list, capped to keep the table cell readable.
func configSkipExtensionsDisplay(exts []string) string {
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

// samplePaths returns up to three sorted example paths for compact summaries.
func samplePaths(paths []string, noneValue string) string {
	const maxCount = 3

	if len(paths) == 0 {
		return noneValue
	}

	unique := reportjson.SortedUniqueNonEmptyStrings(paths)
	if len(unique) <= maxCount {
		return strings.Join(unique, "; ")
	}
	return strings.Join(unique[:maxCount], "; ") + fmt.Sprintf(" (+%d more)", len(unique)-maxCount)
}
