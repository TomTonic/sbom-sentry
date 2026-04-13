package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
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
	if node.StatusDetail != "" {
		fmt.Fprintf(w, " (%s)", node.StatusDetail)
	}
	fmt.Fprintln(w)

	for _, child := range node.Children {
		writeExtractionTree(w, child, depth+1, t)
	}
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
	suppression := collectSuppressionStats(data.Suppressions)
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

	unique := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}

	sort.Strings(unique)
	if len(unique) <= maxCount {
		return strings.Join(unique, "; ")
	}
	return strings.Join(unique[:maxCount], "; ") + fmt.Sprintf(" (+%d more)", len(unique)-maxCount)
}

// collectExtractionStats walks the extraction tree and aggregates status and
// path counters used by summary and residual-risk sections.
func collectExtractionStats(node *extract.ExtractionNode) extractionStats {
	stats := extractionStats{}

	var walk func(n *extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}

		stats.Total++
		switch n.Status {
		case extract.StatusExtracted:
			stats.Extracted++
		case extract.StatusSyftNative:
			stats.SyftNative++
		case extract.StatusFailed:
			stats.Failed++
			stats.FailedPaths = append(stats.FailedPaths, n.Path)
		case extract.StatusSkipped:
			stats.Skipped++
		case extract.StatusToolMissing:
			stats.ToolMissing++
			stats.ToolMissingPaths = append(stats.ToolMissingPaths, n.Path)
		case extract.StatusSecurityBlocked:
			stats.SecurityBlocked++
			stats.SecurityBlockedPaths = append(stats.SecurityBlockedPaths, n.Path)
		case extract.StatusPending:
			stats.Pending++
		default:
			stats.Other++
		}

		// Aggregate extension-filtered files recorded at each node.
		stats.ExtensionFiltered += len(n.ExtensionFilteredPaths)
		stats.ExtensionFilteredPaths = append(stats.ExtensionFilteredPaths, n.ExtensionFilteredPaths...)

		for _, child := range n.Children {
			walk(child)
		}
	}

	walk(node)
	return stats
}

// collectScanStats aggregates scan success/error counters and coverage hints.
func collectScanStats(scans []scan.ScanResult) scanStats {
	stats := scanStats{Total: len(scans)}
	for _, sr := range scans {
		if sr.Error != nil {
			stats.Errors++
			stats.ErrorPaths = append(stats.ErrorPaths, sr.NodePath)
			continue
		}
		stats.Successful++
		componentCount := 0
		if sr.BOM != nil && sr.BOM.Components != nil {
			componentCount = len(*sr.BOM.Components)
			stats.TotalComponents += componentCount
		}
		if componentCount == 0 {
			stats.NoComponentTasks++
			stats.NoComponentPaths = append(stats.NoComponentPaths, sr.NodePath)
		}
	}
	return stats
}

// collectPolicyStats aggregates policy-action counters for summary reporting.
func collectPolicyStats(decisions []policy.Decision) policyStats {
	stats := policyStats{Total: len(decisions)}
	for _, d := range decisions {
		switch d.Action {
		case policy.ActionContinue:
			stats.Continue++
		case policy.ActionSkip:
			stats.Skip++
		case policy.ActionAbort:
			stats.Abort++
		}
	}
	return stats
}
