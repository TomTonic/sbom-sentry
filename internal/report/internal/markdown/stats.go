package markdown

import (
	"fmt"
	"io"
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
	model := reportjson.BuildMarkdownResidualRiskModel(data, ext, scn, idx, reportjson.MarkdownResidualRiskTemplates{
		ResidualRiskPURLCoverage:         t.residualRiskPURLCoverage,
		ResidualRiskEvidenceCoverage:     t.residualRiskEvidenceCoverage,
		ResidualRiskNoComponentTasks:     t.residualRiskNoComponentTasks,
		ResidualRiskFileArtifactCoverage: t.residualRiskFileArtifactCoverage,
		ResidualRiskExtensionFilter:      t.residualRiskExtensionFilter,
		ResidualRiskExtractionGap:        t.residualRiskExtractionGap,
		ResidualRiskToolGap:              t.residualRiskToolGap,
		ResidualRiskScanGap:              t.residualRiskScanGap,
		ResidualRiskMoreDetails:          t.residualRiskMoreDetails,
		NoneValue:                        t.noneValue,
	}, reportjson.MarkdownResidualRiskLinks{
		ScanNoPackageIdentitiesLink:     sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs),
		SuppressionFSArtifactsLink:      sectionLink(t.suppressionReasonFSArtifact, anchorSuppressionFSArtifacts),
		SuppressionLowValueLink:         sectionLink(t.suppressionReasonLowValueFile, anchorSuppressionLowValue),
		ExtensionFilterLink:             sectionLink(t.extensionFilterSection, anchorExtensionFilter),
		PackageDetectionReliabilityLink: scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability"),
		ComponentsWithPURLAnchorID:      anchorComponentsWithPURL,
		ComponentsWithoutPURLAnchorID:   anchorComponentsWithoutPURL,
	})
	if model.PURLLine != "" {
		fmt.Fprintf(w, "- %s\n", model.PURLLine)
	}
	if model.EvidenceLine != "" {
		fmt.Fprintf(w, "- %s\n", model.EvidenceLine)
	}
	if model.NoComponentLine != "" {
		fmt.Fprintf(w, "- %s\n", model.NoComponentLine)
	}
	if model.FileArtifactLine != "" {
		fmt.Fprintf(w, "- %s\n", model.FileArtifactLine)
	}
	if model.ExtensionLine != "" {
		fmt.Fprintf(w, "- %s\n", model.ExtensionLine)
	}
	if model.ExtractionGapLine != "" {
		fmt.Fprintf(w, "- %s\n", model.ExtractionGapLine)
	}
	if model.ToolGapLine != "" {
		fmt.Fprintf(w, "- %s\n", model.ToolGapLine)
	}
	if model.ScanGapLine != "" {
		fmt.Fprintf(w, "- %s\n", model.ScanGapLine)
	}
	fmt.Fprintf(w, "- %s\n", model.MoreDetailsLine)
}

// configSkipExtensionsDisplay returns a compact one-liner for the configuration
// table showing the active skip list, capped to keep the table cell readable.
func configSkipExtensionsDisplay(exts []string) string {
	return reportjson.FormatMarkdownConfigSkipExtensions(exts)
}
