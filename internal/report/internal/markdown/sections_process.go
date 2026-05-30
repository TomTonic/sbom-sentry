package markdown

import (
	"fmt"
	"io"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/policy"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

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

// writeProcessingIssues prints a bounded table of pipeline/extraction/scan
// issues for auditable troubleshooting.
func writeProcessingIssues(w io.Writer, data ReportData, ext extractionStats, scn scanStats, t translations) {
	entries := reportjson.CollectMarkdownProcessingEntries(data)

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

// escapeMarkdownCell sanitizes table-cell content for Markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
