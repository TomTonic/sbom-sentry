package markdown

import (
	"bytes"
	"strings"
	"testing"
)

// TestCrossReportOrderingContractHumanSectionBlocks verifies that the human
// report keeps executive guidance before appendix-heavy sections.
func TestCrossReportOrderingContractHumanSectionBlocks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	out := buf.String()

	summaryIdx := strings.Index(out, "## Summary")
	methodIdx := strings.Index(out, "## Method At A Glance")
	appendixIdx := strings.Index(out, "## Appendix")
	scanLogIdx := strings.Index(out, "## Package Scan Log")
	extractionLogIdx := strings.Index(out, "## Extraction Log")
	if summaryIdx == -1 || methodIdx == -1 || appendixIdx == -1 || scanLogIdx == -1 || extractionLogIdx == -1 {
		t.Fatal("expected report sections are missing")
	}
	if summaryIdx >= appendixIdx || methodIdx >= appendixIdx || appendixIdx >= scanLogIdx || appendixIdx >= extractionLogIdx {
		t.Fatal("human section ordering contract violated")
	}
}
