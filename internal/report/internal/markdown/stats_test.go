package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestResidualRiskWithUnsafeMode verifies that the residual risk section
// identifies unsafe mode as a risk.
func TestResidualRiskWithUnsafeMode(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Residual Risk") {
		t.Error("missing residual risk section")
	}

	if !strings.Contains(output, "sandbox isolation") {
		t.Error("residual risk does not mention sandbox isolation")
	}
}

// TestResidualRiskWithScanErrors verifies that scan errors are reported
// as a residual risk.
func TestResidualRiskWithScanErrors(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{{
		NodePath: "test.zip",
		Error:    &testError{msg: "syft failed"},
	}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "scan") || !strings.Contains(output, "errors") {
		t.Error("residual risk does not mention scan errors")
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestCollectExtractionStats(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.jar", Status: extract.StatusSyftNative},
			{Path: "b.cab", Status: extract.StatusFailed, StatusDetail: "7zz error"},
			{Path: "c.msi", Status: extract.StatusToolMissing},
			{Path: "d.iso", Status: extract.StatusSecurityBlocked},
			{Path: "e.tar", Status: extract.StatusSkipped},
			{Path: "f.zip", Status: extract.StatusPending},
			{
				Path:                   "g.zip",
				Status:                 extract.StatusExtracted,
				ExtensionFilteredPaths: []string{"g.zip/skip.dll"},
			},
		},
	}

	stats := domain.CollectExtractionStats(tree)
	if stats.Total != 8 {
		t.Errorf("Total = %d, want 8", stats.Total)
	}
	if stats.Extracted != 2 {
		t.Errorf("Extracted = %d, want 2", stats.Extracted)
	}
	if stats.SyftNative != 1 {
		t.Errorf("SyftNative = %d, want 1", stats.SyftNative)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if stats.ToolMissing != 1 {
		t.Errorf("ToolMissing = %d, want 1", stats.ToolMissing)
	}
	if stats.SecurityBlocked != 1 {
		t.Errorf("SecurityBlocked = %d, want 1", stats.SecurityBlocked)
	}
	if stats.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", stats.Skipped)
	}
	if stats.Pending != 1 {
		t.Errorf("Pending = %d, want 1", stats.Pending)
	}
	if stats.ExtensionFiltered != 1 {
		t.Errorf("ExtensionFiltered = %d, want 1", stats.ExtensionFiltered)
	}
}

func TestCollectExtractionStatsNilTree(t *testing.T) {
	t.Parallel()
	stats := domain.CollectExtractionStats(nil)
	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}
}

func TestWriteExtractionTreeRendersArchiveMetadata(t *testing.T) {
	t.Parallel()

	node := &extract.ExtractionNode{
		Path:   "sample.zip",
		Format: identify.FormatInfo{Format: identify.ZIP},
		Status: extract.StatusExtracted,
		ArchiveMeta: &extract.ArchiveMetadata{
			Type:             "zip",
			Methods:          []string{"Deflate", "Store"},
			PhysicalSize:     "1234",
			HeadersSize:      "120",
			HasEncryptedItem: true,
		},
	}

	var buf bytes.Buffer
	writeExtractionTree(&buf, node, 0, getTranslations("en"))
	out := buf.String()

	for _, want := range []string{"{type=zip", "method=Deflate / Store", "encrypted=yes", "physical-size=1234", "headers-size=120"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %q", want, out)
		}
	}
}

func TestWriteScanNoPackageIdentitiesSubsection(t *testing.T) {
	t.Parallel()

	tr := getTranslations("en")

	t.Run("zero tasks", func(t *testing.T) {
		var buf bytes.Buffer
		writeScanNoPackageIdentitiesSubsection(&buf, scanStats{NoComponentTasks: 0}, tr)
		if !strings.Contains(buf.String(), tr.noScanNoPackageIDs) {
			t.Fatal("expected 'no items' message for zero-task case")
		}
	})

	t.Run("with paths", func(t *testing.T) {
		var buf bytes.Buffer
		stats := scanStats{NoComponentTasks: 2, NoComponentPaths: []string{"b/file.jar", "a/file.war"}}
		writeScanNoPackageIdentitiesSubsection(&buf, stats, tr)
		out := buf.String()
		if !strings.Contains(out, "`a/file.war`") || !strings.Contains(out, "`b/file.jar`") {
			t.Fatalf("expected both paths in output, got:\n%s", out)
		}
	})
}

func TestCollectScanStats(t *testing.T) {
	t.Parallel()

	comps := []cdx.Component{{Name: "a"}, {Name: "b"}}
	scans := []scan.ScanResult{
		{NodePath: "good.jar", BOM: &cdx.BOM{Components: &comps}},
		{NodePath: "empty.jar", BOM: &cdx.BOM{}},
		{NodePath: "err.jar", Error: &testError{msg: "fail"}},
	}
	stats := domain.CollectScanStats(scans)
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Successful != 2 {
		t.Errorf("Successful = %d, want 2", stats.Successful)
	}
	if stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", stats.Errors)
	}
	if stats.TotalComponents != 2 {
		t.Errorf("TotalComponents = %d, want 2", stats.TotalComponents)
	}
	if stats.NoComponentTasks != 1 {
		t.Errorf("NoComponentTasks = %d, want 1", stats.NoComponentTasks)
	}
}

func TestCollectPolicyStats(t *testing.T) {
	t.Parallel()

	stats := domain.CollectPolicyStats(nil)
	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}

	withDecisions := domain.CollectPolicyStats([]policy.Decision{{Action: policy.ActionContinue}, {Action: policy.ActionSkip}, {Action: policy.ActionAbort}})
	if withDecisions.Total != 3 || withDecisions.Continue != 1 || withDecisions.Skip != 1 || withDecisions.Abort != 1 {
		t.Fatalf("unexpected policy stats: %+v", withDecisions)
	}
}
