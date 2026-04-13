// Report module tests: Verify that audit reports are generated with
// correct structure, content, and i18n support for both human-readable
// Markdown and machine-readable JSON formats.
package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// makeTestReportData creates a minimal ReportData suitable for testing.
func makeTestReportData() ReportData {
	return ReportData{
		Input: InputSummary{
			Filename: "test.zip",
			Size:     1024,
			SHA256:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			SHA512:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Generator: buildinfo.Info{
			Version:  "v1.2.3",
			Revision: "0123456789abcdef",
			Time:     "2026-04-11T12:34:56Z",
			Modified: true,
		},
		Config: config.DefaultConfig(),
		Tree: &extract.ExtractionNode{
			Path:   "test.zip",
			Status: extract.StatusExtracted,
			Format: identify.FormatInfo{Format: identify.ZIP},
		},
		Scans:           []scan.ScanResult{},
		PolicyDecisions: []policy.Decision{},
		SandboxInfo: SandboxSummary{
			Name:      "passthrough",
			Available: true,
			UnsafeOvr: false,
		},
		StartTime: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2025, 1, 15, 10, 0, 5, 0, time.UTC),
		SBOMPath:  "/output/test.cdx.json",
	}
}

// TestGenerateHumanIncludesGeneratorBuildInfo verifies that build metadata
// for the generator is visible in the human-readable report.
func TestGenerateHumanIncludesGeneratorBuildInfo(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "| extract-sbom build | v1.2.3 rev 0123456789ab 2026-04-11T12:34:56Z dirty |") {
		t.Fatal("report does not contain generator build info")
	}
}

// TestComputeInputSummaryComputesCorrectHashes verifies that SHA-256
// and SHA-512 hashes are computed correctly for the input file.
func TestComputeInputSummaryComputesCorrectHashes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := ComputeInputSummary(path)
	if err != nil {
		t.Fatalf("ComputeInputSummary error: %v", err)
	}

	if summary.Filename != "test.bin" {
		t.Errorf("Filename = %q, want %q", summary.Filename, "test.bin")
	}

	if summary.Size != 11 {
		t.Errorf("Size = %d, want 11", summary.Size)
	}

	// "hello world" SHA-256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if summary.SHA256 != expectedSHA256 {
		t.Errorf("SHA256 = %q, want %q", summary.SHA256, expectedSHA256)
	}

	if len(summary.SHA512) != 128 {
		t.Errorf("SHA512 length = %d, want 128", len(summary.SHA512))
	}
}

// TestComputeInputSummaryFailsForMissingFile verifies that a missing
// file produces an error.
func TestComputeInputSummaryFailsForMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ComputeInputSummary("/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestGenerateHumanContainsRequiredSections verifies that the English
// Markdown report contains all required sections from DESIGN.md §10.4.
func TestGenerateHumanContainsRequiredSections(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}

	output := buf.String()

	requiredSections := []string{
		"# extract-sbom Audit Report",
		"## Table of Contents",
		"## Input File",
		"## Configuration",
		"## Root SBOM Metadata",
		"## Sandbox Configuration",
		"## Summary",
		"## Processing Errors",
		"## Residual Risk and Limitations",
		"## Policy Decisions",
		"## Component Occurrence Index",
		"## Component Normalization",
		"## Extraction Log",
		"## Scan Results",
		"End of report.",
	}

	for _, section := range requiredSections {
		if !strings.Contains(output, section) {
			t.Errorf("missing required section %q", section)
		}
	}
}

// TestGenerateHumanContainsInputHashes verifies that the report includes
// both SHA-256 and SHA-512 hashes of the input file.
func TestGenerateHumanContainsInputHashes(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, data.Input.SHA256) {
		t.Error("report does not contain SHA-256 hash")
	}

	if !strings.Contains(output, data.Input.SHA512) {
		t.Error("report does not contain SHA-512 hash")
	}
}

// TestGenerateHumanGermanTranslation verifies that the German report
// uses German section headers and labels.
func TestGenerateHumanGermanTranslation(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "de", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}

	output := buf.String()

	germanHeaders := []string{
		"# extract-sbom Prüfbericht",
		"## Eingabedatei",
		"## Konfiguration",
	}

	for _, header := range germanHeaders {
		if !strings.Contains(output, header) {
			t.Errorf("missing German header %q", header)
		}
	}
}

// TestGenerateHumanWithUnsafeShowsWarning verifies that the report
// clearly warns when --unsafe mode was used.
func TestGenerateHumanWithUnsafeShowsWarning(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "WARNING") {
		t.Error("unsafe mode report does not contain WARNING")
	}

	if !strings.Contains(output, "Unsafe mode active") || !strings.Contains(output, "no sandbox isolation") {
		t.Error("unsafe mode report does not explain the risk")
	}
}

// TestGenerateHumanWithPolicyDecisions verifies that policy decisions
// are included in the report when present.
func TestGenerateHumanWithPolicyDecisions(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.PolicyDecisions = []policy.Decision{
		{
			Trigger:  "max-depth",
			NodePath: "/deeply/nested/archive.zip",
			Action:   policy.ActionSkip,
			Detail:   "Resource limit max-depth exceeded",
		},
	}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Policy Decisions") {
		t.Error("report does not contain Policy Decisions section")
	}

	if !strings.Contains(output, "max-depth") {
		t.Error("report does not contain the policy trigger")
	}
}

// TestGenerateHumanWithProcessingIssues verifies that processing-stage errors
// are documented in a dedicated section for operator auditability.
func TestGenerateHumanWithProcessingIssues(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ProcessingIssues = []ProcessingIssue{{
		Stage:   "assembly",
		Message: "failed to merge components",
	}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "## Processing Errors") {
		t.Fatal("report does not contain Processing Errors section")
	}
	if !strings.Contains(output, "| pipeline | assembly | failed to merge components |") {
		t.Fatal("report does not contain processing issue details")
	}
}

// TestGenerateHumanTOCContainsAnchorLinks verifies that the Table of Contents
// includes clickable anchor links for all major sections.
func TestGenerateHumanTOCContainsAnchorLinks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	for _, link := range []string{
		"- [Input File](#input-file)",
		"- [Configuration](#configuration)",
		"- [Summary](#summary)",
		"- [Processing Errors](#processing-errors)",
		"- [Residual Risk and Limitations](#residual-risk-and-limitations)",
		"- [Policy Decisions](#policy-decisions)",
		"- [Component Occurrence Index](#component-occurrence-index)",
		"- [Component Normalization](#component-normalization)",
		"- [Scan Results](#scan-results)",
		"- [Extraction Log](#extraction-log)",
	} {
		if !strings.Contains(output, link) {
			t.Fatalf("report table of contents missing %q", link)
		}
	}
}

// TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst verifies that
// Summary/Errors/Risk appear before the large Scan/Extraction bulk sections.
func TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	summaryIdx := strings.Index(output, "## Summary")
	errorsIdx := strings.Index(output, "## Processing Errors")
	riskIdx := strings.Index(output, "## Residual Risk and Limitations")
	scanIdx := strings.Index(output, "## Scan Results")
	extractionIdx := strings.Index(output, "## Extraction Log")

	if summaryIdx == -1 || errorsIdx == -1 || riskIdx == -1 || scanIdx == -1 || extractionIdx == -1 {
		t.Fatal("one or more expected sections are missing")
	}

	if summaryIdx >= scanIdx || summaryIdx >= extractionIdx ||
		errorsIdx >= scanIdx || errorsIdx >= extractionIdx ||
		riskIdx >= scanIdx || riskIdx >= extractionIdx {
		t.Fatal("summary/errors/risk sections are not placed before scan/extraction sections")
	}
}

// TestGenerateHumanWithScanResults verifies that scan results
// are displayed in the report.
func TestGenerateHumanWithScanResults(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{
		{
			NodePath: "test.zip",
			BOM: &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "express", Version: "4.18.0"},
					{Name: "lodash", Version: "4.17.21"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "2 components found") {
		t.Error("report does not show component count")
	}
}

// TestGenerateHumanComponentIndexUsesFinalBOMRefs verifies that the human
// report exposes final component occurrence IDs from the assembled SBOM and
// orders entries by delivery path rather than by object ID.
func TestGenerateHumanComponentIndexUsesFinalBOMRefs(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:ZZZZ_ZZZZ",
			Name:       "zlib",
			Version:    "1.2.13",
			PackageURL: "pkg:generic/zlib@1.2.13",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "b/path/zlib.jar"}},
		},
		{
			BOMRef:     "extract-sbom:AAAA_AAAA",
			Name:       "alpha",
			Version:    "1.0.0",
			PackageURL: "pkg:maven/com.acme/alpha@1.0.0",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "a/path/alpha.jar"},
				{Name: "extract-sbom:evidence-path", Value: "a/path/alpha.jar/META-INF/MANIFEST.MF"},
				{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
			},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "### extract-sbom:AAAA_AAAA")
	zlibIdx := strings.Index(output, "### extract-sbom:ZZZZ_ZZZZ")
	if alphaIdx == -1 || zlibIdx == -1 {
		t.Fatal("component occurrence headings missing from report")
	}
	if alphaIdx >= zlibIdx {
		t.Fatalf("component occurrences are not sorted by delivery path: alpha=%d zlib=%d", alphaIdx, zlibIdx)
	}

	for _, fragment := range []string{
		"Package: `alpha`",
		"PURL: `pkg:maven/com.acme/alpha@1.0.0`",
		"Delivery path: `a/path/alpha.jar`",
		"Evidence path: `a/path/alpha.jar/META-INF/MANIFEST.MF`",
		"Found by: `java-archive-cataloger`",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
	if strings.Contains(output, "Object ID: `extract-sbom:AAAA_AAAA`") {
		t.Fatal("object-id line should not be repeated when object id is already the heading")
	}
}

// TestGenerateHumanComponentIndexFiltersAbsPathNames verifies that
// file-cataloger artifacts (Name starts with /) are excluded from
// the component occurrence index, even if they have delivery paths.
func TestGenerateHumanComponentIndexFiltersAbsPathNames(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef: "extract-sbom:GOOD_COMP",
			Type:   cdx.ComponentTypeLibrary,
			Name:   "janino",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery.zip/inner/janino.jar"},
			},
		},
		{
			BOMRef: "extract-sbom:BAD_COMP",
			Type:   cdx.ComponentTypeFile,
			Name:   "/tmp/extract-sbom-zip-12345/inner/janino.jar",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery.zip/inner/janino.jar"},
			},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "### extract-sbom:GOOD_COMP") {
		t.Error("properly-identified component missing from report")
	}
	if strings.Contains(output, "### extract-sbom:BAD_COMP") {
		t.Error("file-cataloger artifact with absolute-path Name should be filtered from report")
	}
	if strings.Contains(output, "/tmp/extract-sbom-zip-12345") {
		t.Error("temp extraction path leaked into report")
	}
}

// TestGenerateHumanComponentIndexMergesWeakDuplicatePlaceholders verifies
// that when two entries point to the same delivery/evidence location, a
// richer package record is kept and weak placeholders are suppressed.
func TestGenerateHumanComponentIndexMergesWeakDuplicatePlaceholders(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:GOOD_JANINO",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "janino",
			Version:    "3.1.10",
			PackageURL: "pkg:maven/org.codehaus.janino/janino@3.1.10",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery.zip/plugins/janino-3.1.10.jar"},
				{Name: "extract-sbom:evidence-path", Value: "delivery.zip/plugins/janino-3.1.10.jar/META-INF/MANIFEST.MF"},
				{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
			},
		},
		{
			BOMRef: "extract-sbom:WEAK_JANINO",
			Type:   cdx.ComponentTypeLibrary,
			Name:   "janino-3.1.10.jar",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery.zip/plugins/janino-3.1.10.jar"},
				{Name: "extract-sbom:evidence-path", Value: "delivery.zip/plugins/janino-3.1.10.jar/META-INF/MANIFEST.MF"},
			},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "### extract-sbom:GOOD_JANINO") {
		t.Fatal("rich janino record missing from component index")
	}
	if strings.Contains(output, "### extract-sbom:WEAK_JANINO") {
		t.Fatal("weak duplicate placeholder should be merged away")
	}
}

func TestGenerateHumanComponentIndexPrunesAncestorDeliveryPaths(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "extract-sbom:JRT_FS",
		Type:       cdx.ComponentTypeLibrary,
		Name:       "jrt-fs",
		Version:    "11.0.30",
		PackageURL: "pkg:maven/jrt-fs/jrt-fs@11.0.30",
		Properties: &[]cdx.Property{
			{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client.zip"},
			{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar"},
			{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar"},
			{Name: "extract-sbom:evidence-path", Value: "delivery.zip/windows/Client.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"},
			{Name: "extract-sbom:evidence-path", Value: "delivery.zip/windows/Client.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"},
			{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
		},
	}}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "- Delivery path: `delivery.zip/windows/Client.zip`\n") {
		t.Fatal("report should not render redundant ancestor delivery path")
	}
	for _, fragment := range []string{
		"- Delivery path: `delivery.zip/windows/Client.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar`",
		"- Delivery path: `delivery.zip/windows/Client.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar`",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
}

// TestGenerateHumanRootPropertiesAreSorted verifies that repeated runs render
// root metadata properties in deterministic key order for audit stability.
func TestGenerateHumanRootPropertiesAreSorted(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Config.RootMetadata.Properties = map[string]string{
		"zeta":  "last",
		"alpha": "first",
		"mu":    "middle",
	}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "| alpha | first | User-supplied |")
	muIdx := strings.Index(output, "| mu | middle | User-supplied |")
	zetaIdx := strings.Index(output, "| zeta | last | User-supplied |")
	if alphaIdx == -1 || muIdx == -1 || zetaIdx == -1 {
		t.Fatal("expected sorted root property rows to be present in human report")
	}
	if alphaIdx >= muIdx || muIdx >= zetaIdx {
		t.Fatalf("root properties are not sorted deterministically: alpha=%d mu=%d zeta=%d", alphaIdx, muIdx, zetaIdx)
	}
}

// TestGenerateMachineIncludesProcessingIssues verifies that machine output
// includes processing issues for downstream automation.
func TestGenerateMachineIncludesProcessingIssues(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ProcessingIssues = []ProcessingIssue{{
		Stage:   "scan",
		Message: "syft catalog error",
	}}

	var buf bytes.Buffer
	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid machine report JSON: %v", err)
	}

	issues, ok := parsed["issues"].([]interface{})
	if !ok || len(issues) != 1 {
		t.Fatalf("issues missing or wrong size: %#v", parsed["issues"])
	}
	issue, ok := issues[0].(map[string]interface{})
	if !ok {
		t.Fatalf("issue entry has wrong type: %#v", issues[0])
	}
	if issue["stage"] != "scan" || issue["message"] != "syft catalog error" {
		t.Fatalf("unexpected issue payload: %#v", issue)
	}
}

// TestGenerateHumanIncludesNestedExtractionEvidenceAndPolicyDetails verifies
// that the human report includes the full extraction tree, evidence paths, and
// explanatory policy decisions for a nested delivery.
func TestGenerateHumanIncludesNestedExtractionEvidenceAndPolicyDetails(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "delivery.cab",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.CAB},
		Tool:   "7zz",
		Children: []*extract.ExtractionNode{{
			Path:   "delivery.cab/layer.tar",
			Status: extract.StatusExtracted,
			Format: identify.FormatInfo{Format: identify.TAR},
			Tool:   "archive/tar",
			Children: []*extract.ExtractionNode{{
				Path:   "delivery.cab/layer.tar/app.zip",
				Status: extract.StatusExtracted,
				Format: identify.FormatInfo{Format: identify.ZIP},
				Tool:   "archive/zip",
				Children: []*extract.ExtractionNode{{
					Path:   "delivery.cab/layer.tar/app.zip/lib.jar",
					Status: extract.StatusSyftNative,
					Format: identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
					Tool:   "syft",
				}},
			}},
		}},
	}
	data.Scans = []scan.ScanResult{{
		NodePath: "delivery.cab/layer.tar/app.zip/lib.jar",
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			BOMRef:  "pkg:maven/com.acme/demo@1.0.0",
			Name:    "demo",
			Version: "1.0.0",
		}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {"delivery.cab/layer.tar/app.zip/lib.jar/META-INF/MANIFEST.MF"},
		},
	}}
	data.PolicyDecisions = []policy.Decision{{
		Trigger:  "max-depth",
		NodePath: "delivery.cab/layer.tar/deeper.zip",
		Action:   policy.ActionSkip,
		Detail:   "Resource limit max-depth exceeded at delivery.cab/layer.tar/deeper.zip (partial mode: skipping subtree)",
	}}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	for _, fragment := range []string{
		"delivery.cab",
		"delivery.cab/layer.tar",
		"delivery.cab/layer.tar/app.zip",
		"delivery.cab/layer.tar/app.zip/lib.jar",
		"1 components found",
		"evidence-path: `delivery.cab/layer.tar/app.zip/lib.jar/META-INF/MANIFEST.MF`",
		"max-depth",
		"partial mode: skipping subtree",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
}

// TestGenerateMachineIncludesEvidencePaths verifies that machine-readable scan
// entries expose evidence paths for downstream automation.
func TestGenerateMachineIncludesEvidencePaths(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{{
		NodePath: "test.zip/lib.jar",
		BOM:      &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "pkg:maven/com.acme/demo@1.0.0"}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {"test.zip/lib.jar/META-INF/MANIFEST.MF"},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report struct {
		Scans []struct {
			NodePath      string   `json:"nodePath"`
			EvidencePaths []string `json:"evidencePaths"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.Scans) != 1 {
		t.Fatalf("machine report scans = %d, want 1", len(report.Scans))
	}
	if !reflect.DeepEqual(report.Scans[0].EvidencePaths, []string{"test.zip/lib.jar/META-INF/MANIFEST.MF"}) {
		t.Fatalf("evidencePaths = %v, want manifest path", report.Scans[0].EvidencePaths)
	}
}

// TestGenerateMachineProducesValidJSON verifies that the machine-readable
// report is valid JSON with the expected schema.
func TestGenerateMachineProducesValidJSON(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report["schemaVersion"] != "1.0.0" {
		t.Errorf("schemaVersion = %v, want %q", report["schemaVersion"], "1.0.0")
	}

	if report["input"] == nil {
		t.Error("missing 'input' field in JSON report")
	}

	if report["config"] == nil {
		t.Error("missing 'config' field in JSON report")
	}

	if report["extraction"] == nil {
		t.Error("missing 'extraction' field in JSON report")
	}

	generator, ok := report["generator"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'generator' field in JSON report")
	}
	if generator["version"] != "v1.2.3" {
		t.Fatalf("generator.version = %v, want %q", generator["version"], "v1.2.3")
	}
}

// TestGenerateMachineContainsTiming verifies that the machine report
// includes start/end times and duration.
func TestGenerateMachineContainsTiming(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report["startTime"] == nil {
		t.Error("missing startTime in JSON report")
	}

	if report["endTime"] == nil {
		t.Error("missing endTime in JSON report")
	}

	if report["duration"] == nil {
		t.Error("missing duration in JSON report")
	}
}

// TestResidualRiskWithUnsafeMode verifies that the residual risk section
// identifies unsafe mode as a risk.
func TestResidualRiskWithUnsafeMode(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
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
	data.Scans = []scan.ScanResult{
		{
			NodePath: "test.zip",
			Error:    &testError{msg: "syft failed"},
		},
	}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "scan") || !strings.Contains(output, "errors") {
		t.Error("residual risk does not mention scan errors")
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
