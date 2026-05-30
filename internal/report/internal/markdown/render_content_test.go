package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestGenerateHumanIncludesGeneratorBuildInfo verifies that build metadata
// for the generator is visible in the human-readable report.
func TestGenerateHumanIncludesGeneratorBuildInfo(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "| extract-sbom build | v1.2.3 rev 0123456789ab 2026-04-11T12:34:56Z dirty |") {
		t.Fatal("report does not contain generator build info")
	}
}

// TestGenerateHumanContainsRequiredSections verifies that the English
// Markdown report contains all required sections from DESIGN.md §10.4.
func TestGenerateHumanContainsRequiredSections(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	output := buf.String()

	requiredSections := []string{
		"# extract-sbom Audit Report",
		"## Table of Contents",
		"## Summary",
		"### Analysis Overview",
		"### Key Findings",
		"### Vulnerability Summary",
		"## Method At A Glance",
		"## Processing Errors",
		"## Residual Risk and Limitations",
		"## Appendix",
		"## Component Occurrence Index",
		"## Component Normalization",
		"## Input File",
		"## Configuration",
		"## Extension Filter",
		"## Root SBOM Metadata",
		"## Sandbox Configuration",
		"## Policy Decisions",
		"## Extraction Log",
		"## Package Scan Log",
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

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
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

	if err := GenerateMarkdownWithOptions(data, "de", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "## Processing Errors") {
		t.Fatal("report does not contain Processing Errors section")
	}
	if !strings.Contains(output, "| Source | Location | Class | Status | Detected | Tool | Archive Type | Archive Method | Encrypted | Physical Size | Detail |") {
		t.Fatal("report does not contain structured processing issue header")
	}
	if !strings.Contains(output, "| pipeline | assembly | pipeline-error |") || !strings.Contains(output, "failed to merge components") {
		t.Fatal("report does not contain processing issue details")
	}
}

// TestGenerateHumanTOCContainsAnchorLinks verifies that the Table of Contents
// includes clickable anchor links for all major sections.
func TestGenerateHumanTOCContainsAnchorLinks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, link := range []string{
		"- [Summary](#summary)",
		"  - [Analysis Overview](#analysis-overview)",
		"  - [Key Findings](#key-findings)",
		"  - [Vulnerability Summary](#vulnerability-summary)",
		"- [Method At A Glance](#method-at-a-glance)",
		"- [Processing Errors](#processing-errors)",
		"- [Residual Risk and Limitations](#residual-risk-and-limitations)",
		"- [Appendix](#appendix)",
		"- [Component Occurrence Index](#component-occurrence-index)",
		"- [Component Normalization](#component-normalization)",
		"- [Input File](#input-file)",
		"- [Configuration](#configuration)",
		"- [Extension Filter](#extension-filter)",
		"- [Policy Decisions](#policy-decisions)",
		"- [Package Scan Log](#scan-results)",
		"- [Extraction Log](#extraction-log)",
	} {
		if !strings.Contains(output, link) {
			t.Fatalf("report table of contents missing %q", link)
		}
	}
}

func TestGenerateHumanAvoidsDuplicateExplicitAnchorsForNaturalHeadingSlugs(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, anchor := range []string{
		"summary",
		"analysis-overview",
		"key-findings",
		"vulnerability-summary",
		"method-at-a-glance",
		"processing-errors",
		"residual-risk-and-limitations",
		"appendix",
		"component-occurrence-index",
		"component-normalization",
		"input-file",
		"configuration",
		"extension-filter",
		"root-sbom-metadata",
		"sandbox-configuration",
		"policy-decisions",
		"content-items-without-package-identities",
		"extraction-log",
	} {
		if strings.Contains(output, "<a id=\""+anchor+"\"></a>") {
			t.Fatalf("report should rely on Markdown heading slug for %q", anchor)
		}
	}

	if !strings.Contains(output, "<a id=\"scan-results\"></a>") {
		t.Fatal("report should keep explicit anchor when heading slug differs from link target")
	}
}

// TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst verifies that
// Summary/method/errors/risk appear before the large appendix sections.
func TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	summaryIdx := strings.Index(output, "## Summary")
	methodIdx := strings.Index(output, "## Method At A Glance")
	errorsIdx := strings.Index(output, "## Processing Errors")
	riskIdx := strings.Index(output, "## Residual Risk and Limitations")
	appendixIdx := strings.Index(output, "## Appendix")
	indexIdx := strings.Index(output, "## Component Occurrence Index")
	scanIdx := strings.Index(output, "## Package Scan Log")
	extractionIdx := strings.Index(output, "## Extraction Log")

	if summaryIdx == -1 || methodIdx == -1 || errorsIdx == -1 || riskIdx == -1 || appendixIdx == -1 || indexIdx == -1 || scanIdx == -1 || extractionIdx == -1 {
		t.Fatal("one or more expected sections are missing")
	}

	if summaryIdx >= appendixIdx || methodIdx >= appendixIdx ||
		summaryIdx >= scanIdx || summaryIdx >= extractionIdx ||
		methodIdx >= scanIdx || methodIdx >= extractionIdx ||
		errorsIdx >= scanIdx || errorsIdx >= extractionIdx ||
		riskIdx >= scanIdx || riskIdx >= extractionIdx ||
		appendixIdx >= indexIdx {
		t.Fatal("executive guidance is not placed before the appendix bulk sections")
	}
}

func TestGenerateHumanIncludesMethodDeepLinks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, fragment := range []string{
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#3-two-phases",
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#81-how-deduplication-works",
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#6-package-detection-reliability",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "2 components found") {
		t.Error("report does not show component count")
	}
	if !strings.Contains(output, "## Package Scan Log") {
		t.Error("report does not contain Package Scan Log section")
	}
	if !strings.Contains(output, "This is a per-item package scan log") {
		t.Error("scan log does not explain its item-level semantics")
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "| alpha | first | User-supplied |")
	muIdx := strings.Index(output, "| mu | middle | User-supplied |")
	zetaIdx := strings.Index(output, "| zeta | last | User-supplied |")
	if alphaIdx == -1 || muIdx == -1 || zetaIdx == -1 {
		t.Fatal("expected sorted root property rows to be present in markdown report")
	}
	if alphaIdx >= muIdx || muIdx >= zetaIdx {
		t.Fatalf("root properties are not sorted deterministically: alpha=%d mu=%d zeta=%d", alphaIdx, muIdx, zetaIdx)
	}
}

// TestGenerateHumanIncludesNestedExtractionEvidenceAndPolicyDetails verifies
// that the markdown report includes the full extraction tree, evidence paths, and
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
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
