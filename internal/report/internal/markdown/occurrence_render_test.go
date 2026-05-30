package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func TestUniqueSortedPathsEmpty(t *testing.T) {
	t.Parallel()
	if got := uniqueSortedPaths(nil); got != nil {
		t.Fatalf("uniqueSortedPaths(nil) = %v, want nil", got)
	}
}

func TestUniqueSortedPathsDedupsAndSorts(t *testing.T) {
	t.Parallel()
	input := []string{"b/path", "a/path", "", "b/path", "c/path", ""}
	got := uniqueSortedPaths(input)
	want := []string{"a/path", "b/path", "c/path"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "#### alpha 1.0.0")
	zlibIdx := strings.Index(output, "#### zlib 1.2.13")
	if alphaIdx == -1 || zlibIdx == -1 {
		t.Fatal("package headings missing from report")
	}
	if alphaIdx >= zlibIdx {
		t.Fatalf("package groups are not sorted by delivery path: alpha=%d zlib=%d", alphaIdx, zlibIdx)
	}
	if !strings.Contains(output, "- Component-ID: <a id=\"component-extract-sbom-aaaa_aaaa\"></a>`extract-sbom:AAAA_AAAA`") {
		t.Fatal("nested occurrence list entry missing for alpha component")
	}

	for _, fragment := range []string{
		"Package: `alpha`",
		"PURL: `pkg:maven/com.acme/alpha@1.0.0`",
		"- Component-ID: <a id=\"component-extract-sbom-aaaa_aaaa\"></a>`extract-sbom:AAAA_AAAA`",
		"Delivery path: `a/path/alpha.jar`",
		"Evidence path: `a/path/alpha.jar/META-INF/MANIFEST.MF`",
		"Found by: `java-archive-cataloger`",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
	if strings.Contains(output, "Occurrences: 1") {
		t.Fatal("occurrence counter line should not be rendered")
	}
	if strings.Contains(output, "PURL: `pkg:maven/com.acme/alpha@1.0.0`\n\n- Component-ID") {
		t.Fatal("component-id entry must directly follow package list without blank line")
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "- Component-ID: <a id=\"component-extract-sbom-good_comp\"></a>`extract-sbom:GOOD_COMP`") {
		t.Error("properly-identified component missing from report")
	}
	if strings.Contains(output, "- Component-ID: <a id=\"component-extract-sbom-bad_comp\"></a>`extract-sbom:BAD_COMP`") {
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "- Component-ID: <a id=\"component-extract-sbom-good_janino\"></a>`extract-sbom:GOOD_JANINO`") {
		t.Fatal("rich janino record missing from component index")
	}
	if strings.Contains(output, "- Component-ID: <a id=\"component-extract-sbom-weak_janino\"></a>`extract-sbom:WEAK_JANINO`") {
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
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
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

func TestGenerateHumanComponentIndexRendersPackageLevelVulnerabilityStatus(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:ONE",
			Name:       "log4net",
			Version:    "2.0.13.0-.NET 4.5",
			PackageURL: "pkg:nuget/log4net@2.0.13.0-.NET%204.5",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/msi/log4net.dll"}},
		},
		{
			BOMRef:     "extract-sbom:TWO",
			Name:       "log4net",
			Version:    "2.0.13.0-.NET 4.5",
			PackageURL: "pkg:nuget/log4net@2.0.13.0-.NET%204.5",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/zip/log4net.dll"}},
		},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		State: vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"extract-sbom:ONE": {{
				VulnerabilityID: "GHSA-4f7c-pmjv-c25w",
				Severity:        "medium",
			}},
			"extract-sbom:TWO": {{
				VulnerabilityID: "GHSA-4f7c-pmjv-c25w",
				Severity:        "medium",
			}},
		},
	}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "`extract-sbom:ONE`") || !strings.Contains(output, "`extract-sbom:TWO`") {
		t.Fatalf("expected both occurrence list entries, got: %s", output)
	}
	if strings.Count(output, "Vulnerability status: `found` (1)") != 1 {
		t.Fatalf("expected a single package-level vulnerability status block, got: %s", output)
	}
}

func TestGenerateHumanComponentIndexRendersOccurrenceLevelVulnerabilityWhenBlocksDiffer(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:ONE",
			Name:       "log4net",
			Version:    "2.0.13.0-.NET 4.5",
			PackageURL: "pkg:nuget/log4net@2.0.13.0-.NET%204.5",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/msi/log4net.dll"}},
		},
		{
			BOMRef:     "extract-sbom:TWO",
			Name:       "log4net",
			Version:    "2.0.13.0-.NET 4.5",
			PackageURL: "pkg:nuget/log4net@2.0.13.0-.NET%204.5",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/zip/log4net.dll"}},
		},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		State: vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"extract-sbom:ONE": {{
				VulnerabilityID: "GHSA-4f7c-pmjv-c25w",
				Severity:        "medium",
			}},
		},
	}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Count(output, "Vulnerability status: `found` (1)") != 1 {
		t.Fatalf("expected one found status for first occurrence, got: %s", output)
	}
	if strings.Count(output, "Vulnerability status: `none`") == 0 {
		t.Fatalf("expected none status for second occurrence, got: %s", output)
	}
}
