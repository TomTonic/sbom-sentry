package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
)

func TestSortSuppressionRecords(t *testing.T) {
	t.Parallel()

	records := []assembly.SuppressionRecord{
		{DeliveryPath: "z/path", Component: cdx.Component{Name: "zlib"}},
		{DeliveryPath: "a/path", Component: cdx.Component{Name: "alpha"}},
		{DeliveryPath: "a/path", Component: cdx.Component{Name: "beta"}},
	}

	sortSuppressionRecords(records)
	if records[0].DeliveryPath != "a/path" || records[0].Component.Name != "alpha" {
		t.Fatalf("first record = %+v, want a/path alpha", records[0])
	}
	if records[1].DeliveryPath != "a/path" || records[1].Component.Name != "beta" {
		t.Fatalf("second record = %+v, want a/path beta", records[1])
	}
	if records[2].DeliveryPath != "z/path" {
		t.Fatalf("third record = %+v, want z/path", records[2])
	}
}

func TestWriteSuppressionReportUsesUniformTablesSortedAndLinked(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:FS_A",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-fs-a",
			PackageURL: "pkg:generic/kept-fs-a@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "a/fs"}},
		},
		{
			BOMRef:     "extract-sbom:FS_Z",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-fs-z",
			PackageURL: "pkg:generic/kept-fs-z@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "z/fs"}},
		},
		{
			BOMRef:     "extract-sbom:LOW_A",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-low-a",
			PackageURL: "pkg:generic/kept-low-a@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "a/low"}},
		},
		{
			BOMRef:     "extract-sbom:LOW_Z",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-low-z",
			PackageURL: "pkg:generic/kept-low-z@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "z/low"}},
		},
		{
			BOMRef:     "extract-sbom:WEAK_A",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-weak-a",
			PackageURL: "pkg:generic/kept-weak-a@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "a/weak"},
				{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
			},
		},
		{
			BOMRef:     "extract-sbom:WEAK_Z",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-weak-z",
			PackageURL: "pkg:generic/kept-weak-z@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "z/weak"},
				{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
			},
		},
		{
			BOMRef:     "extract-sbom:PURL_A",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-purl-a",
			PackageURL: "pkg:generic/kept-purl-a@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "a/purl"},
				{Name: "syft:package:foundBy", Value: "apk-db-cataloger"},
			},
		},
		{
			BOMRef:     "extract-sbom:PURL_Z",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "kept-purl-z",
			PackageURL: "pkg:generic/kept-purl-z@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "z/purl"},
				{Name: "syft:package:foundBy", Value: "apk-db-cataloger"},
			},
		},
	}}

	suppressions := []assembly.SuppressionRecord{
		{Reason: assembly.SuppressionFSArtifact, DeliveryPath: "z/fs", Component: cdx.Component{Name: "supp-fs-z"}},
		{Reason: assembly.SuppressionFSArtifact, DeliveryPath: "a/fs", Component: cdx.Component{Name: "supp-fs-a"}},
		{Reason: assembly.SuppressionLowValueFile, DeliveryPath: "z/low", Component: cdx.Component{Name: "supp-low-z"}},
		{Reason: assembly.SuppressionLowValueFile, DeliveryPath: "a/low", Component: cdx.Component{Name: "supp-low-a"}},
		{Reason: assembly.SuppressionWeakDuplicate, DeliveryPath: "z/weak", Component: cdx.Component{Name: "supp-weak-z"}, KeptName: "kept-weak-z", KeptFoundBy: "java-archive-cataloger"},
		{Reason: assembly.SuppressionWeakDuplicate, DeliveryPath: "a/weak", Component: cdx.Component{Name: "supp-weak-a"}, KeptName: "kept-weak-a", KeptFoundBy: "java-archive-cataloger"},
		{Reason: assembly.SuppressionPURLDuplicate, DeliveryPath: "z/purl", Component: cdx.Component{Name: "supp-purl-z"}, KeptName: "kept-purl-z", KeptFoundBy: "apk-db-cataloger"},
		{Reason: assembly.SuppressionPURLDuplicate, DeliveryPath: "a/purl", Component: cdx.Component{Name: "supp-purl-a"}, KeptName: "kept-purl-a", KeptFoundBy: "apk-db-cataloger"},
	}

	var buf bytes.Buffer
	writeSuppressionReport(&buf, suppressions, bom, getTranslations("en"))
	output := buf.String()

	if strings.Count(output, "| Delivery path | Suppressed component name | Suppressed by |") != 4 {
		t.Fatalf("expected 4 uniform suppression tables, got %d", strings.Count(output, "| Delivery path | Suppressed component name | Suppressed by |"))
	}

	fsA := strings.Index(output, "| `a/fs` | `supp-fs-a` | [extract-sbom:FS_A](#component-extract-sbom-fs_a) |")
	fsZ := strings.Index(output, "| `z/fs` | `supp-fs-z` | [extract-sbom:FS_Z](#component-extract-sbom-fs_z) |")
	if fsA == -1 || fsZ == -1 || fsA >= fsZ {
		t.Fatalf("FS artifact rows are missing or unsorted by delivery path (a=%d, z=%d)", fsA, fsZ)
	}

	lowA := strings.Index(output, "| `a/low` | `supp-low-a` | [extract-sbom:LOW_A](#component-extract-sbom-low_a) |")
	lowZ := strings.Index(output, "| `z/low` | `supp-low-z` | [extract-sbom:LOW_Z](#component-extract-sbom-low_z) |")
	if lowA == -1 || lowZ == -1 || lowA >= lowZ {
		t.Fatalf("low-value rows are missing or unsorted by delivery path (a=%d, z=%d)", lowA, lowZ)
	}

	weakA := strings.Index(output, "| `a/weak` | `supp-weak-a` | [extract-sbom:WEAK_A](#component-extract-sbom-weak_a) |")
	weakZ := strings.Index(output, "| `z/weak` | `supp-weak-z` | [extract-sbom:WEAK_Z](#component-extract-sbom-weak_z) |")
	if weakA == -1 || weakZ == -1 || weakA >= weakZ {
		t.Fatalf("weak-duplicate rows are missing or unsorted by delivery path (a=%d, z=%d)", weakA, weakZ)
	}

	purlA := strings.Index(output, "| `a/purl` | `supp-purl-a` | [extract-sbom:PURL_A](#component-extract-sbom-purl_a) |")
	purlZ := strings.Index(output, "| `z/purl` | `supp-purl-z` | [extract-sbom:PURL_Z](#component-extract-sbom-purl_z) |")
	if purlA == -1 || purlZ == -1 || purlA >= purlZ {
		t.Fatalf("purl-duplicate rows are missing or unsorted by delivery path (a=%d, z=%d)", purlA, purlZ)
	}
}

func TestWriteSuppressionReportExplainsMissingSuppressedByLink(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "extract-sbom:KNOWN_COMP",
		Type:       cdx.ComponentTypeLibrary,
		Name:       "known",
		PackageURL: "pkg:generic/known@1.0.0",
		Version:    "1.0.0",
		Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "known/path"}},
	}}}

	suppressions := []assembly.SuppressionRecord{{
		Reason:       assembly.SuppressionFSArtifact,
		DeliveryPath: "missing/path",
		Component:    cdx.Component{Name: "supp-missing"},
	}}

	var buf bytes.Buffer
	writeSuppressionReport(&buf, suppressions, bom, getTranslations("en"))
	output := buf.String()

	want := "| `missing/path` | `supp-missing` | *removed by normalization rule; no surviving package component exists for this delivery path (see [Component Occurrence Index](#component-occurrence-index))* |"
	if !strings.Contains(output, want) {
		t.Fatalf("missing italic suppressed-by explanation for unresolved link. want row %q", want)
	}
}

func TestWriteSuppressionReportDoesNotLinkToFilteredNonOccurrenceComponents(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:GOOD_COMP",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "good-lib",
			PackageURL: "pkg:generic/good-lib@1.0.0",
			Version:    "1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "good/path.dll"}},
		},
		{
			BOMRef:     "extract-sbom:FILTERED_FILE",
			Type:       cdx.ComponentTypeFile,
			Name:       "/tmp/extract-sbom-12345/good/path.dll",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "good/path.dll"}},
		},
	}}

	suppressions := []assembly.SuppressionRecord{{
		Reason:       assembly.SuppressionFSArtifact,
		DeliveryPath: "good/path.dll",
		Component:    cdx.Component{Name: "/tmp/extract-sbom-12345/good/path.dll"},
	}}

	var buf bytes.Buffer
	writeSuppressionReport(&buf, suppressions, bom, getTranslations("en"))
	output := buf.String()

	if strings.Contains(output, "#component-extract-sbom-filtered_file") {
		t.Fatal("suppression report must not link to filtered components that never appear in the occurrence index")
	}
	if !strings.Contains(output, "[extract-sbom:GOOD_COMP](#component-extract-sbom-good_comp)") {
		t.Fatal("suppression report should link to the rendered surviving occurrence")
	}
	if strings.Contains(output, "/tmp/extract-sbom-12345/good/path.dll`) | [extract-sbom:FILTERED_FILE](#component-extract-sbom-filtered_file)") {
		t.Fatal("suppression report linked to a filtered file-cataloger artifact")
	}
}
