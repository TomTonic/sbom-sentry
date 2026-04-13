package scan

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
)

// TestCollectEvidencePathsFromJARManifest verifies that scan results can carry
// deterministic evidence pointers for Syft-native JARs when a manifest exists.
func TestCollectEvidencePathsFromJARManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jarPath := filepath.Join(dir, "app.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	manifest, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write([]byte("Manifest-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	node := &extract.ExtractionNode{
		Path:         "delivery.zip/lib/app.jar",
		OriginalPath: jarPath,
		Status:       extract.StatusSyftNative,
		Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
	}
	bom := &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "pkg:maven/com.acme/app@1.0.0", Name: "app", Version: "1.0.0"}}}

	evidence := collectEvidencePaths(node, jarPath, bom)
	paths := evidence["pkg:maven/com.acme/app@1.0.0"]
	if !reflect.DeepEqual(paths, []string{"delivery.zip/lib/app.jar/META-INF/MANIFEST.MF"}) {
		t.Fatalf("evidence = %v, want manifest path", paths)
	}
}

// TestCollectEvidencePathsFromExtractedDirPEBinary verifies that for an
// extracted-directory node, collectEvidencePaths derives per-component
// evidence from syft:location:0:path for non-JAR files (PE binaries, dotnet
// DLLs, etc.), where the binary itself is the identity evidence.
func TestCollectEvidencePathsFromExtractedDirPEBinary(t *testing.T) {
	t.Parallel()

	node := &extract.ExtractionNode{
		Path:   "delivery.zip/setup.msi",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.MSI},
	}

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:  "syft-dll-1",
			Name:    "mfc42u.dll",
			Version: "6.02.400",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/mfc42u.dll"},
				{Name: "syft:package:foundBy", Value: "pe-binary-package-cataloger"},
			},
		},
		{
			BOMRef:  "syft-dll-2",
			Name:    "combit.CSharpScript28.Engine",
			Version: "28.3.0.0",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/native/lib/28/combit.CSharpScript28.Engine.x64.dll"},
				{Name: "syft:package:foundBy", Value: "dotnet-deps-binary-cataloger"},
			},
		},
	}}

	evidence := collectEvidencePaths(node, "/tmp/extracted-msi-xyz", bom)

	want1 := []string{"delivery.zip/setup.msi/mfc42u.dll"}
	if got := evidence["syft-dll-1"]; !reflect.DeepEqual(got, want1) {
		t.Errorf("mfc42u.dll evidence = %v, want %v", got, want1)
	}

	want2 := []string{"delivery.zip/setup.msi/native/lib/28/combit.CSharpScript28.Engine.x64.dll"}
	if got := evidence["syft-dll-2"]; !reflect.DeepEqual(got, want2) {
		t.Errorf("combit dll evidence = %v, want %v", got, want2)
	}
}

// TestCollectEvidencePathsFromExtractedDirIncludesJARs verifies that JAR files
// found in an extracted directory get the JAR path as evidence. Global
// cross-node dedup (in the assembly module) later selects between the
// extracted-dir entry and the SyftNative entry based on evidence richness.
func TestCollectEvidencePathsFromExtractedDirIncludesJARs(t *testing.T) {
	t.Parallel()

	node := &extract.ExtractionNode{
		Path:   "delivery.zip",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.ZIP},
	}

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:  "syft-jar",
			Name:    "gt-xsd-wfs",
			Version: "28.0",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/lib/gis/gt-xsd-wfs-28.0.jar"},
				{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
			},
		},
	}}

	evidence := collectEvidencePaths(node, "/tmp/extracted-zip-abc", bom)
	want := []string{"delivery.zip/lib/gis/gt-xsd-wfs-28.0.jar"}
	if got := evidence["syft-jar"]; !reflect.DeepEqual(got, want) {
		t.Errorf("JAR evidence = %v, want %v", got, want)
	}
}

// TestCollectEvidencePathsSkipsSelfReferencing verifies that when
// syft:location:0:path resolves to the node path itself (self-reference),
// no evidence is recorded; evidence equal to delivery path is meaningless.
func TestCollectEvidencePathsSkipsSelfReferencing(t *testing.T) {
	t.Parallel()

	node := &extract.ExtractionNode{
		Path:   "delivery.zip/app-1.0.zip",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.ZIP},
	}

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:  "self-ref",
			Name:    "app",
			Version: "1.0",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/"},
			},
		},
	}}

	evidence := collectEvidencePaths(node, "/tmp/extracted-xyz", bom)
	if evidence != nil {
		t.Errorf("expected nil evidence for self-referencing location, got %v", evidence)
	}
}

// TestFlattenEvidencePathsReturnsSortedUniqueValues verifies that report and
// machine-report generation can safely flatten evidence paths without
// duplicates.
func TestFlattenEvidencePathsReturnsSortedUniqueValues(t *testing.T) {
	t.Parallel()

	result := ScanResult{EvidencePaths: map[string][]string{
		"a": {"z/path", "a/path"},
		"b": {"a/path", "m/path"},
	}}

	got := FlattenEvidencePaths(result)
	want := []string{"a/path", "m/path", "z/path"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FlattenEvidencePaths() = %v, want %v", got, want)
	}
}
