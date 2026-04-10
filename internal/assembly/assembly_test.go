// Assembly module tests: Verify that SBOM assembly correctly merges
// per-node CycloneDX BOMs into a consolidated SBOM with proper metadata,
// component trees, and deterministic output.
package assembly

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/extract"
	"github.com/sbom-sentry/internal/identify"
	"github.com/sbom-sentry/internal/scan"
)

// TestAssembleProducesValidBOM verifies that Assemble produces a well-formed
// CycloneDX BOM with correct metadata from the simplest possible input:
// a single extracted node with no scan results.
func TestAssembleProducesValidBOM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a minimal input file so we can compute its hash.
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake zip content"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.RootMetadata = config.RootMetadata{
		Name:         "TestProduct",
		Manufacturer: "TestCorp",
		Version:      "1.0.0",
		DeliveryDate: "2025-01-15",
	}

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("SpecVersion = %v, want 1.6", bom.SpecVersion)
	}

	if bom.Metadata == nil {
		t.Fatal("Metadata is nil")
	}

	if bom.Metadata.Component == nil {
		t.Fatal("Metadata.Component is nil")
	}

	if bom.Metadata.Component.Name != "TestProduct" {
		t.Errorf("root name = %q, want %q", bom.Metadata.Component.Name, "TestProduct")
	}

	if bom.Metadata.Component.Version != "1.0.0" {
		t.Errorf("root version = %q, want %q", bom.Metadata.Component.Version, "1.0.0")
	}

	if bom.Metadata.Component.Supplier == nil || bom.Metadata.Component.Supplier.Name != "TestCorp" {
		t.Error("root supplier not set to TestCorp")
	}

	// Verify hash was computed.
	if bom.Metadata.Component.Hashes == nil || len(*bom.Metadata.Component.Hashes) == 0 {
		t.Error("root component has no hashes")
	}
}

// TestAssembleNestedScenarioBuildsDependencyGraph verifies a realistic nested
// container chain with merged scan results: CAB -> TAR -> ZIP -> JAR -> package.
func TestAssembleNestedScenarioBuildsDependencyGraph(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outerPath := filepath.Join(dir, "delivery.cab")
	tarPath := filepath.Join(dir, "layer.tar")
	zipPath := filepath.Join(dir, "app.zip")
	jarPath := filepath.Join(dir, "lib.jar")
	for _, file := range []string{outerPath, tarPath, zipPath, jarPath} {
		if err := os.WriteFile(file, []byte(filepath.Base(file)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir

	jarNodePath := "delivery.cab/layer.tar/app.zip/lib.jar"
	tree := &extract.ExtractionNode{
		Path:         "delivery.cab",
		OriginalPath: outerPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.CAB},
		Children: []*extract.ExtractionNode{{
			Path:         "delivery.cab/layer.tar",
			OriginalPath: tarPath,
			Status:       extract.StatusExtracted,
			Format:       identify.FormatInfo{Format: identify.TAR},
			Children: []*extract.ExtractionNode{{
				Path:         "delivery.cab/layer.tar/app.zip",
				OriginalPath: zipPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
				Children: []*extract.ExtractionNode{{
					Path:         jarNodePath,
					OriginalPath: jarPath,
					Status:       extract.StatusSyftNative,
					Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
				}},
			}},
		}},
	}

	scans := []scan.ScanResult{{
		NodePath: jarNodePath,
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			BOMRef:  "pkg:maven/com.acme/demo@1.0.0",
			Name:    "demo",
			Version: "1.0.0",
		}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {jarNodePath + "/META-INF/MANIFEST.MF"},
		},
	}}

	bom, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}

	depsByRef := make(map[string][]string)
	for _, dep := range *bom.Dependencies {
		if dep.Dependencies != nil {
			depsByRef[dep.Ref] = append([]string(nil), *dep.Dependencies...)
		}
	}

	tarRef := makeBOMRef("delivery.cab/layer.tar")
	zipRef := makeBOMRef("delivery.cab/layer.tar/app.zip")
	jarRef := makeBOMRef(jarNodePath)
	pkgRef := jarRef + "/pkg:maven/com.acme/demo@1.0.0"
	rootRef := makeBOMRef("delivery.cab")

	if !reflect.DeepEqual(depsByRef[rootRef], []string{tarRef}) {
		t.Fatalf("root deps = %v, want [%s]", depsByRef[rootRef], tarRef)
	}
	if !reflect.DeepEqual(depsByRef[tarRef], []string{zipRef}) {
		t.Fatalf("tar deps = %v, want [%s]", depsByRef[tarRef], zipRef)
	}
	if !reflect.DeepEqual(depsByRef[zipRef], []string{jarRef}) {
		t.Fatalf("zip deps = %v, want [%s]", depsByRef[zipRef], jarRef)
	}
	if !reflect.DeepEqual(depsByRef[jarRef], []string{pkgRef}) {
		t.Fatalf("jar deps = %v, want [%s]", depsByRef[jarRef], pkgRef)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var packageFound bool
	for _, comp := range *bom.Components {
		if comp.BOMRef != pkgRef {
			continue
		}
		packageFound = true
		if comp.Properties == nil {
			t.Fatal("merged package has no properties")
		}
		props := make(map[string][]string)
		for _, prop := range *comp.Properties {
			props[prop.Name] = append(props[prop.Name], prop.Value)
		}
		if !reflect.DeepEqual(props["sbom-sentry:delivery-path"], []string{jarNodePath}) {
			t.Fatalf("delivery-path = %v, want [%s]", props["sbom-sentry:delivery-path"], jarNodePath)
		}
		if !reflect.DeepEqual(props["sbom-sentry:evidence-path"], []string{jarNodePath + "/META-INF/MANIFEST.MF"}) {
			t.Fatalf("evidence-path = %v, want manifest path", props["sbom-sentry:evidence-path"])
		}
	}
	if !packageFound {
		t.Fatal("merged package component not found")
	}
}

// TestAssembleWithScanResultsMergesComponents verifies that components
// from per-node scan results are merged into the consolidated BOM.
func TestAssembleWithScanResultsMergesComponents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	scans := []scan.ScanResult{
		{
			NodePath: "delivery.zip",
			BOM: &cdx.BOM{
				Components: &[]cdx.Component{
					{BOMRef: "pkg:npm/express@4.18.0", Name: "express", Version: "4.18.0"},
					{BOMRef: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21"},
				},
			},
		},
	}

	bom, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil, expected merged components")
	}

	if len(*bom.Components) < 2 {
		t.Errorf("Components count = %d, want >= 2", len(*bom.Components))
	}
}

// TestAssembleNestedTreeCreatesContainerComponents verifies that nested
// extraction nodes produce container-as-module components with proper
// dependency relationships.
func TestAssembleNestedTreeCreatesContainerComponents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	innerPath := filepath.Join(dir, "inner.zip")
	if err := os.WriteFile(innerPath, []byte("PK inner"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/inner.zip",
				OriginalPath: innerPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
			},
		},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil, expected container component for inner.zip")
	}

	// Should have at least one component for the inner container.
	found := false
	for _, comp := range *bom.Components {
		if comp.Name == "inner.zip" {
			found = true
			break
		}
	}

	if !found {
		t.Error("inner.zip container component not found in Components")
	}

	// Should have a dependency from root to inner.
	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}
}

// TestAssembleDeriveRootNameFromFilename verifies that when no root name
// is configured, the input filename is used as the root component name.
func TestAssembleDeriveRootNameFromFilename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "my-delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	// No RootMetadata.Name set.

	tree := &extract.ExtractionNode{
		Path:         "my-delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Metadata.Component.Name != "my-delivery.zip" {
		t.Errorf("root name = %q, want %q", bom.Metadata.Component.Name, "my-delivery.zip")
	}
}

// TestWriteSBOMWritesValidJSON verifies that WriteSBOM creates a readable
// CycloneDX JSON file.
func TestWriteSBOMWritesValidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "test.cdx.json")

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{}

	if err := WriteSBOM(bom, outPath); err != nil {
		t.Fatalf("WriteSBOM error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("cannot read output: %v", err)
	}

	if len(content) == 0 {
		t.Error("output file is empty")
	}

	// Should be valid JSON starting with {.
	if content[0] != '{' {
		t.Errorf("output doesn't start with '{', got %q", string(content[:10]))
	}
}

// TestGenerateCPEFromMetadata verifies CPE generation from MSI-style metadata.
func TestGenerateCPEFromMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		manufacturer string
		product      string
		version      string
		want         string
	}{
		{
			name:         "complete metadata",
			manufacturer: "Acme Corp", product: "Widget Pro", version: "2.1.0",
			want: "cpe:2.3:a:acme_corp:widget_pro:2.1.0:*:*:*:*:*:*:*",
		},
		{
			name:         "no version",
			manufacturer: "TestVendor", product: "TestApp", version: "",
			want: "cpe:2.3:a:testvendor:testapp:*:*:*:*:*:*:*:*",
		},
		{
			name:         "empty manufacturer",
			manufacturer: "", product: "SomeApp", version: "1.0",
			want: "",
		},
		{
			name:         "empty product",
			manufacturer: "Vendor", product: "", version: "1.0",
			want: "",
		},
		{
			name:         "special characters stripped",
			manufacturer: "Vendor (Inc.)", product: "App & Tools", version: "1.0",
			want: "cpe:2.3:a:vendor_inc.:app__tools:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := generateCPE(tt.manufacturer, tt.product, tt.version)
			if got != tt.want {
				t.Errorf("generateCPE(%q, %q, %q) = %q, want %q",
					tt.manufacturer, tt.product, tt.version, got, tt.want)
			}
		})
	}
}

// TestMakeBOMRefIsDeterministic verifies that makeBOMRef produces the same
// output for the same input, and different output for different inputs.
func TestMakeBOMRefIsDeterministic(t *testing.T) {
	t.Parallel()

	ref1 := makeBOMRef("/path/to/file.zip")
	ref2 := makeBOMRef("/path/to/file.zip")
	ref3 := makeBOMRef("/path/to/other.zip")

	if ref1 != ref2 {
		t.Errorf("same input produced different refs: %q vs %q", ref1, ref2)
	}

	if ref1 == ref3 {
		t.Errorf("different inputs produced same ref: %q", ref1)
	}

	if ref1 == "" {
		t.Error("BOMRef is empty")
	}

	// Should have the expected prefix.
	if ref1[:12] != "sbom-sentry:" {
		t.Errorf("BOMRef doesn't start with 'sbom-sentry:', got %q", ref1)
	}
}

// TestNormalizeCPEField verifies the CPE field normalization logic.
func TestNormalizeCPEField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"Hello World", "hello_world"},
		{"  spaces  ", "spaces"},
		{"UPPER", "upper"},
		{"with-dashes", "with-dashes"},
		{"under_scores", "under_scores"},
		{"dots.here", "dots.here"},
		{"special!@#$chars", "specialchars"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := normalizeCPEField(tt.input)
			if got != tt.want {
				t.Errorf("normalizeCPEField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestAssembleWithCompositions verifies that composition annotations
// are generated for extraction nodes based on their status.
func TestAssembleWithCompositions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "test.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Compositions == nil || len(*bom.Compositions) == 0 {
		t.Error("expected at least one composition annotation")
	}
}

// TestAssembleIncludesInterpretModeProperty verifies that the root component
// includes an sbom-sentry:interpret-mode property reflecting the configured mode.
func TestAssembleIncludesInterpretModeProperty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []config.InterpretMode{config.InterpretPhysical, config.InterpretInstallerSemantic} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			cfg := config.DefaultConfig()
			cfg.InputPath = inputPath
			cfg.OutputDir = dir
			cfg.InterpretMode = mode

			tree := &extract.ExtractionNode{
				Path:         "test.zip",
				OriginalPath: inputPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
			}

			bom, err := Assemble(tree, nil, cfg)
			if err != nil {
				t.Fatalf("Assemble error: %v", err)
			}

			props := bom.Metadata.Component.Properties
			if props == nil {
				t.Fatal("root component has no properties")
			}

			found := false
			for _, p := range *props {
				if p.Name == "sbom-sentry:interpret-mode" {
					if p.Value != mode.String() {
						t.Errorf("interpret-mode = %q, want %q", p.Value, mode.String())
					}
					found = true
				}
			}
			if !found {
				t.Error("sbom-sentry:interpret-mode property not found on root component")
			}
		})
	}
}

// TestAssembleInstallerHintSurfacedOnMSINode verifies that when an extraction
// node has an InstallerHint, it appears as an sbom-sentry:installer-hint
// property on the corresponding SBOM component.
func TestAssembleInstallerHintSurfacedOnMSINode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	msiPath := filepath.Join(dir, "setup.msi")
	if err := os.WriteFile(msiPath, []byte("MSI fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.InterpretMode = config.InterpretInstallerSemantic

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/setup.msi",
				OriginalPath: msiPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.MSI},
				Metadata: &extract.ContainerMetadata{
					ProductName:    "Acme Widget",
					Manufacturer:   "Acme Corp",
					ProductVersion: "3.0.0",
				},
				InstallerHint: "msi-file-table-remapping-available",
			},
		},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var hintFound bool
	for _, comp := range *bom.Components {
		if comp.Properties == nil {
			continue
		}
		for _, p := range *comp.Properties {
			if p.Name == "sbom-sentry:installer-hint" {
				if p.Value != "msi-file-table-remapping-available" {
					t.Errorf("installer-hint = %q, want %q", p.Value, "msi-file-table-remapping-available")
				}
				hintFound = true
			}
		}
	}

	if !hintFound {
		t.Error("sbom-sentry:installer-hint property not found on MSI component")
	}
}

// TestAssembleNoInstallerHintInPhysicalMode verifies that when InstallerHint
// is empty (physical mode), no installer-hint property appears.
func TestAssembleNoInstallerHintInPhysicalMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	msiPath := filepath.Join(dir, "setup.msi")
	if err := os.WriteFile(msiPath, []byte("MSI fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.InterpretMode = config.InterpretPhysical

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/setup.msi",
				OriginalPath: msiPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.MSI},
				Metadata: &extract.ContainerMetadata{
					ProductName:    "Acme Widget",
					Manufacturer:   "Acme Corp",
					ProductVersion: "3.0.0",
				},
				// InstallerHint is empty — physical mode doesn't set it.
			},
		},
	}

	bom, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		return // no components = no hint, that's fine
	}

	for _, comp := range *bom.Components {
		if comp.Properties == nil {
			continue
		}
		for _, p := range *comp.Properties {
			if p.Name == "sbom-sentry:installer-hint" {
				t.Errorf("unexpected installer-hint property in physical mode: %q", p.Value)
			}
		}
	}
}
