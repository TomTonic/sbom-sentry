// Output and identifier tests validate user-visible SBOM serialization,
// deterministic identifier generation, and CPE normalization rules.
package assembly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestWriteSBOMWritesValidJSON verifies that WriteSBOM creates a readable
// CycloneDX JSON file.
func TestWriteSBOMWritesValidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "test.cdx.json")

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{}

	if err := WriteSBOM(bom, outPath, "cyclonedx-json"); err != nil {
		t.Fatalf("WriteSBOM error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("cannot read output: %v", err)
	}

	if len(content) == 0 {
		t.Error("output file is empty")
	}

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

	if !strings.HasPrefix(ref1, "extract-sbom:") {
		t.Errorf("BOMRef doesn't start with 'extract-sbom:', got %q", ref1)
	}

	token := strings.TrimPrefix(ref1, "extract-sbom:")
	if len(token) != 9 || token[4] != '_' {
		t.Errorf("BOMRef token = %q, want 8 chars grouped as XXXX_XXXX", token)
	}
}

// TestBOMRefAssignerResolvesCollisionsDeterministically verifies that
// short BOM refs are collision-checked and resolved in stable sorted-key order.
func TestBOMRefAssignerResolvesCollisionsDeterministically(t *testing.T) {
	t.Parallel()

	assigner := newBOMRefAssignerWithKeys([]string{"node-b", "node-a"}, func(key string, salt int) string {
		if salt == 0 {
			return "extract-sbom:AAAA_AAAA"
		}
		if key == "node-a" {
			return "extract-sbom:BBBB_BBBB"
		}
		return "extract-sbom:CCCC_CCCC"
	})

	if got := assigner.RefForNode("node-a"); got != "extract-sbom:AAAA_AAAA" {
		t.Fatalf("node-a ref = %q, want extract-sbom:AAAA_AAAA", got)
	}
	if got := assigner.RefForNode("node-b"); got != "extract-sbom:CCCC_CCCC" {
		t.Fatalf("node-b ref = %q, want extract-sbom:CCCC_CCCC", got)
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
