// SPDX serialization tests validate the user-visible SPDX 2.3 JSON artifact:
// that the document parses, that license and package data survive the
// CycloneDX→SPDX conversion, and — critically — that the output is reproducible
// so two runs over the same input yield byte-for-byte identical SBOMs. These
// behaviors belong to the assembly module's SBOM-writing responsibility.
package assembly

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// spdxJSONDoc captures the subset of SPDX 2.3 JSON fields the tests assert on.
type spdxJSONDoc struct {
	SPDXVersion       string `json:"spdxVersion"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created string `json:"created"`
	} `json:"creationInfo"`
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"versionInfo"`
		License string `json:"licenseConcluded"`
	} `json:"packages"`
	Relationships []struct {
		Type string `json:"relationshipType"`
	} `json:"relationships"`
}

// testSPDXBOM builds a representative CycloneDX BOM with a root component, two
// dependency components, a license, and a fixed metadata timestamp.
func testSPDXBOM() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: "2026-01-02T03:04:05Z",
		Component: &cdx.Component{
			BOMRef:  "root-component",
			Name:    "demo-product",
			Version: "2.1.0",
		},
	}
	bom.Components = &[]cdx.Component{
		{
			BOMRef:     "pkg:generic/libA@1.0.0",
			Name:       "libA",
			Version:    "1.0.0",
			PackageURL: "pkg:generic/libA@1.0.0",
			Licenses:   &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
		},
		{
			BOMRef:  "pkg:generic/libB@2.0.0",
			Name:    "libB",
			Version: "2.0.0",
		},
	}
	return bom
}

// parseSPDX decodes SPDX JSON bytes or fails the test.
func parseSPDX(t *testing.T, raw []byte) spdxJSONDoc {
	t.Helper()
	var doc spdxJSONDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}
	return doc
}

// TestWriteSBOMSPDXProducesParseableDocument verifies that the on-disk SPDX
// artifact is valid JSON, carries the document name from the root component,
// and includes every CycloneDX component as an SPDX package.
func TestWriteSBOMSPDXProducesParseableDocument(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "out.spdx.json")
	if err := WriteSBOMSPDX(testSPDXBOM(), path); err != nil {
		t.Fatalf("WriteSBOMSPDX error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SPDX output: %v", err)
	}
	doc := parseSPDX(t, raw)

	if doc.SPDXVersion == "" {
		t.Error("spdxVersion is empty, want a populated SPDX version")
	}
	if doc.Name != "demo-product" {
		t.Errorf("document name = %q, want %q", doc.Name, "demo-product")
	}
	names := map[string]bool{}
	for _, p := range doc.Packages {
		names[p.Name] = true
	}
	for _, want := range []string{"demo-product", "libA", "libB"} {
		if !names[want] {
			t.Errorf("SPDX packages missing %q (got %v)", want, names)
		}
	}
}

// TestWriteSPDXIsDeterministicAcrossRuns verifies the reproducibility fix: two
// conversions of the same BOM must produce byte-for-byte identical SPDX. Before
// the fix a fresh random namespace UUID and a wall-clock timestamp were
// injected on every run, so identical input produced differing SBOMs.
func TestWriteSPDXIsDeterministicAcrossRuns(t *testing.T) {
	t.Parallel()

	bom := testSPDXBOM()
	var first, second bytes.Buffer
	if err := writeSPDXTo(bom, &first); err != nil {
		t.Fatalf("first writeSPDXTo error: %v", err)
	}
	if err := writeSPDXTo(bom, &second); err != nil {
		t.Fatalf("second writeSPDXTo error: %v", err)
	}
	if first.String() != second.String() {
		t.Error("SPDX output differs between two runs over identical input; output is not reproducible")
	}
}

// TestSPDXDocumentNamespaceIsStableAndDistinct verifies that the document
// namespace is derived deterministically: identical BOMs share a namespace,
// while a BOM with a different component set receives a different one.
func TestSPDXDocumentNamespaceIsStableAndDistinct(t *testing.T) {
	t.Parallel()

	const created = "2026-01-02T03:04:05Z"
	nsA := spdxDocumentNamespace(testSPDXBOM(), "demo-product", created)
	nsB := spdxDocumentNamespace(testSPDXBOM(), "demo-product", created)
	if nsA != nsB {
		t.Errorf("namespace not stable for identical BOMs: %q vs %q", nsA, nsB)
	}

	changed := testSPDXBOM()
	(*changed.Components)[0].Version = "9.9.9"
	nsChanged := spdxDocumentNamespace(changed, "demo-product", created)
	if nsChanged == nsA {
		t.Error("namespace did not change when the component set changed")
	}
	if !strings.HasPrefix(nsA, "https://extract-sbom/spdx/") {
		t.Errorf("namespace = %q, want the extract-sbom SPDX URI prefix", nsA)
	}
}

// TestSPDXCreatedUsesBOMMetadataTimestamp verifies that the SPDX creation
// timestamp is taken from the source BOM (which itself derives it from the
// input file) rather than the wall clock.
func TestSPDXCreatedUsesBOMMetadataTimestamp(t *testing.T) {
	t.Parallel()

	if got := spdxCreated(testSPDXBOM()); got != "2026-01-02T03:04:05Z" {
		t.Errorf("spdxCreated = %q, want the BOM metadata timestamp", got)
	}
}

// TestSPDXCreatedFallsBackToFixedSentinel verifies that, when no BOM timestamp
// is available, a fixed sentinel is used so the output stays reproducible
// instead of falling back to the current time.
func TestSPDXCreatedFallsBackToFixedSentinel(t *testing.T) {
	t.Parallel()

	if got := spdxCreated(nil); got != spdxFallbackCreated {
		t.Errorf("spdxCreated(nil) = %q, want %q", got, spdxFallbackCreated)
	}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{}
	if got := spdxCreated(bom); got != spdxFallbackCreated {
		t.Errorf("spdxCreated(no timestamp) = %q, want %q", got, spdxFallbackCreated)
	}
}

// TestSPDXLicenseMappingPrefersIDThenExpression verifies how a CycloneDX
// component license is projected onto the SPDX licenseConcluded field: an SPDX
// license ID is used directly, a license expression is used as a fallback, and
// a component with no license data yields NOASSERTION.
func TestSPDXLicenseMappingPrefersIDThenExpression(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		component cdx.Component
		want      string
	}{
		{
			name:      "license ID is used directly",
			component: cdx.Component{Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}}},
			want:      "Apache-2.0",
		},
		{
			name:      "license expression is used when no ID is present",
			component: cdx.Component{Licenses: &cdx.Licenses{{Expression: "MIT OR GPL-2.0-only"}}},
			want:      "MIT OR GPL-2.0-only",
		},
		{
			name:      "missing license data yields NOASSERTION",
			component: cdx.Component{},
			want:      "NOASSERTION",
		},
	}
	for i := range cases {
		tc := cases[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := spdxLicense(tc.component); got != tc.want {
				t.Errorf("spdxLicense = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWriteSBOMSPDXHandlesNilBOM verifies that a nil BOM still yields a minimal
// valid SPDX document rather than an error or empty file.
func TestWriteSBOMSPDXHandlesNilBOM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nil.spdx.json")
	if err := WriteSBOMSPDX(nil, path); err != nil {
		t.Fatalf("WriteSBOMSPDX(nil) error: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SPDX output: %v", err)
	}
	doc := parseSPDX(t, raw)
	if doc.SPDXVersion == "" {
		t.Error("nil-BOM SPDX document has an empty spdxVersion")
	}
}

// TestSanitizeSPDXIDProducesValidElementIDs verifies that bom-ref strings with
// characters disallowed in SPDX element IDs are normalized to alphanumeric and
// hyphen characters, and that an empty bom-ref yields a stable placeholder.
func TestSanitizeSPDXIDProducesValidElementIDs(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"pkg:generic/lib@1.0.0", "a//b::c", ""} {
		got := sanitizeSPDXID(in)
		if got == "" {
			t.Errorf("sanitizeSPDXID(%q) is empty, want a non-empty element ID", in)
		}
		if strings.ContainsAny(got, "/:@") {
			t.Errorf("sanitizeSPDXID(%q) = %q still contains disallowed characters", in, got)
		}
	}
	if got := sanitizeSPDXID(""); got != "component" {
		t.Errorf("sanitizeSPDXID(\"\") = %q, want %q", got, "component")
	}
}
