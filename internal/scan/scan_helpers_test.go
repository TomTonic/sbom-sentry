package scan

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

func TestFormatComponentCountZero(t *testing.T) {
	t.Parallel()
	got := FormatComponentCount(0)
	if got != "0 components" {
		t.Fatalf("FormatComponentCount(0) = %q, want %q", got, "0 components")
	}
}

func TestFormatComponentCountOne(t *testing.T) {
	t.Parallel()
	got := FormatComponentCount(1)
	if got != "\033[1m1 component\033[0m" {
		t.Fatalf("FormatComponentCount(1) = %q", got)
	}
}

func TestFormatComponentCountMany(t *testing.T) {
	t.Parallel()
	got := FormatComponentCount(42)
	if got != "\033[1m42 components\033[0m" {
		t.Fatalf("FormatComponentCount(42) = %q", got)
	}
}

func TestCountScannedComponentsEmpty(t *testing.T) {
	t.Parallel()
	if got := CountScannedComponents(nil); got != 0 {
		t.Fatalf("CountScannedComponents(nil) = %d, want 0", got)
	}
}

func TestCountScannedComponentsMixed(t *testing.T) {
	t.Parallel()
	comps := []cdx.Component{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	scans := []ScanResult{
		{NodePath: "a.jar", BOM: &cdx.BOM{Components: &comps}},
		{NodePath: "b.jar", BOM: nil},
		{NodePath: "c.jar", Error: nil, BOM: &cdx.BOM{}},
	}
	if got := CountScannedComponents(scans); got != 3 {
		t.Fatalf("CountScannedComponents = %d, want 3", got)
	}
}

func TestIsManifestEvidenceCandidateExtensions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target string
		want   bool
	}{
		{"lib/app.jar", true},
		{"lib/app.JAR", true},
		{"lib/app.war", true},
		{"lib/app.ear", true},
		{"lib/app.jpi", true},
		{"lib/app.hpi", true},
		{"lib/app.zip", false},
		{"lib/app.tar.gz", false},
		{"lib/app.dll", false},
		{"lib/app", false},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if got := isManifestEvidenceCandidate(tt.target); got != tt.want {
				t.Errorf("isManifestEvidenceCandidate(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestFirstPropertyValueNilProperties(t *testing.T) {
	t.Parallel()
	comp := cdx.Component{Name: "test"}
	if got := firstPropertyValue(comp, "key"); got != "" {
		t.Fatalf("firstPropertyValue with nil properties = %q, want empty", got)
	}
}

func TestFirstPropertyValueFound(t *testing.T) {
	t.Parallel()
	comp := cdx.Component{
		Name: "test",
		Properties: &[]cdx.Property{
			{Name: "other", Value: "x"},
			{Name: "target", Value: "found"},
		},
	}
	if got := firstPropertyValue(comp, "target"); got != "found" {
		t.Fatalf("firstPropertyValue = %q, want %q", got, "found")
	}
}

func TestFirstPropertyValueNotFound(t *testing.T) {
	t.Parallel()
	comp := cdx.Component{
		Name:       "test",
		Properties: &[]cdx.Property{{Name: "other", Value: "x"}},
	}
	if got := firstPropertyValue(comp, "missing"); got != "" {
		t.Fatalf("firstPropertyValue = %q, want empty", got)
	}
}

func TestFlattenEvidencePathsEmpty(t *testing.T) {
	t.Parallel()
	result := ScanResult{}
	if got := FlattenEvidencePaths(result); got != nil {
		t.Fatalf("FlattenEvidencePaths empty = %v, want nil", got)
	}
}

func TestFlattenEvidencePathsOnlyEmptyStrings(t *testing.T) {
	t.Parallel()
	result := ScanResult{
		EvidencePaths: map[string][]string{
			"ref1": {""},
			"ref2": {""},
		},
	}
	if got := FlattenEvidencePaths(result); got != nil {
		t.Fatalf("FlattenEvidencePaths all-empty = %v, want nil", got)
	}
}

func TestDetectSyftVersionReturnsNonEmpty(t *testing.T) {
	t.Parallel()
	// detectSyftVersion() is called at init time and uses debug.ReadBuildInfo.
	// We just verify it returns a non-empty string.
	v := detectSyftVersion()
	if v == "" {
		t.Fatal("detectSyftVersion() returned empty string")
	}
}

func TestCollectScanTargetsSkipsAllNonScannableStatuses(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusSecurityBlocked,
		Children: []*extract.ExtractionNode{
			{Path: "a.jar", Status: extract.StatusFailed},
			{Path: "b.dll", Status: extract.StatusSkipped},
		},
	}
	var results []ScanResult
	collectScanTargets(root, &results)
	if len(results) != 0 {
		t.Fatalf("got %d results from non-scannable nodes, want 0", len(results))
	}
}

func TestFindNodeReturnsNilForMissing(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{Path: "root.zip"}
	if got := findNode(root, "nonexistent"); got != nil {
		t.Fatal("findNode should return nil for missing path")
	}
}

func TestFindNodeReturnsRoot(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{Path: "root.zip"}
	if got := findNode(root, "root.zip"); got != root {
		t.Fatal("findNode should return root for matching path")
	}
}

func TestFindNodeReturnsChild(t *testing.T) {
	t.Parallel()
	child := &extract.ExtractionNode{Path: "inner.jar"}
	root := &extract.ExtractionNode{
		Path:     "root.zip",
		Children: []*extract.ExtractionNode{child},
	}
	if got := findNode(root, "inner.jar"); got != child {
		t.Fatal("findNode should return child for matching path")
	}
}
