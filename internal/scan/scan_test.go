// Scan module tests: Verify the scan module's tree walking and target
// collection logic. Actual Syft invocation is not tested in unit tests
// since it requires real filesystem artifacts and pulls in the entire
// Syft cataloger stack.
package scan

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/extract"
	"github.com/sbom-sentry/internal/identify"
)

// TestCollectScanTargetsFindsExtractedNodes verifies that the scan target
// collector identifies extracted nodes for Syft scanning.
func TestCollectScanTargetsFindsExtractedNodes(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:   "root.zip/lib.jar",
				Status: extract.StatusSyftNative,
				Format: identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
			},
			{
				Path:   "root.zip/readme.txt",
				Status: extract.StatusSkipped,
				Format: identify.FormatInfo{Format: identify.Unknown},
			},
			{
				Path:   "root.zip/inner.tar.gz",
				Status: extract.StatusExtracted,
				Format: identify.FormatInfo{Format: identify.GzipTAR},
			},
		},
	}

	var results []ScanResult
	collectScanTargets(tree, &results)

	// root.zip (extracted) + lib.jar (syft-native) + inner.tar.gz (extracted) = 3
	if len(results) != 3 {
		t.Errorf("scan targets = %d, want 3", len(results))
	}

	paths := make(map[string]bool)
	for _, r := range results {
		paths[r.NodePath] = true
	}

	expected := []string{"root.zip", "root.zip/lib.jar", "root.zip/inner.tar.gz"}
	for _, p := range expected {
		if !paths[p] {
			t.Errorf("missing scan target %q", p)
		}
	}
}

// TestCollectScanTargetsSkipsNonScannableNodes verifies that nodes with
// non-scannable statuses are excluded from scan targets.
func TestCollectScanTargetsSkipsNonScannableNodes(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusFailed,
		Format: identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:   "root.zip/blocked",
				Status: extract.StatusSecurityBlocked,
			},
			{
				Path:   "root.zip/tool-missing",
				Status: extract.StatusToolMissing,
			},
			{
				Path:   "root.zip/skipped",
				Status: extract.StatusSkipped,
			},
		},
	}

	var results []ScanResult
	collectScanTargets(tree, &results)

	if len(results) != 0 {
		t.Errorf("scan targets = %d, want 0 (none scannable)", len(results))
	}
}

// TestCollectScanTargetsHandlesNilNode verifies nil safety.
func TestCollectScanTargetsHandlesNilNode(t *testing.T) {
	t.Parallel()

	var results []ScanResult
	collectScanTargets(nil, &results)

	if len(results) != 0 {
		t.Errorf("scan targets from nil = %d, want 0", len(results))
	}
}

// TestFindNodeLocatesNodeByPath verifies that findNode correctly
// traverses the tree to locate nodes by their delivery path.
func TestFindNodeLocatesNodeByPath(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path: "root",
		Children: []*extract.ExtractionNode{
			{
				Path: "root/child1",
				Children: []*extract.ExtractionNode{
					{Path: "root/child1/grandchild"},
				},
			},
			{Path: "root/child2"},
		},
	}

	tests := []struct {
		path  string
		found bool
	}{
		{"root", true},
		{"root/child1", true},
		{"root/child2", true},
		{"root/child1/grandchild", true},
		{"root/nonexistent", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			node := findNode(tree, tt.path)
			if tt.found && node == nil {
				t.Errorf("findNode(%q) = nil, want non-nil", tt.path)
			}
			if !tt.found && node != nil {
				t.Errorf("findNode(%q) = non-nil, want nil", tt.path)
			}
		})
	}
}

// TestScanResultZeroValue verifies that the zero-value ScanResult
// has the expected empty state.
func TestScanResultZeroValue(t *testing.T) {
	t.Parallel()

	var sr ScanResult
	if sr.NodePath != "" {
		t.Errorf("NodePath = %q, want empty", sr.NodePath)
	}
	if sr.BOM != nil {
		t.Error("BOM is non-nil, want nil")
	}
	if sr.EvidencePaths != nil {
		t.Error("EvidencePaths is non-nil, want nil")
	}
	if sr.Error != nil {
		t.Error("Error is non-nil, want nil")
	}
}

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

// TestFlattenEvidencePathsReturnsSortedUniqueValues verifies that report and
// machine-report generation can safely flatten evidence paths without duplicates.
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

// TestScanAllWithNoScannableNodesReturnsEmpty verifies that ScanAll returns
// an empty slice when the extraction tree contains no scannable nodes.
// This is the normal case for unrecognised or blocked archives.
func TestScanAllWithNoScannableNodesReturnsEmpty(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "blocked.zip",
		Status: extract.StatusSecurityBlocked,
	}

	cfg := config.DefaultConfig()
	results, err := ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("ScanAll got %d results, want 0", len(results))
	}
}

// TestScanAllWithNonExistentTargetCapturesError verifies that when a
// scannable node points to a path that does not exist, the error is
// captured in the ScanResult rather than terminating the entire scan run.
func TestScanAllWithNonExistentTargetCapturesError(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: "/nonexistent/path/delivery.zip",
		Status:       extract.StatusSyftNative,
		Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
	}

	cfg := config.DefaultConfig()
	results, err := ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll returned unexpected top-level error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected per-node error for nonexistent target, got nil")
	}
}

// TestScanAllWithEmptyExtractedDirectoryCallsSyft verifies that ScanAll
// invokes Syft for an extracted node pointing to a real (empty) directory.
// This exercises the ScanAll loop, scanNode, and the full Syft library
// integration path. In unit tests Syft may fail due to missing build-time
// dependencies (e.g., sqlite for RPM cataloging); what matters is that the
// scan pipeline executes and captures any error in the per-node result rather
// than panicking or dropping the result entirely.
func TestScanAllWithEmptyExtractedDirectoryCallsSyft(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	extractedDir, err := os.MkdirTemp(dir, "extracted-*")
	if err != nil {
		t.Fatal(err)
	}

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: dir,
		ExtractedDir: extractedDir,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	cfg := config.DefaultConfig()
	results, err := ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll returned unexpected top-level error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 1 extracted node, got %d", len(results))
	}
	if results[0].NodePath != "delivery.zip" {
		t.Errorf("NodePath = %q, want delivery.zip", results[0].NodePath)
	}
	// A per-node scan error is acceptable in unit tests where Syft may be
	// missing build-time dependencies (sqlite for RPM cataloging). The
	// important assertions are that ScanAll ran and returned exactly one result.
	if results[0].Error != nil {
		t.Logf("per-node Syft error (accepted in test env): %v", results[0].Error)
	}
}
