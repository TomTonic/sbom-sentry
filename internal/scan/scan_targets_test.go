// Scan module tests: verify tree walking and target collection behavior.
// Full Syft cataloging semantics are exercised by integration tests.
package scan

import (
	"testing"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
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

// TestFindNodeLocatesNodeByPath verifies that findNode correctly traverses
// the tree to locate nodes by their delivery path.
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

// TestFindNodeHandlesNilRoot verifies nil safety when callers search
// an empty extraction tree.
func TestFindNodeHandlesNilRoot(t *testing.T) {
	t.Parallel()

	if got := findNode(nil, "any/path"); got != nil {
		t.Fatalf("findNode(nil, ...) = %v, want nil", got)
	}
}

// TestScanResultZeroValue verifies that the zero-value ScanResult has the
// expected empty state.
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
