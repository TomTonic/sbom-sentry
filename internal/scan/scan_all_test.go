package scan

import (
	"context"
	"os"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
)

// TestScanAllWithNoScannableNodesReturnsEmpty verifies that ScanAll returns
// an empty slice when the extraction tree contains no scannable nodes.
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
// scannable node points to a path that does not exist, the error is captured
// in the ScanResult instead of terminating the entire scan run.
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
	if results[0].Error != nil {
		t.Logf("per-node Syft error (accepted in test env): %v", results[0].Error)
	}
}
