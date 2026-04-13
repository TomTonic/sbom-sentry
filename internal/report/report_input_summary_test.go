package report

import (
	"os"
	"path/filepath"
	"testing"
)

// TestComputeInputSummaryComputesCorrectHashes verifies that SHA-256
// and SHA-512 hashes are computed correctly for the input file.
func TestComputeInputSummaryComputesCorrectHashes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := ComputeInputSummary(path)
	if err != nil {
		t.Fatalf("ComputeInputSummary error: %v", err)
	}

	if summary.Filename != "test.bin" {
		t.Errorf("Filename = %q, want %q", summary.Filename, "test.bin")
	}

	if summary.Size != 11 {
		t.Errorf("Size = %d, want 11", summary.Size)
	}

	// "hello world" SHA-256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if summary.SHA256 != expectedSHA256 {
		t.Errorf("SHA256 = %q, want %q", summary.SHA256, expectedSHA256)
	}

	if len(summary.SHA512) != 128 {
		t.Errorf("SHA512 length = %d, want 128", len(summary.SHA512))
	}
}

// TestComputeInputSummaryFailsForMissingFile verifies that a missing
// file produces an error.
func TestComputeInputSummaryFailsForMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ComputeInputSummary("/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
