package extract

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// TestExtract7zWithPasswords_NoPasswordNeeded validates that when an archive is
// not encrypted, extract7zWithPasswords succeeds on the first attempt (the
// no-password attempt) without invoking the sandbox more than once.
func TestExtract7zWithPasswords_NoPasswordNeeded(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()
	orig := lookPath
	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	defer func() { lookPath = orig }()

	calls := 0
	sb := &recordingSandbox{
		run: func(_ string, _ []string, _ string, outputDir string) error {
			calls++
			// Simulate successful extraction by writing a file to outDir.
			return os.WriteFile(filepath.Join(outputDir, "file.txt"), []byte("data"), 0o600)
		},
	}

	dir := t.TempDir()
	node := &ExtractionNode{Path: "archive.7z"}
	err := extract7zWithPasswords(context.Background(), node, "/tmp/archive.7z", sb, dir, config.DefaultLimits(), []string{"pw1", "pw2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusExtracted {
		t.Errorf("status = %v, want StatusExtracted", node.Status)
	}
	if calls != 1 {
		t.Errorf("sandbox called %d times, want 1 (no-password attempt should succeed)", calls)
	}
}

// TestExtract7zWithPasswords_CorrectPassword validates that when the first two
// attempts fail (no password, wrong password) but the third matches, the node
// is marked extracted and the sandbox was called exactly three times.
func TestExtract7zWithPasswords_CorrectPassword(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()
	orig := lookPath
	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	defer func() { lookPath = orig }()

	const correctPW = "correct"
	calls := 0
	sb := &recordingSandbox{
		run: func(_ string, args []string, _ string, outputDir string) error {
			calls++
			// Check if the correct password was provided as -p<password> arg.
			for _, a := range args {
				if a == "-p"+correctPW {
					return os.WriteFile(filepath.Join(outputDir, "file.txt"), []byte("data"), 0o600)
				}
			}
			// No matching -p arg → simulate wrong-password failure.
			return os.ErrPermission
		},
	}

	dir := t.TempDir()
	node := &ExtractionNode{Path: "archive.zip"}
	err := extract7zWithPasswords(context.Background(), node, "/tmp/archive.zip", sb, dir, config.DefaultLimits(), []string{"wrong1", correctPW, "wrong2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusExtracted {
		t.Errorf("status = %v, want StatusExtracted", node.Status)
	}
	// Attempts: no-pw, "wrong1", correctPW → 3 calls
	if calls != 3 {
		t.Errorf("sandbox called %d times, want 3", calls)
	}
}

// TestExtract7zWithPasswords_AllPasswordsFail validates that when no candidate
// password matches, the node is marked failed with a descriptive message and
// the function returns nil (not a hard infrastructure error).
func TestExtract7zWithPasswords_AllPasswordsFail(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()
	orig := lookPath
	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	defer func() { lookPath = orig }()

	sb := &recordingSandbox{
		run: func(_ string, _ []string, _ string, _ string) error {
			return os.ErrPermission // always fail
		},
	}

	dir := t.TempDir()
	node := &ExtractionNode{Path: "archive.zip"}
	err := extract7zWithPasswords(context.Background(), node, "/tmp/archive.zip", sb, dir, config.DefaultLimits(), []string{"pw1", "pw2"})
	if err != nil {
		t.Fatalf("expected nil error (failure captured in node), got %v", err)
	}
	if node.Status != StatusFailed {
		t.Errorf("status = %v, want StatusFailed", node.Status)
	}
	if node.StatusDetail == "" {
		t.Error("StatusDetail must not be empty on failure")
	}
}

// TestExtract7zWithPasswords_ToolMissing validates that when 7-Zip is not
// installed, the function immediately sets StatusToolMissing and returns nil
// without attempting any password.
func TestExtract7zWithPasswords_ToolMissing(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()
	orig := lookPath
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	defer func() { lookPath = orig }()

	dir := t.TempDir()
	node := &ExtractionNode{Path: "archive.7z"}
	err := extract7zWithPasswords(context.Background(), node, "/tmp/archive.7z", &recordingSandbox{}, dir, config.DefaultLimits(), []string{"pw1"})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if node.Status != StatusToolMissing {
		t.Errorf("status = %v, want StatusToolMissing", node.Status)
	}
}
