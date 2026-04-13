package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtract7zMarksToolMissingWhenUnavailable(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("missing")
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sandbox.NewPassthroughSandbox(), t.TempDir(), config.DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusToolMissing {
		t.Fatalf("status = %v, want %v", node.Status, StatusToolMissing)
	}
	if node.Tool != "7zz" {
		t.Fatalf("tool = %q, want %q", node.Tool, "7zz")
	}
}

func TestExtract7zUsesSandboxOutputAndSummarizesFiles(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-7zz", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{name: "recording", run: func(_ string, _ []string, _ string, outputDir string) error {
		if err := os.MkdirAll(filepath.Join(outputDir, "nested"), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "nested", "a.txt"), []byte("alpha"), 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(outputDir, "b.txt"), []byte("beta"), 0o600)
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sb, t.TempDir(), config.DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sb.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(sb.calls))
	}
	if sb.calls[0].cmd != "7zz" {
		t.Fatalf("cmd = %q, want %q", sb.calls[0].cmd, "7zz")
	}
	if node.Status != StatusExtracted {
		t.Fatalf("status = %v, want %v", node.Status, StatusExtracted)
	}
	if node.SandboxUsed != "recording" {
		t.Fatalf("sandbox = %q, want %q", node.SandboxUsed, "recording")
	}
	if node.EntriesCount != 2 {
		t.Fatalf("entries = %d, want 2", node.EntriesCount)
	}
	if node.TotalSize != int64(len("alpha")+len("beta")) {
		t.Fatalf("total size = %d, want %d", node.TotalSize, len("alpha")+len("beta"))
	}
	if node.ExtractedDir == "" {
		t.Fatal("expected extracted dir to be recorded")
	}
	CleanupNode(node)
}

func TestExtractUnshieldPassesDestinationDirectory(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-unshield", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{name: "recording", run: func(_ string, args []string, _ string, outputDir string) error {
		wantArgs := []string{"-d", outputDir, "x", "/tmp/setup.cab"}
		if !reflect.DeepEqual(args, wantArgs) {
			return fmt.Errorf("args = %v, want %v", args, wantArgs)
		}
		return os.WriteFile(filepath.Join(outputDir, "payload.bin"), []byte("payload"), 0o600)
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.InstallShieldCAB}}
	err := extractUnshield(context.Background(), node, "/tmp/setup.cab", sb, t.TempDir(), config.DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusExtracted {
		t.Fatalf("status = %v, want %v", node.Status, StatusExtracted)
	}
	if node.EntriesCount != 1 {
		t.Fatalf("entries = %d, want 1", node.EntriesCount)
	}
	CleanupNode(node)
}

func TestExtract7zRejectsUnsafePostExtractionOutput(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-7zz", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{run: func(_ string, _ []string, _ string, outputDir string) error {
		return os.Symlink("/etc/passwd", filepath.Join(outputDir, "escape-link"))
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sb, t.TempDir(), config.DefaultLimits())
	if err == nil {
		t.Fatal("expected hard security error, got nil")
	}
	if _, ok := err.(*safeguard.HardSecurityError); !ok {
		t.Fatalf("error = %T, want *safeguard.HardSecurityError", err)
	}
	if node.ExtractedDir != "" {
		t.Fatal("unsafe extraction output should not be retained")
	}
}

func TestExtract7zToolMissingRecordsStatusCorrectly(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	dir := t.TempDir()

	savedLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("executable not found")
	}
	defer func() { lookPath = savedLookPath }()

	cabContent := []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	cabPath := filepath.Join(dir, "setup.cab")
	if err := os.WriteFile(cabPath, cabContent, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = cabPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), cabPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	if tree.Status != StatusToolMissing {
		t.Errorf("status = %v, want StatusToolMissing", tree.Status)
	}
	if tree.Tool != "7zz" {
		t.Errorf("Tool = %q, want 7zz", tree.Tool)
	}
}

func TestExtractInstallShieldToolMissingRecordsStatusCorrectly(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	dir := t.TempDir()

	savedLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("executable not found")
	}
	defer func() { lookPath = savedLookPath }()

	iscContent := []byte{'I', 'S', 'c', '(', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	iscPath := filepath.Join(dir, "data1.cab")
	if err := os.WriteFile(iscPath, iscContent, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = iscPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), iscPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	if tree.Status != StatusToolMissing {
		t.Errorf("status = %v, want StatusToolMissing", tree.Status)
	}
	if tree.Tool != "unshield" {
		t.Errorf("Tool = %q, want unshield", tree.Tool)
	}
}
