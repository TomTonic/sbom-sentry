package extract

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtractNestedZIPInZIPRecursesCorrectly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	innerPath := createTestZIP(t, dir, "inner.zip", map[string][]byte{
		"inner-file.txt": []byte("inner content"),
	})
	innerContent, err := os.ReadFile(innerPath)
	if err != nil {
		t.Fatal(err)
	}

	outerPath := createTestZIP(t, dir, "outer.zip", map[string][]byte{
		"inner.zip": innerContent,
		"readme.md": []byte("# Outer readme"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), outerPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want Extracted", tree.Status)
	}

	if len(tree.Children) == 0 {
		t.Fatal("expected at least one child node for nested ZIP")
	}

	foundInner := false
	for _, child := range tree.Children {
		if filepath.Base(child.Path) == "inner.zip" {
			foundInner = true
			if child.Status != StatusExtracted {
				t.Errorf("inner ZIP status = %v, want Extracted", child.Status)
			}
		}
	}

	if !foundInner {
		t.Error("inner.zip child node not found")
	}

	CleanupNode(tree)
}

func TestExtractRespectsDepthLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "test.zip", map[string][]byte{
		"file.txt": []byte("content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.Limits.MaxDepth = 0

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree should not be nil even when depth is exceeded")
	}

	if err != nil {
		if _, ok := err.(*safeguard.ResourceLimitError); !ok {
			t.Errorf("expected ResourceLimitError, got %T: %v", err, err)
		}
	}

	if tree.Status == StatusPending {
		t.Error("root node should not remain in pending status after extraction")
	}
}

func TestExtractHandlesContextCancellation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "test.zip", map[string][]byte{
		"file.txt": []byte("content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(ctx, zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree should not be nil even with cancelled context")
	}
	if err == nil && tree.Status == StatusExtracted {
		t.Log("extraction completed despite cancelled context (timing-dependent, acceptable)")
	}
}

func TestExtensionFilterSkipsDocumentFormats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	oleHeader := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	xlsContent := make([]byte, 300)
	copy(xlsContent, oleHeader)

	zipPath := createTestZIP(t, dir, "delivery.zip", map[string][]byte{
		"DataModel_de.xls": xlsContent,
		"readme.txt":       []byte("Hello"),
		"document.xlsx":    []byte("fake xlsx content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.SkipExtensions = []string{".xls", ".xlsx"}

	tree, err := Extract(context.Background(), zipPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want StatusExtracted", tree.Status)
	}

	var checkNoFailed func(n *ExtractionNode)
	checkNoFailed = func(n *ExtractionNode) {
		if n.Status == StatusFailed {
			t.Errorf("node %q has StatusFailed (StatusDetail=%q)", n.Path, n.StatusDetail)
		}
		for _, c := range n.Children {
			checkNoFailed(c)
		}
	}
	checkNoFailed(tree)

	CleanupNode(tree)
}

func TestIsSkippedExtension(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		skipList []string
		want     bool
	}{
		{"/path/file.xls", []string{".xls", ".xlsx"}, true},
		{"/path/file.XLS", []string{".xls", ".xlsx"}, true},
		{"/path/file.XLSX", []string{".xls", ".xlsx"}, true},
		{"/path/file.msi", []string{".xls", ".xlsx"}, false},
		{"/path/file.msi", []string{}, false},
		{"/path/file", []string{".xls"}, false},
		{"/path/file.xls", []string{".XLS"}, true},
	}

	for _, tt := range tests {
		got := isSkippedExtension(tt.path, tt.skipList)
		if got != tt.want {
			t.Errorf("isSkippedExtension(%q, %v) = %v, want %v", tt.path, tt.skipList, got, tt.want)
		}
	}
}

func TestExtractionNodeStatusStringReturnsReadableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status ExtractionStatus
		want   string
	}{
		{StatusPending, "pending"},
		{StatusSyftNative, "syft-native"},
		{StatusExtracted, "extracted"},
		{StatusSkipped, "skipped"},
		{StatusFailed, "failed"},
		{StatusSecurityBlocked, "security-blocked"},
		{StatusToolMissing, "tool-missing"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanupNodeRemovesTemporaryDirectories(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	childDir, err := os.MkdirTemp(tmpDir, "child-*")
	if err != nil {
		t.Fatal(err)
	}

	node := &ExtractionNode{
		ExtractedDir: tmpDir,
		Children: []*ExtractionNode{
			{ExtractedDir: childDir},
		},
	}

	if err := os.WriteFile(filepath.Join(childDir, "test.txt"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	CleanupNode(node)

	if _, err := os.Stat(childDir); err == nil {
		t.Error("child temp dir still exists after cleanup")
	}
}
