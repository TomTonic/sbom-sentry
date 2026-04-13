package extract

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtractTARGZProducesExtractionTree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	tarPath := createTestTARGZ(t, dir, "delivery.tar.gz", map[string][]byte{
		"app.bin":        []byte("ELF fake binary"),
		"config/app.yml": []byte("key: value"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = tarPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), tarPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want Extracted", tree.Status)
	}

	if tree.EntriesCount != 2 {
		t.Errorf("EntriesCount = %d, want 2", tree.EntriesCount)
	}

	CleanupNode(tree)
}

func TestExtractTARWithSymlinkRejects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	tarPath := filepath.Join(dir, "symlink.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}

	tw := tar.NewWriter(f)

	if err := tw.WriteHeader(&tar.Header{
		Name: "normal.txt",
		Mode: 0o644,
		Size: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "evil-link",
		Linkname: "/etc/passwd",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	f.Close()

	cfg := config.DefaultConfig()
	cfg.InputPath = tarPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, _ := Extract(context.Background(), tarPath, cfg, sb)

	if tree != nil && tree.Status == StatusExtracted {
		if tree.ExtractedDir != "" {
			linkPath := filepath.Join(tree.ExtractedDir, "evil-link")
			if info, err := os.Lstat(linkPath); err == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					t.Fatal("symlink was created despite safeguard — SECURITY VIOLATION")
				}
			}
		}
	}

	if tree != nil {
		CleanupNode(tree)
	}
}

func TestExtractPlainTARProducesExtractionTree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	tarPath := createTestTAR(t, dir, "delivery.tar", map[string][]byte{
		"readme.txt": []byte("plain tar content"),
		"bin/tool":   []byte("binary data"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = tarPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), tarPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Status != StatusExtracted {
		t.Errorf("status = %v, want Extracted", tree.Status)
	}
	if tree.EntriesCount != 2 {
		t.Errorf("EntriesCount = %d, want 2", tree.EntriesCount)
	}
	if tree.Tool != "archive/tar" {
		t.Errorf("Tool = %q, want archive/tar", tree.Tool)
	}
	CleanupNode(tree)
}

func TestExtractPlainTARExecutableFileDoesNotTripSpecialFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	tarPath := filepath.Join(dir, "delivery.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}

	tw := tar.NewWriter(f)
	if writeHeaderErr := tw.WriteHeader(&tar.Header{
		Name: "0052_37.0-Patch2/01_start.sh",
		Mode: 0o755,
		Size: int64(len("#!/bin/sh\necho ok\n")),
	}); writeHeaderErr != nil {
		t.Fatal(writeHeaderErr)
	}
	if _, writeErr := tw.Write([]byte("#!/bin/sh\necho ok\n")); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := tw.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = tarPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), tarPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Status != StatusExtracted {
		t.Fatalf("status = %v, want Extracted (detail=%q)", tree.Status, tree.StatusDetail)
	}
	CleanupNode(tree)
}

func TestExtractBzip2TARInvalidDataFailsGracefully(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	fakeBzip2 := append([]byte{'B', 'Z', 'h', '9'}, make([]byte, 64)...)
	fakePath := filepath.Join(dir, "fake.tar.bz2")
	if err := os.WriteFile(fakePath, fakeBzip2, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = fakePath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, _ := Extract(context.Background(), fakePath, cfg, sb)
	if tree == nil {
		t.Fatal("tree must not be nil even for invalid bzip2 input")
	}
	if tree.Status == StatusExtracted {
		t.Errorf("status = Extracted for invalid bzip2 data, want Failed or Skipped")
	}
	CleanupNode(tree)
}

func TestTarHeaderFileModeBounds(t *testing.T) {
	t.Parallel()

	if got := tarHeaderFileMode(-1); got != 0 {
		t.Fatalf("tarHeaderFileMode(-1) = %v, want 0", got)
	}

	if got := tarHeaderFileMode(0o755); got != os.FileMode(0o755) {
		t.Fatalf("tarHeaderFileMode(0755) = %v, want %v", got, os.FileMode(0o755))
	}
}
