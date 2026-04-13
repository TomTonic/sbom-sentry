package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var lookPathMu sync.Mutex

type sandboxCall struct {
	cmd       string
	args      []string
	inputPath string
	outputDir string
}

type recordingSandbox struct {
	name  string
	calls []sandboxCall
	run   func(cmd string, args []string, inputPath string, outputDir string) error
}

func (s *recordingSandbox) Run(_ context.Context, cmd string, args []string, inputPath string, outputDir string) error {
	s.calls = append(s.calls, sandboxCall{
		cmd:       cmd,
		args:      append([]string(nil), args...),
		inputPath: inputPath,
		outputDir: outputDir,
	})
	if s.run != nil {
		return s.run(cmd, args, inputPath, outputDir)
	}
	return nil
}

func (s *recordingSandbox) Available() bool {
	return true
}

func (s *recordingSandbox) Name() string {
	if s.name == "" {
		return "recording"
	}
	return s.name
}

// createTestZIP creates a minimal ZIP file with the given entries.
func createTestZIP(t *testing.T, dir string, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	for entryName, content := range entries {
		fw, err := w.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// createTestTARGZ creates a minimal gzip-compressed TAR file.
func createTestTARGZ(t *testing.T, dir string, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for entryName, content := range entries {
		hdr := &tar.Header{
			Name: entryName,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

// createTestTAR creates a plain uncompressed TAR file with the given entries.
func createTestTAR(t *testing.T, dir string, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	for entryName, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: entryName,
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
