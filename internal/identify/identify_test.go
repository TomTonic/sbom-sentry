package identify

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestIdentifyZip verifies that a standard ZIP delivery container is detected
// and marked extractable for recursive processing.
func TestIdentifyZip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := createZip(path); err != nil {
		t.Fatalf("create zip fixture: %v", err)
	}

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("identify failed: %v", err)
	}
	if info.Format != FormatZIP {
		t.Fatalf("expected ZIP, got %s", info.Format)
	}
	if !info.Extractable {
		t.Fatal("expected ZIP to be extractable")
	}
}

// TestIdentifySyftNativeJar verifies JAR-like artifacts remain Syft-native and
// are not forced through sbom-sentry extraction logic.
func TestIdentifySyftNativeJar(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "component.jar")
	if err := createZip(path); err != nil {
		t.Fatalf("create jar fixture: %v", err)
	}

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("identify failed: %v", err)
	}
	if !info.SyftNative {
		t.Fatal("expected .jar extension to be syft-native")
	}
}

// TestIdentifyGzipTar verifies compressed TAR containers are recognized for
// extraction using stdlib archive/tar plus gzip decompression.
func TestIdentifyGzipTar(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "payload.tar.gz")
	if err := createGzipTar(path); err != nil {
		t.Fatalf("create tar.gz fixture: %v", err)
	}

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("identify failed: %v", err)
	}
	if info.Format != FormatGzipTAR {
		t.Fatalf("expected GzipTAR, got %s", info.Format)
	}
}

func createZip(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create("file.txt")
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		return err
	}
	return zw.Close()
}

func createGzipTar(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("hello-tar")
	hdr := &tar.Header{Name: "app.bin", Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := bytes.NewBuffer(body).WriteTo(tw); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
