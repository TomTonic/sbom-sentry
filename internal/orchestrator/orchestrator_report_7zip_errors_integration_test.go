package orchestrator

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
)

type extractionProcessingRow struct {
	Class         string
	Status        string
	Detected      string
	Tool          string
	ArchiveType   string
	ArchiveMethod string
	Encrypted     string
	PhysicalSize  string
	Detail        string
}

func TestReportProcessingErrorsClassToolMissing(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "missing-tool.cab")
	if err := os.WriteFile(inputPath, []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}

	report := runHumanReportForInput(t, inputPath, func(cfg *config.Config) {
		cfg.Unsafe = true
		t.Setenv("PATH", "")
	})

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "tool-missing" {
		t.Fatalf("class = %q, want %q", row.Class, "tool-missing")
	}
}

func TestReportProcessingErrorsClassSecurityBlocked(t *testing.T) {
	dir := t.TempDir()
	inputPath := createTarWithSymlink(t, dir, "symlink.tar")

	report := runHumanReportForInput(t, inputPath, nil)

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "security-blocked" {
		t.Fatalf("class = %q, want %q", row.Class, "security-blocked")
	}
	if !strings.Contains(strings.ToLower(row.Detail), "hard security violation") {
		t.Fatalf("detail = %q, want hard security violation context", row.Detail)
	}
}

func TestReportProcessingErrorsClassTimeout(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "timeout.cab")
	if err := os.WriteFile(inputPath, []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExecutableScript(t, filepath.Join(binDir, "7zz"), "#!/bin/sh\necho per-extraction timeout (1s) exceeded 1>&2\nexit 42\n")

	report := runHumanReportForInput(t, inputPath, func(_ *config.Config) {
		t.Setenv("PATH", binDir)
	})

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "timeout" {
		t.Fatalf("class = %q, want %q", row.Class, "timeout")
	}
	if !strings.Contains(strings.ToLower(row.Detail), "timeout") {
		t.Fatalf("detail = %q, want timeout marker", row.Detail)
	}
}

func TestReportProcessingErrorsClassFormatMismatchOrInvalidArchive(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "invalid.cab")
	if err := os.WriteFile(inputPath, []byte("MSCF\x00\x00\x00\x00garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	report := runHumanReportForInput(t, inputPath, nil)

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "format-mismatch-or-invalid-archive" {
		t.Fatalf("class = %q, want %q (detail=%q)", row.Class, "format-mismatch-or-invalid-archive", row.Detail)
	}
	lower := strings.ToLower(row.Detail)
	if !strings.Contains(lower, "archive") {
		t.Fatalf("detail = %q, want archive mismatch marker", row.Detail)
	}
}

func TestReportProcessingErrorsClassArchiveCorruptOrTruncated(t *testing.T) {
	dir := t.TempDir()
	inputPath := createTruncatedZIP(t, dir, "truncated.zip")

	report := runHumanReportForInput(t, inputPath, nil)

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "archive-corrupt-or-truncated" {
		t.Fatalf("class = %q, want %q (detail=%q)", row.Class, "archive-corrupt-or-truncated", row.Detail)
	}
}

func TestReportProcessingErrorsClassExtractionFailed(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "crash.cab")
	if err := os.WriteFile(inputPath, []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExecutableScript(t, filepath.Join(binDir, "7zz"), "#!/bin/sh\necho intentional crash 1>&2\nexit 42\n")

	report := runHumanReportForInput(t, inputPath, func(_ *config.Config) {
		t.Setenv("PATH", binDir)
	})

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "extraction-failed" {
		t.Fatalf("class = %q, want %q", row.Class, "extraction-failed")
	}
	if !strings.Contains(strings.ToLower(row.Detail), "intentional crash") {
		t.Fatalf("detail = %q, want crash marker", row.Detail)
	}
}

func TestReportProcessingErrorsAdditionalBytes(t *testing.T) {
	dir := t.TempDir()
	inputPath := createZIPWithTrailingBytes(t, dir, "additional-bytes.zip")

	report := runHumanReportForInput(t, inputPath, nil)

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if ok {
		if row.Class != "extraction-failed" && row.Class != "archive-corrupt-or-truncated" {
			t.Fatalf("class = %q, want extraction-failed or archive-corrupt-or-truncated", row.Class)
		}
		if !strings.Contains(strings.ToLower(row.Detail), "archive") {
			t.Fatalf("detail = %q, want archive error/warning marker", row.Detail)
		}
		return
	}

	wantExtractionLog := fmt.Sprintf("- **%s** [ZIP] Status=extracted", filepath.Base(inputPath))
	if !strings.Contains(report, wantExtractionLog) {
		t.Fatalf("expected either extraction processing row or extracted log line %q; report:\n%s", wantExtractionLog, report)
	}
}

func TestReportProcessingErrorsCRCMutation(t *testing.T) {
	dir := t.TempDir()
	inputPath := createCRCMutatedZIP(t, dir, "crc-mutated.zip")

	report := runHumanReportForInput(t, inputPath, nil)

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if !strings.Contains(strings.ToLower(row.Detail), "crc") && !strings.Contains(strings.ToLower(row.Detail), "data error") {
		t.Fatalf("detail = %q, want crc/data error marker", row.Detail)
	}
}

func TestReportProcessingErrorsNoMatchingPassword(t *testing.T) {
	if _, err := exec.LookPath("7zz"); err != nil {
		t.Skip("7zz not found in PATH")
	}

	dir := t.TempDir()
	inputPath := createPasswordProtectedZIP(t, dir, "encrypted.zip", "correct-secret")

	report := runHumanReportForInput(t, inputPath, func(cfg *config.Config) {
		cfg.Passwords = []string{"wrong-1", "wrong-2"}
	})

	row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath))
	if !ok {
		t.Fatalf("processing row for %q not found; report:\n%s", filepath.Base(inputPath), report)
	}
	if row.Class != "password-required" {
		t.Fatalf("class = %q, want %q", row.Class, "password-required")
	}
	if !strings.Contains(strings.ToLower(row.Detail), "no matching password") {
		t.Fatalf("detail = %q, want no-matching-password marker", row.Detail)
	}
}

func TestReportExtensionMismatchShowsDetectedFormat(t *testing.T) {
	dir := t.TempDir()
	inputPath := createTarWithOneFile(t, dir, "looks-like-zip.zip")

	report := runHumanReportForInput(t, inputPath, nil)

	if row, ok := findExtractionProcessingRow(report, filepath.Base(inputPath)); ok {
		t.Fatalf("unexpected processing error row for extension mismatch case: %+v", row)
	}

	want := fmt.Sprintf("- **%s** [TAR] Status=extracted", filepath.Base(inputPath))
	if !strings.Contains(report, want) {
		t.Fatalf("report missing extracted TAR marker for mismatched extension: %q", want)
	}
}

func runHumanReportForInput(t *testing.T, inputPath string, tweak func(*config.Config)) string {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = filepath.Dir(inputPath)
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportMarkdown
	cfg.PolicyMode = config.PolicyPartial
	if tweak != nil {
		tweak(&cfg)
	}

	result := Run(context.Background(), cfg)
	if result.ReportPath == "" {
		t.Fatalf("ReportPath is empty (exit=%d, err=%v)", result.ExitCode, result.Error)
	}
	raw, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read report: %v", err)
	}
	return string(raw)
}

func findExtractionProcessingRow(report string, location string) (extractionProcessingRow, bool) {
	prefix := "| extraction | " + location + " |"
	for _, line := range strings.Split(report, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 12 {
			continue
		}
		trim := func(i int) string { return strings.TrimSpace(parts[i]) }
		return extractionProcessingRow{
			Class:         trim(3),
			Status:        trim(4),
			Detected:      trim(5),
			Tool:          trim(6),
			ArchiveType:   trim(7),
			ArchiveMethod: trim(8),
			Encrypted:     trim(9),
			PhysicalSize:  trim(10),
			Detail:        trim(11),
		}, true
	}
	return extractionProcessingRow{}, false
}

func createTruncatedZIP(t *testing.T, dir string, name string) string {
	t.Helper()
	path := createMinimalZIP(t, dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 8 {
		t.Fatalf("zip too small: %d bytes", len(raw))
	}
	truncated := raw[:len(raw)/2]
	if err := os.WriteFile(path, truncated, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func createZIPWithTrailingBytes(t *testing.T, dir string, name string) string {
	t.Helper()
	path := createMinimalZIP(t, dir, name)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("TRAILING-BYTES")); err != nil {
		t.Fatal(err)
	}
	return path
}

func createCRCMutatedZIP(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)

	f, createErr := os.Create(path)
	if createErr != nil {
		t.Fatal(createErr)
	}
	w := zip.NewWriter(f)
	h := &zip.FileHeader{Name: "payload.bin", Method: zip.Deflate}
	entry, entryErr := w.CreateHeader(h)
	if entryErr != nil {
		t.Fatal(entryErr)
	}
	payload := bytes.Repeat([]byte("ABCDEFGH12345678"), 4096)
	if _, writeErr := entry.Write(payload); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.File) == 0 {
		t.Fatal("zip has no files")
	}
	off, err := r.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	if r.File[0].CompressedSize64 < 4 {
		t.Fatalf("compressed payload too small: %d", r.File[0].CompressedSize64)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if off < 0 {
		t.Fatalf("negative data offset: %d", off)
	}
	idx64 := uint64(off) + (r.File[0].CompressedSize64 / 2) //nolint:gosec // G115: off is checked non-negative and bounds are validated below.
	if idx64 >= uint64(len(raw)) {
		t.Fatalf("mutation index out of range: %d (len=%d)", idx64, len(raw))
	}
	idx := int(idx64) //nolint:gosec // G115: idx64 is validated to be < len(raw).
	raw[idx] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func createTarWithSymlink(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)

	content := []byte("safe")
	if err := tw.WriteHeader(&tar.Header{Name: "safe.txt", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func createTarWithOneFile(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	content := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{Name: "readme.txt", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func createPasswordProtectedZIP(t *testing.T, dir string, name string, password string) string {
	t.Helper()

	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("secret payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("7zz", "a", "-tzip", "-p"+password, "-mem=AES256", out, plain) //nolint:gosec // G204: integration test intentionally invokes trusted local 7zz binary.
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot create password-protected zip via 7zz: %v; output=%s", err, string(outBytes))
	}
	return out
}

func writeExecutableScript(t *testing.T, path string, content string) {
	t.Helper()
	//nolint:gosec // G306: test fixture must be executable.
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}
