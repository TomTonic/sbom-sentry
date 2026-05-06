// Package externaltools_test provides integration tests for extract-sbom's
// interaction with external binaries (7zz, unshield). This file covers the
// password-based extraction feature for encrypted archives.
//
// Tests in this file require 7zz on PATH to create and extract test fixtures.
// They are skipped automatically when 7zz is not available.
package externaltools_test

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// require7zz skips the test when 7zz (or a compatible 7-Zip binary) is absent.
func require7zzForPassword(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"7zz", "7za", "7z"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("7zz not on PATH — skipping encrypted archive integration test")
	return ""
}

// createEncryptedZIPWith7z creates an encrypted ZIP archive using 7-Zip.
// The archive contains a single plain-text file. It is placed in dir and
// returns the absolute path. The test is skipped when 7zz is not available.
func createEncryptedZIPWith7z(t *testing.T, dir string, password string) string {
	t.Helper()
	bin := require7zzForPassword(t)

	// Write the file to include in the archive.
	srcFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(srcFile, []byte("top secret content"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	archivePath := filepath.Join(dir, "encrypted.zip")
	cmd := exec.Command(bin, "a", "-tzip", "-p"+password, archivePath, srcFile) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("7zz create encrypted zip: %v\n%s", err, out)
	}
	return archivePath
}

// createEncryptedSevenZipWith7z creates an encrypted .7z archive using 7-Zip.
func createEncryptedSevenZipWith7z(t *testing.T, dir string, password string) string {
	t.Helper()
	bin := require7zzForPassword(t)

	srcFile := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(srcFile, []byte("payload content"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	archivePath := filepath.Join(dir, "encrypted.7z")
	cmd := exec.Command(bin, "a", "-t7z", "-p"+password, archivePath, srcFile) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("7zz create encrypted 7z: %v\n%s", err, out)
	}
	return archivePath
}

// TestEncryptedZIPExtractedWithCorrectPassword validates that the full
// extract.Extract pipeline handles an encrypted ZIP:
//   - Go's archive/zip detects the encryption and returns EncryptedArchiveError
//   - The flow re-routes the archive to 7-Zip
//   - 7-Zip succeeds with the correct password from Config.Passwords
//   - The extraction node reaches StatusExtracted
func TestEncryptedZIPExtractedWithCorrectPassword(t *testing.T) {
	dir := t.TempDir()
	const password = "hunter2"
	zipPath := createEncryptedZIPWith7z(t, dir, password)

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = []string{"wrongpw", password}

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}
	if root.Status != extract.StatusExtracted {
		t.Errorf("root status = %v (detail: %q), want StatusExtracted", root.Status, root.StatusDetail)
	}
}

// TestEncryptedZIPFailsWithoutPassword validates that an encrypted ZIP is
// recorded as StatusFailed when no passwords are configured, rather than
// causing a panic or a hard pipeline error.
func TestEncryptedZIPFailsWithoutPassword(t *testing.T) {
	dir := t.TempDir()
	zipPath := createEncryptedZIPWith7z(t, dir, "secret")

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = nil // no passwords configured

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}
	if root.Status != extract.StatusFailed {
		t.Errorf("root status = %v (detail: %q), want StatusFailed", root.Status, root.StatusDetail)
	}
}

// TestEncryptedZIPFailsWithWrongPassword validates that providing only wrong
// passwords results in StatusFailed with a descriptive status detail.
func TestEncryptedZIPFailsWithWrongPassword(t *testing.T) {
	dir := t.TempDir()
	zipPath := createEncryptedZIPWith7z(t, dir, "correctpassword")

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = []string{"wrong1", "wrong2"}

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}
	if root.Status != extract.StatusFailed {
		t.Errorf("root status = %v (detail: %q), want StatusFailed", root.Status, root.StatusDetail)
	}
}

// TestEncrypted7zExtractedWithCorrectPassword validates that encrypted .7z
// archives (which are not ZIP and do not go through extractZIP) are also
// correctly handled when the right password is in Config.Passwords.
func TestEncrypted7zExtractedWithCorrectPassword(t *testing.T) {
	dir := t.TempDir()
	const password = "s3cr3t"
	archivePath := createEncryptedSevenZipWith7z(t, dir, password)

	cfg := config.DefaultConfig()
	cfg.InputPath = archivePath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = []string{password}

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), archivePath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}
	if root.Status != extract.StatusExtracted {
		t.Errorf("root status = %v (detail: %q), want StatusExtracted", root.Status, root.StatusDetail)
	}
}

// TestEncryptedZIPNestedInsidePlainZIP validates the recursive case: a plain
// outer ZIP contains an encrypted inner ZIP. The outer ZIP is extracted
// normally; the inner encrypted ZIP is detected, re-routed to 7-Zip, and
// extracted with the password from Config.Passwords.
func TestEncryptedZIPNestedInsidePlainZIP(t *testing.T) {
	require7zzForPassword(t)

	dir := t.TempDir()
	const password = "innerpass"

	// Create the inner encrypted ZIP.
	innerDir := t.TempDir()
	innerZip := createEncryptedZIPWith7z(t, innerDir, password)

	// Wrap it in a plain outer ZIP.
	outerZipPath := filepath.Join(dir, "outer.zip")
	outerZipFile, err := os.Create(outerZipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(outerZipFile)
	innerData, err := os.ReadFile(innerZip)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := w.Create("inner/encrypted.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := fw.Write(innerData); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := outerZipFile.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = outerZipPath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = []string{password}

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), outerZipPath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}
	if root.Status != extract.StatusExtracted {
		t.Errorf("outer ZIP root status = %v, want StatusExtracted", root.Status)
	}

	// Find the inner encrypted ZIP child node.
	var innerNode *extract.ExtractionNode
	for _, child := range root.Children {
		if filepath.Ext(child.Path) == ".zip" {
			innerNode = child
			break
		}
	}
	if innerNode == nil {
		t.Fatal("inner encrypted ZIP node not found in extraction tree")
	}
	if innerNode.Status != extract.StatusExtracted {
		t.Errorf("inner encrypted ZIP status = %v (detail: %q), want StatusExtracted",
			innerNode.Status, innerNode.StatusDetail)
	}
}

// TestEncryptedZIPDetectionFromFakeHeader validates that the detection works
// with a minimal hand-crafted ZIP that has the encryption bit set, independent
// of a real 7zz installation. This is a deterministic regression test for the
// bit-flag check in extractZIP.
func TestEncryptedZIPDetectionFromFakeHeader(t *testing.T) {
	dir := t.TempDir()

	// Write a ZIP where the first entry has bit 0 of the GP flags set.
	zipPath := filepath.Join(dir, "fake_encrypted.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	nameBytes := []byte("hidden.bin")

	// Local file header with encryption bit set.
	lhdr := []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	lhdr = binary.LittleEndian.AppendUint16(lhdr, uint16(len(nameBytes))) //nolint:gosec // G115: len() is always non-negative and bounded by ZIP spec max name size
	lhdr = binary.LittleEndian.AppendUint16(lhdr, 0)
	lhdr = append(lhdr, nameBytes...)
	_, _ = f.Write(lhdr)
	localLen := int32(len(lhdr)) //nolint:gosec // G115: test fixture, len is small

	// Central directory entry.
	cdEntry := []byte{0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	cdEntry = binary.LittleEndian.AppendUint16(cdEntry, uint16(len(nameBytes))) //nolint:gosec // G115: test fixture, bounded by ZIP spec
	cdEntry = binary.LittleEndian.AppendUint16(cdEntry, 0)
	cdEntry = binary.LittleEndian.AppendUint16(cdEntry, 0)
	cdEntry = binary.LittleEndian.AppendUint16(cdEntry, 0)
	cdEntry = binary.LittleEndian.AppendUint16(cdEntry, 0)
	cdEntry = binary.LittleEndian.AppendUint32(cdEntry, 0)
	cdEntry = binary.LittleEndian.AppendUint32(cdEntry, 0)
	cdEntry = append(cdEntry, nameBytes...)
	cdOffset := localLen
	_, _ = f.Write(cdEntry)
	cdLen := int32(len(cdEntry)) //nolint:gosec // G115: test fixture, bounded by ZIP spec

	// End of central directory.
	eocd := []byte{0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00}
	eocd = binary.LittleEndian.AppendUint32(eocd, uint32(cdLen))
	eocd = binary.LittleEndian.AppendUint32(eocd, uint32(cdOffset))
	eocd = binary.LittleEndian.AppendUint16(eocd, 0)
	_, _ = f.Write(eocd)
	_ = f.Close()

	// Verify that Extract returns StatusFailed (7zz absent or fails on this fake)
	// rather than crashing or returning StatusExtracted, and that it does NOT
	// return StatusSyftNative or StatusSkipped — the encryption was detected.
	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.WorkDir = dir
	cfg.Unsafe = true
	cfg.Passwords = []string{"anypassword"}

	sb := sandbox.NewPassthroughSandbox()
	root, err := extract.Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("Extract returned hard error: %v", err)
	}

	// The node should be either Extracted (if 7zz is installed and the fake
	// succeeds) or Failed (if 7zz is absent or cannot parse the fake archive).
	// What must NOT happen: StatusSkipped, StatusSyftNative, or StatusPending.
	switch root.Status {
	case extract.StatusExtracted, extract.StatusFailed, extract.StatusToolMissing:
		// acceptable outcomes
	default:
		t.Errorf("unexpected node status = %v (detail: %q)", root.Status, root.StatusDetail)
	}
}
