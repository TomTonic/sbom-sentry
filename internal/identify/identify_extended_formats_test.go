// Additional identify tests for extended container formats.
//
// These checks validate detection paths that were added after the original
// baseline archive set (xz/zstd tar, cpio, squashfs, appimage, iso).
package identify

import (
	"context"
	"testing"
)

// TestIdentifyDetectsXzTARByMagicAndExtension verifies detection of
// xz-compressed TAR archives.
func TestIdentifyDetectsXzTARByMagicAndExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00})

	path := createTestFile(t, dir, "test.tar.xz", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != XzTAR {
		t.Errorf("Format = %v, want XzTAR", info.Format)
	}
}

// TestIdentifyDetectsZstdTARByMagicAndExtension verifies detection of
// zstandard-compressed TAR archives.
func TestIdentifyDetectsZstdTARByMagicAndExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{0x28, 0xB5, 0x2F, 0xFD})

	path := createTestFile(t, dir, "test.tar.zst", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != ZstdTAR {
		t.Errorf("Format = %v, want ZstdTAR", info.Format)
	}
}

// TestIdentifyDetectsCPIOByMagicNewc verifies that CPIO archives in newc
// format are detected by their ASCII magic "070701".
func TestIdentifyDetectsCPIOByMagicNewc(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := make([]byte, 20)
	copy(content, []byte("070701"))
	path := createTestFile(t, dir, "test.cpio", content)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != CPIO {
		t.Errorf("Format = %v, want CPIO", info.Format)
	}
	if !info.Extractable {
		t.Error("Extractable = false, want true")
	}
	if info.MIMEType != "application/x-cpio" {
		t.Errorf("MIMEType = %q, want application/x-cpio", info.MIMEType)
	}
}

// TestIdentifyDetectsCPIOByOldBinaryMagic verifies that CPIO archives in old
// binary format are detected by their binary magic bytes.
func TestIdentifyDetectsCPIOByOldBinaryMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	contentBE := make([]byte, 20)
	contentBE[0] = 0xC7
	contentBE[1] = 0x71
	path := createTestFile(t, dir, "test_be.cpio", contentBE)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != CPIO {
		t.Errorf("BE Format = %v, want CPIO", info.Format)
	}
	contentLE := make([]byte, 20)
	contentLE[0] = 0x71
	contentLE[1] = 0xC7
	path2 := createTestFile(t, dir, "test_le.cpio", contentLE)
	info2, err := Identify(context.Background(), path2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info2.Format != CPIO {
		t.Errorf("LE Format = %v, want CPIO", info2.Format)
	}
}

// TestIdentifyDetectsSquashfsByMagicLittleEndian verifies SquashFS detection
// by little-endian magic "hsqs".
func TestIdentifyDetectsSquashfsByMagicLittleEndian(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := make([]byte, 20)
	content[0] = 0x68
	content[1] = 0x73
	content[2] = 0x71
	content[3] = 0x73
	path := createTestFile(t, dir, "test.squashfs", content)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != Squashfs {
		t.Errorf("Format = %v, want Squashfs", info.Format)
	}
	if !info.Extractable {
		t.Error("Extractable = false, want true")
	}
	if info.MIMEType != "application/x-squashfs" {
		t.Errorf("MIMEType = %q, want application/x-squashfs", info.MIMEType)
	}
}

// TestIdentifyDetectsSquashfsBySnapExtension verifies .snap extension fallback.
func TestIdentifyDetectsSquashfsBySnapExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := make([]byte, 20)
	path := createTestFile(t, dir, "test.snap", content)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != Squashfs {
		t.Errorf("Format = %v, want Squashfs", info.Format)
	}
}

// TestIdentifyDetectsAppImageByELFAndMagic verifies AppImage detection.
func TestIdentifyDetectsAppImageByELFAndMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := make([]byte, 20)
	content[0] = 0x7F
	content[1] = 0x45
	content[2] = 0x4C
	content[3] = 0x46
	content[8] = 0x41
	content[9] = 0x49
	content[10] = 0x02
	path := createTestFile(t, dir, "test.AppImage", content)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != AppImage {
		t.Errorf("Format = %v, want AppImage", info.Format)
	}
	if info.Extractable {
		t.Error("Extractable = true, want false for AppImage")
	}
	if info.MIMEType != "application/x-appimage" {
		t.Errorf("MIMEType = %q, want application/x-appimage", info.MIMEType)
	}
}

// TestIdentifyDetectsISOByExtension verifies .iso extension-based detection.
func TestIdentifyDetectsISOByExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := make([]byte, 20)
	path := createTestFile(t, dir, "test.iso", content)
	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != ISO {
		t.Errorf("Format = %v, want ISO", info.Format)
	}
	if !info.Extractable {
		t.Error("Extractable = false, want true")
	}
	if info.MIMEType != "application/x-iso9660-image" {
		t.Errorf("MIMEType = %q, want application/x-iso9660-image", info.MIMEType)
	}
}
