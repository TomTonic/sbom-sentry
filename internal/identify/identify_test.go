// Identify module tests: Validate that format detection correctly classifies
// archive files by magic bytes and extension. This belongs to the format
// identification subsystem which determines how each file in a delivery is
// processed.
package identify

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// createTestFile creates a temporary file with the given content and extension.
func createTestFile(t *testing.T, dir string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestIdentifyDetectsZIPByMagicBytes verifies that a standard ZIP file
// is correctly identified. ZIP is the most common delivery format and
// the primary extraction path.
func TestIdentifyDetectsZIPByMagicBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Valid ZIP header: PK\x03\x04 + padding.
	content := make([]byte, 300)
	content[0] = 'P'
	content[1] = 'K'
	content[2] = 0x03
	content[3] = 0x04

	path := createTestFile(t, dir, "test.zip", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != ZIP {
		t.Errorf("Format = %v, want ZIP", info.Format)
	}
	if !info.Extractable {
		t.Error("Extractable = false, want true")
	}
	if info.SyftNative {
		t.Error("SyftNative = true, want false for plain ZIP")
	}
}

// TestIdentifyRecognizesJARAsZIPButSyftNative verifies that JAR files
// (which are ZIPs with .jar extension) are detected as ZIP format but
// marked as Syft-native. This ensures the Syft-first principle: JARs
// are passed directly to Syft for richer Java metadata extraction.
func TestIdentifyRecognizesJARAsZIPButSyftNative(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	content[0] = 'P'
	content[1] = 'K'
	content[2] = 0x03
	content[3] = 0x04

	for _, ext := range []string{".jar", ".war", ".ear", ".nupkg", ".whl"} {
		t.Run(ext, func(t *testing.T) {
			t.Parallel()
			path := createTestFile(t, dir, "test"+ext, content)
			info, err := Identify(context.Background(), path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Format != ZIP {
				t.Errorf("Format = %v, want ZIP", info.Format)
			}
			if !info.SyftNative {
				t.Errorf("SyftNative = false, want true for %s", ext)
			}
		})
	}
}

// TestIdentifyDetectsTARByUstarMagic verifies that plain TAR archives
// are detected by the "ustar" magic at offset 257. TAR is a common
// delivery format on Linux.
func TestIdentifyDetectsTARByUstarMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content[257:], "ustar")

	path := createTestFile(t, dir, "test.tar", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != TAR {
		t.Errorf("Format = %v, want TAR", info.Format)
	}
	if !info.Extractable {
		t.Error("Extractable = false, want true")
	}
}

// TestIdentifyDetectsGzipTARByMagicAndExtension verifies that gzip-
// compressed TAR files are detected by the gzip magic bytes (1F 8B)
// combined with a .tar.gz or .tgz extension.
func TestIdentifyDetectsGzipTARByMagicAndExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	content[0] = 0x1F
	content[1] = 0x8B

	for _, name := range []string{"test.tar.gz", "test.tgz"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := createTestFile(t, dir, name, content)
			info, err := Identify(context.Background(), path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Format != GzipTAR {
				t.Errorf("Format = %v, want GzipTAR", info.Format)
			}
		})
	}
}

// TestIdentifyDetectsBzip2TARByMagicAndExtension verifies detection of
// bzip2-compressed TAR archives by BZh magic bytes and .tar.bz2 extension.
func TestIdentifyDetectsBzip2TARByMagicAndExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	content[0] = 'B'
	content[1] = 'Z'
	content[2] = 'h'

	path := createTestFile(t, dir, "test.tar.bz2", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != Bzip2TAR {
		t.Errorf("Format = %v, want Bzip2TAR", info.Format)
	}
}

// TestIdentifyDetectsCABByMSCFMagic verifies that Microsoft Cabinet files
// are detected by the "MSCF" magic bytes at offset 0. CAB files are the
// primary Windows-native container format in vendor deliveries.
func TestIdentifyDetectsCABByMSCFMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	content[0] = 'M'
	content[1] = 'S'
	content[2] = 'C'
	content[3] = 'F'

	path := createTestFile(t, dir, "test.cab", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != CAB {
		t.Errorf("Format = %v, want CAB", info.Format)
	}
}

// TestIdentifyDetectsMSIByOLEMagic verifies that MSI installer files
// are detected by the OLE compound document magic bytes. MSI packages
// carry product metadata that enriches the SBOM with CPE information.
func TestIdentifyDetectsMSIByOLEMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})

	path := createTestFile(t, dir, "test.msi", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != MSI {
		t.Errorf("Format = %v, want MSI", info.Format)
	}
}

// TestIdentifyDetects7zByMagicBytes verifies that 7z archive files
// are detected by their distinctive magic byte sequence.
func TestIdentifyDetects7zByMagicBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})

	path := createTestFile(t, dir, "test.7z", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != SevenZip {
		t.Errorf("Format = %v, want 7z", info.Format)
	}
}

// TestIdentifyDetectsRARByMagicBytes verifies that RAR archive files
// are detected by the "Rar!" magic byte sequence.
func TestIdentifyDetectsRARByMagicBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{'R', 'a', 'r', '!', 0x1A, 0x07})

	path := createTestFile(t, dir, "test.rar", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != RAR {
		t.Errorf("Format = %v, want RAR", info.Format)
	}
}

// TestIdentifyDetectsInstallShieldCABByMagic verifies that InstallShield
// proprietary cabinet files are detected by the "ISc(" magic bytes.
// These require the unshield tool for extraction.
func TestIdentifyDetectsInstallShieldCABByMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte{'I', 'S', 'c', '('})

	path := createTestFile(t, dir, "data1.cab", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != InstallShieldCAB {
		t.Errorf("Format = %v, want InstallShieldCAB", info.Format)
	}
}

// TestIdentifyTreatsInstallShieldHdrAsUnknown verifies that InstallShield
// header files (data*.hdr) are not misidentified as extractable containers.
// The .hdr file is a companion to the .cab file and cannot be extracted
// independently.
func TestIdentifyTreatsInstallShieldHdrAsUnknown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte("HDR header content"))

	path := createTestFile(t, dir, "data1.hdr", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != Unknown {
		t.Errorf("Format = %v, want Unknown for .hdr companion file", info.Format)
	}
	if info.Extractable {
		t.Error("Extractable = true, want false for .hdr companion file")
	}
}

// TestIdentifyReturnsUnknownForUnrecognizedFormat verifies that files
// with no recognizable magic bytes are reported as Unknown rather than
// causing an error. Unknown files are treated as plain leaves.
func TestIdentifyReturnsUnknownForUnrecognizedFormat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	content := make([]byte, 300)
	copy(content, []byte("This is just a plain text file"))

	path := createTestFile(t, dir, "readme.txt", content)

	info, err := Identify(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != Unknown {
		t.Errorf("Format = %v, want Unknown", info.Format)
	}
}

// TestIdentifySyftNativeByExtensionForNonZIPFormats verifies that files
// with syft-native extensions (RPM, DEB, APK) are correctly identified
// even though their magic bytes don't match any archive format check.
// These formats are handled directly by Syft and should not be extracted.
func TestIdentifySyftNativeByExtensionForNonZIPFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		magic   []byte
		wantExt bool
	}{
		{"server.rpm", []byte{0xED, 0xAB, 0xEE, 0xDB}, true}, // RPM magic
		{"libssl.deb", []byte("!<arch>\n"), true},            // DEB/ar magic
		{"alpine.apk", []byte{0x1F, 0x8B, 0x08}, true},       // APK is gzip
		{"readme.txt", []byte("plain text content"), false},  // not syft-native
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()

			content := make([]byte, 300)
			copy(content, tt.magic)
			path := createTestFile(t, dir, tt.name, content)

			info, err := Identify(context.Background(), path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantExt && !info.SyftNative {
				t.Errorf("%s: SyftNative = false, want true", tt.name)
			}
			if tt.wantExt && info.Extractable {
				t.Errorf("%s: Extractable = true, want false for syft-native", tt.name)
			}
			if !tt.wantExt && info.SyftNative {
				t.Errorf("%s: SyftNative = true, want false", tt.name)
			}
		})
	}
}

// TestIdentifyReturnsErrorForNonexistentFile verifies that Identify
// returns a clear error when the file does not exist, rather than
// proceeding with garbage data.
func TestIdentifyReturnsErrorForNonexistentFile(t *testing.T) {
	t.Parallel()
	_, err := Identify(context.Background(), "/nonexistent/path/file.zip")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestFormatStringReturnsReadableNames verifies that all Format constants
// have human-readable String() representations for use in audit reports.
func TestFormatStringReturnsReadableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format Format
		want   string
	}{
		{ZIP, "ZIP"},
		{TAR, "TAR"},
		{GzipTAR, "GzipTAR"},
		{Bzip2TAR, "Bzip2TAR"},
		{XzTAR, "XzTAR"},
		{ZstdTAR, "ZstdTAR"},
		{CAB, "CAB"},
		{MSI, "MSI"},
		{SevenZip, "7z"},
		{RAR, "RAR"},
		{InstallShieldCAB, "InstallShieldCAB"},
		{Unknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.format.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

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
