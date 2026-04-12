// Package identify detects the format of a file and determines whether Syft
// can handle it natively or whether extract-sbom needs to extract it.
// Detection uses file-magic bytes and file extension, never attempting
// extraction. All I/O is read-only and bounded.
package identify

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Format represents a recognized archive or container format.
type Format int

const (
	// Unknown indicates the format could not be determined.
	Unknown Format = iota
	// ZIP represents a ZIP archive.
	ZIP
	// TAR represents an uncompressed TAR archive.
	TAR
	// GzipTAR represents a gzip-compressed TAR archive (.tar.gz, .tgz).
	GzipTAR
	// Bzip2TAR represents a bzip2-compressed TAR archive (.tar.bz2).
	Bzip2TAR
	// XzTAR represents an xz-compressed TAR archive (.tar.xz).
	XzTAR
	// ZstdTAR represents a zstandard-compressed TAR archive (.tar.zst).
	ZstdTAR
	// CAB represents a Microsoft Cabinet archive.
	CAB
	// MSI represents a Microsoft Installer (OLE compound document) package.
	MSI
	// SevenZip represents a 7z archive.
	SevenZip
	// RAR represents a RAR archive.
	RAR
	// InstallShieldCAB represents a proprietary InstallShield cabinet file.
	InstallShieldCAB
)

// String returns the human-readable name of the format.
func (f Format) String() string {
	switch f {
	case ZIP:
		return "ZIP"
	case TAR:
		return "TAR"
	case GzipTAR:
		return "GzipTAR"
	case Bzip2TAR:
		return "Bzip2TAR"
	case XzTAR:
		return "XzTAR"
	case ZstdTAR:
		return "ZstdTAR"
	case CAB:
		return "CAB"
	case MSI:
		return "MSI"
	case SevenZip:
		return "7z"
	case RAR:
		return "RAR"
	case InstallShieldCAB:
		return "InstallShieldCAB"
	default:
		return "Unknown"
	}
}

// FormatInfo holds the detection result for a file, including whether Syft
// handles it natively and whether extract-sbom can extract it.
type FormatInfo struct {
	Format      Format
	MIMEType    string
	Extension   string
	SyftNative  bool // true if Syft already understands this format
	Extractable bool // true if extract-sbom can extract it
}

// syftNativeExtensions lists file extensions for formats that Syft handles
// natively via its dedicated catalogers. These are never extracted by
// extract-sbom and instead passed directly to Syft for richer metadata.
var syftNativeExtensions = map[string]bool{
	".jar":   true,
	".war":   true,
	".ear":   true,
	".jpi":   true,
	".hpi":   true,
	".whl":   true,
	".egg":   true,
	".rpm":   true,
	".deb":   true,
	".apk":   true,
	".nupkg": true,
	".gem":   true,
	".crate": true,
}

// Identify detects the format of the file at the given path.
// It reads only the first bytes of the file for magic-byte detection, then
// checks file extension for further format refinement. It never performs
// extraction and is safe to call on untrusted input.
//
// Parameters:
//   - ctx: context for cancellation
//   - path: filesystem path to the file to identify
//
// Returns a FormatInfo describing the detected format, or an error if the
// file cannot be read. An Unknown format is not an error — it means the file
// type is not recognized.
func Identify(_ context.Context, path string) (FormatInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return FormatInfo{}, fmt.Errorf("identify: open %s: %w", path, err)
	}
	defer f.Close()

	// Read first 262 bytes (enough for all magic byte checks).
	header := make([]byte, 262)
	n, err := io.ReadAtLeast(f, header, 8)
	if err != nil && err != io.ErrUnexpectedEOF {
		return FormatInfo{}, fmt.Errorf("identify: read header %s: %w", path, err)
	}
	header = header[:n]

	ext := strings.ToLower(filepath.Ext(path))
	// Handle double extensions like .tar.gz
	base := strings.ToLower(filepath.Base(path))

	return identifyFromHeader(header, ext, base), nil
}

// identifyFromHeader determines the format from magic bytes and extension.
func identifyFromHeader(header []byte, ext string, baseName string) FormatInfo {
	info := FormatInfo{
		Format:    Unknown,
		Extension: ext,
	}

	if len(header) < 4 {
		return info
	}

	// Check for Syft-native ZIP-based formats first.
	if header[0] == 'P' && header[1] == 'K' && header[2] == 0x03 && header[3] == 0x04 {
		if syftNativeExtensions[ext] {
			info.Format = ZIP
			info.MIMEType = "application/zip"
			info.SyftNative = true
			info.Extractable = false
			return info
		}
		info.Format = ZIP
		info.MIMEType = "application/zip"
		info.Extractable = true
		return info
	}

	// InstallShield CAB: "ISc(" at offset 0
	if len(header) >= 4 && header[0] == 'I' && header[1] == 'S' && header[2] == 'c' && header[3] == '(' {
		info.Format = InstallShieldCAB
		info.MIMEType = "application/x-installshield-cab"
		info.Extractable = true // when unshield is available
		return info
	}

	// Microsoft CAB: "MSCF" at offset 0
	if header[0] == 'M' && header[1] == 'S' && header[2] == 'C' && header[3] == 'F' {
		info.Format = CAB
		info.MIMEType = "application/vnd.ms-cab-compressed"
		info.Extractable = true // when 7zz is available
		return info
	}

	// MSI/OLE: D0 CF 11 E0 A1 B1 1A E1 at offset 0
	if len(header) >= 8 &&
		header[0] == 0xD0 && header[1] == 0xCF && header[2] == 0x11 && header[3] == 0xE0 &&
		header[4] == 0xA1 && header[5] == 0xB1 && header[6] == 0x1A && header[7] == 0xE1 {
		info.Format = MSI
		info.MIMEType = "application/x-msi"
		info.Extractable = true // when 7zz is available
		return info
	}

	// 7z: 7z BC AF 27 1C at offset 0
	if len(header) >= 6 &&
		header[0] == '7' && header[1] == 'z' &&
		header[2] == 0xBC && header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C {
		info.Format = SevenZip
		info.MIMEType = "application/x-7z-compressed"
		info.Extractable = true // when 7zz is available
		return info
	}

	// RAR: "Rar!\x1A\x07" at offset 0
	if len(header) >= 6 &&
		header[0] == 'R' && header[1] == 'a' && header[2] == 'r' && header[3] == '!' &&
		header[4] == 0x1A && header[5] == 0x07 {
		info.Format = RAR
		info.MIMEType = "application/x-rar-compressed"
		info.Extractable = true // when 7zz is available
		return info
	}

	// Compressed TAR variants — check compression magic, then verify TAR is plausible.
	// Gzip: 1F 8B
	if len(header) >= 2 && header[0] == 0x1F && header[1] == 0x8B {
		if isTarExtension(baseName) {
			info.Format = GzipTAR
			info.MIMEType = "application/gzip"
			info.Extractable = true
			return info
		}
		// Gzip but not a tar — could still be a tar.gz with odd naming.
		// Fall through to extension-based check below.
	}

	// Bzip2: "BZ" at offset 0
	if len(header) >= 3 && header[0] == 'B' && header[1] == 'Z' && header[2] == 'h' {
		if isTarExtension(baseName) {
			info.Format = Bzip2TAR
			info.MIMEType = "application/x-bzip2"
			info.Extractable = true
			return info
		}
	}

	// XZ: FD 37 7A 58 5A 00
	if len(header) >= 6 &&
		header[0] == 0xFD && header[1] == 0x37 && header[2] == 0x7A &&
		header[3] == 0x58 && header[4] == 0x5A && header[5] == 0x00 {
		if isTarExtension(baseName) {
			info.Format = XzTAR
			info.MIMEType = "application/x-xz"
			info.Extractable = true
			return info
		}
	}

	// Zstandard: 28 B5 2F FD
	if len(header) >= 4 &&
		header[0] == 0x28 && header[1] == 0xB5 && header[2] == 0x2F && header[3] == 0xFD {
		if isTarExtension(baseName) {
			info.Format = ZstdTAR
			info.MIMEType = "application/zstd"
			info.Extractable = true
			return info
		}
	}

	// TAR: "ustar" at offset 257
	if len(header) >= 262 &&
		header[257] == 'u' && header[258] == 's' && header[259] == 't' &&
		header[260] == 'a' && header[261] == 'r' {
		info.Format = TAR
		info.MIMEType = "application/x-tar"
		info.Extractable = true
		return info
	}

	// Extension-based fallback for compressed tars with gzip magic but no tar extension.
	if len(header) >= 2 && header[0] == 0x1F && header[1] == 0x8B && (ext == ".gz" || ext == ".tgz") {
		info.Format = GzipTAR
		info.MIMEType = "application/gzip"
		info.Extractable = true
		return info
	}

	// InstallShield by naming convention: data*.cab
	if isInstallShieldByName(baseName) {
		info.Format = InstallShieldCAB
		info.MIMEType = "application/x-installshield-cab"
		info.Extractable = true
		return info
	}

	// Syft-native formats that are not ZIP-based (RPM, DEB, APK, etc.).
	// These have their own magic bytes that none of the checks above matched,
	// but Syft handles them natively as standalone package files.
	if syftNativeExtensions[ext] {
		info.SyftNative = true
		info.Extractable = false
		return info
	}

	return info
}

// isTarExtension checks if the base filename indicates a compressed TAR.
func isTarExtension(baseName string) bool {
	tarExts := []string{".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tar.zstd"}
	for _, ext := range tarExts {
		if strings.HasSuffix(baseName, ext) {
			return true
		}
	}
	return false
}

// isInstallShieldByName detects InstallShield CABs by naming convention.
// Only .cab files are extractable containers; .hdr files are companion
// header files that are not themselves containers.
func isInstallShieldByName(baseName string) bool {
	return strings.HasPrefix(baseName, "data") && strings.HasSuffix(baseName, ".cab")
}
