package identify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Format identifies a recognized file/container format.
type Format string

const (
	FormatUnknown          Format = "Unknown"
	FormatZIP              Format = "ZIP"
	FormatTAR              Format = "TAR"
	FormatGzipTAR          Format = "GzipTAR"
	FormatBzip2TAR         Format = "Bzip2TAR"
	FormatXzTAR            Format = "XzTAR"
	FormatZstdTAR          Format = "ZstdTAR"
	FormatCAB              Format = "CAB"
	FormatInstallShieldCAB Format = "InstallShieldCAB"
	FormatMSI              Format = "MSI"
	FormatSevenZip         Format = "SevenZip"
	FormatRAR              Format = "RAR"
)

// FormatInfo describes how a file should be treated by sbom-sentry.
type FormatInfo struct {
	Format      Format
	MIMEType    string
	Extension   string
	SyftNative  bool
	Extractable bool
}

var syftNativeExtensions = map[string]struct{}{
	".jar":   {},
	".war":   {},
	".ear":   {},
	".whl":   {},
	".egg":   {},
	".nupkg": {},
	".apk":   {},
	".rpm":   {},
	".deb":   {},
}

var installShieldNamePattern = regexp.MustCompile(`(?i)^data\d+\.cab$`)

// Identify inspects a file using bounded magic-byte and extension checks,
// then returns format and processing hints for extraction and scanning dispatch.
func Identify(ctx context.Context, path string) (FormatInfo, error) {
	select {
	case <-ctx.Done():
		return FormatInfo{}, ctx.Err()
	default:
	}

	f, err := os.Open(path)
	if err != nil {
		return FormatInfo{}, fmt.Errorf("open for identify: %w", err)
	}
	defer f.Close()

	head := make([]byte, 560)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return FormatInfo{}, fmt.Errorf("read header: %w", err)
	}
	head = head[:n]

	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	if len(head) >= 4 {
		switch {
		case bytes.HasPrefix(head, []byte("PK\x03\x04")):
			return build(path, FormatZIP, "application/zip", true), nil
		case bytes.HasPrefix(head, []byte("MSCF")):
			if isInstallShieldByName(path) {
				return build(path, FormatInstallShieldCAB, "application/vnd.installshield", false), nil
			}
			return build(path, FormatCAB, "application/vnd.ms-cab-compressed", false), nil
		case bytes.HasPrefix(head, []byte("ISc(")):
			return build(path, FormatInstallShieldCAB, "application/vnd.installshield", false), nil
		case bytes.HasPrefix(head, []byte("Rar!\x1A\x07")):
			return build(path, FormatRAR, "application/vnd.rar", false), nil
		}
	}
	if len(head) >= 6 && bytes.HasPrefix(head, []byte("7z\xBC\xAF\x27\x1C")) {
		return build(path, FormatSevenZip, "application/x-7z-compressed", false), nil
	}
	if len(head) >= 8 && bytes.HasPrefix(head, []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
		if ext == ".msi" {
			return build(path, FormatMSI, "application/x-msi", false), nil
		}
	}
	if len(head) >= 263 && string(head[257:262]) == "ustar" {
		return build(path, FormatTAR, "application/x-tar", true), nil
	}

	switch {
	case strings.HasSuffix(strings.ToLower(path), ".tar.gz") || strings.HasSuffix(strings.ToLower(path), ".tgz"):
		return build(path, FormatGzipTAR, "application/gzip", true), nil
	case strings.HasSuffix(strings.ToLower(path), ".tar.bz2"):
		return build(path, FormatBzip2TAR, "application/x-bzip2", true), nil
	case strings.HasSuffix(strings.ToLower(path), ".tar.xz"):
		return build(path, FormatXzTAR, "application/x-xz", false), nil
	case strings.HasSuffix(strings.ToLower(path), ".tar.zst"):
		return build(path, FormatZstdTAR, "application/zstd", false), nil
	case ext == ".msi":
		return build(path, FormatMSI, "application/x-msi", false), nil
	case ext == ".cab" && installShieldNamePattern.MatchString(base) && hasInstallShieldHDR(path):
		return build(path, FormatInstallShieldCAB, "application/vnd.installshield", false), nil
	case ext == ".cab":
		return build(path, FormatCAB, "application/vnd.ms-cab-compressed", false), nil
	case ext == ".7z":
		return build(path, FormatSevenZip, "application/x-7z-compressed", false), nil
	case ext == ".rar":
		return build(path, FormatRAR, "application/vnd.rar", false), nil
	case ext == ".zip":
		return build(path, FormatZIP, "application/zip", true), nil
	case ext == ".tar":
		return build(path, FormatTAR, "application/x-tar", true), nil
	}

	return build(path, FormatUnknown, "application/octet-stream", false), nil
}

func build(path string, format Format, mime string, stdlibExtractable bool) FormatInfo {
	ext := strings.ToLower(filepath.Ext(path))
	_, native := syftNativeExtensions[ext]

	extractable := stdlibExtractable
	switch format {
	case FormatCAB, FormatMSI, FormatSevenZip, FormatRAR, FormatInstallShieldCAB:
		extractable = true
	}

	return FormatInfo{
		Format:      format,
		MIMEType:    mime,
		Extension:   ext,
		SyftNative:  native,
		Extractable: extractable,
	}
}

func isInstallShieldByName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if !installShieldNamePattern.MatchString(base) {
		return false
	}
	return hasInstallShieldHDR(path)
}

func hasInstallShieldHDR(path string) bool {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	prefix := strings.TrimSuffix(base, filepath.Ext(base))
	hdr := filepath.Join(dir, prefix+".hdr")
	_, err := os.Stat(hdr)
	return err == nil
}
