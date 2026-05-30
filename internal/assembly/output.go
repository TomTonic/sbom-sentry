package assembly

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// WriteSBOM persists a consolidated CycloneDX BOM as pretty-printed JSON or XML.
//
// Why this exists:
// Assembly returns an in-memory BOM, while CLI and integration workflows need
// a stable on-disk artifact for scanners and audit workflows.
//
// Typical use:
// Call WriteSBOM with the result from Assemble and the configured output path
// (usually "<output-dir>/<input>.cdx.json" or "<output-dir>/<input>.cdx.xml").
//
// Parameters:
// - bom: CycloneDX BOM to encode
// - path: target file path to create or truncate
// - format: SBOM format string ("cyclonedx-json" or "cyclonedx-xml")
//
// Returns an error when file creation fails or encoding cannot complete.
func WriteSBOM(bom *cdx.BOM, path string, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("assembly: create SBOM file %s: %w", path, err)
	}

	fileFormat := cdx.BOMFileFormatJSON
	if format == "cyclonedx-xml" {
		fileFormat = cdx.BOMFileFormatXML
	}

	encoder := cdx.NewBOMEncoder(f, fileFormat)
	encoder.SetPretty(true)

	if err := encoder.Encode(bom); err != nil {
		f.Close()
		return fmt.Errorf("assembly: encode SBOM: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("assembly: close SBOM file %s: %w", path, err)
	}

	return nil
}

// generateCPE creates a CPE 2.3 string from manufacturer, product, and version.
// It follows NVD normalization: lowercase, spaces replaced with underscores,
// special characters stripped.
func generateCPE(manufacturer, product, version string) string {
	vendor := normalizeCPEField(manufacturer)
	prod := normalizeCPEField(product)
	ver := normalizeCPEField(version)

	if vendor == "" || prod == "" {
		return ""
	}

	if ver == "" {
		ver = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, prod, ver)
}

// normalizeCPEField normalizes a string for CPE use.
func normalizeCPEField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")

	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// computeSHA256 computes the SHA-256 hash of a file.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
