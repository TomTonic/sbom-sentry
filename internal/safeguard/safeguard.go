package safeguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"sbom-sentry/internal/config"
)

// HardSecurityError is returned for non-overridable violations that indicate
// potentially hostile archive behavior (traversal, symlink escapes, special files).
type HardSecurityError struct {
	Violation string
	Path      string
}

// Error formats a stable, user-facing message for the hard security violation.
func (e *HardSecurityError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("hard security violation: %s", e.Violation)
	}
	return fmt.Sprintf("hard security violation: %s (%s)", e.Violation, e.Path)
}

// EntryHeader is the normalized metadata used to validate an archive member.
type EntryHeader struct {
	Name             string
	Mode             uint32
	CompressedSize   int64
	UncompressedSize int64
	IsDir            bool
	IsSymlink        bool
}

// ExtractionStats tracks aggregate extraction counters used for limit checks.
type ExtractionStats struct {
	Files     int
	TotalSize int64
}

// ValidatePath verifies that an archive entry path is safe to materialize
// under baseDir and rejects traversal and absolute path patterns.
func ValidatePath(name string, baseDir string) error {
	if name == "" {
		return &HardSecurityError{Violation: "empty path", Path: name}
	}

	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." {
		return nil
	}
	if filepath.IsAbs(clean) {
		return &HardSecurityError{Violation: "absolute path", Path: name}
	}
	if strings.HasPrefix(clean, "../") || clean == ".." {
		return &HardSecurityError{Violation: "path traversal", Path: name}
	}

	joined := filepath.Join(baseDir, clean)
	rel, err := filepath.Rel(baseDir, joined)
	if err != nil {
		return fmt.Errorf("path containment check failed: %w", err)
	}
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return &HardSecurityError{Violation: "path escapes extraction root", Path: name}
	}
	return nil
}

// ValidateEntry enforces size/ratio constraints and rejects unsafe file types.
// Hard security violations always return HardSecurityError.
func ValidateEntry(header EntryHeader, limits config.Limits, stats *ExtractionStats) error {
	if header.IsSymlink {
		return &HardSecurityError{Violation: "symlink entry blocked", Path: header.Name}
	}

	if header.Mode&0o170000 != 0 && header.Mode&0o170000 != 0o100000 && header.Mode&0o170000 != 0o040000 {
		return &HardSecurityError{Violation: "special file entry blocked", Path: header.Name}
	}

	if header.UncompressedSize < 0 {
		return errors.New("invalid entry size")
	}
	if header.UncompressedSize > limits.MaxEntrySize {
		return fmt.Errorf("entry exceeds max-entry-size: %s", header.Name)
	}

	if header.CompressedSize > 0 && header.UncompressedSize > 0 {
		ratio := int((header.UncompressedSize * 100) / header.CompressedSize)
		if ratio > limits.MaxRatio {
			return fmt.Errorf("entry exceeds max-ratio: %s", header.Name)
		}
	}

	if !header.IsDir {
		stats.Files++
		stats.TotalSize += header.UncompressedSize
	}

	if stats.Files > limits.MaxFiles {
		return fmt.Errorf("max-files exceeded")
	}
	if stats.TotalSize > limits.MaxTotalSize {
		return fmt.Errorf("max-total-size exceeded")
	}
	return nil
}
