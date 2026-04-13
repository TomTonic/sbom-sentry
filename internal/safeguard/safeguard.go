// Package safeguard provides the hard security boundary for extract-sbom's
// archive extraction. It validates paths, symlinks, file types, and
// compression ratios before any bytes are written to disk.
//
// Hard security violations (path traversal, symlink escape, special files)
// are never overridable, not even in unsafe mode. Resource limit violations
// are reported via separate error types for policy-based handling.
package safeguard

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// HardSecurityError signals a non-overridable security violation.
// These errors always abort the affected extraction subtree, regardless
// of policy mode or --unsafe flag. They cover path traversal, symlink
// escape, special file materialization, and unsafe permissions.
type HardSecurityError struct {
	Violation string
	Path      string
	Detail    string
}

// Error implements the error interface for HardSecurityError.
func (e *HardSecurityError) Error() string {
	return fmt.Sprintf("hard security violation: %s: %s (%s)", e.Violation, e.Path, e.Detail)
}

// ResourceLimitError signals a resource limit violation that may be
// handled by the policy engine (skip or abort depending on mode).
type ResourceLimitError struct {
	Limit   string
	Current int64
	Max     int64
	Path    string
}

// Error implements the error interface for ResourceLimitError.
func (e *ResourceLimitError) Error() string {
	return fmt.Sprintf("resource limit exceeded: %s: %d > %d at %s", e.Limit, e.Current, e.Max, e.Path)
}

// EntryHeader contains metadata about an archive entry needed for validation.
// It abstracts over ZIP, TAR, and other archive entry headers.
type EntryHeader struct {
	Name             string
	UncompressedSize int64
	CompressedSize   int64
	Mode             os.FileMode
	IsDir            bool
	IsSymlink        bool
	LinkTarget       string
}

// ExtractionStats tracks cumulative extraction metrics for limit enforcement.
// Pass a pointer to the same ExtractionStats across all entries in a single
// extraction operation to enforce aggregate limits.
type ExtractionStats struct {
	FileCount int
	TotalSize int64
}

// ValidatePath checks a single archive entry name for safety violations.
// It ensures the resolved path stays within baseDir and rejects path
// traversal, absolute paths, symlink escapes, and special files.
//
// Parameters:
//   - name: the entry name from the archive header
//   - baseDir: the directory entries are being extracted into
//
// Returns a HardSecurityError for any violation, nil if the path is safe.
func ValidatePath(name string, baseDir string) error {
	if name == "" {
		return &HardSecurityError{
			Violation: "empty-path",
			Path:      name,
			Detail:    "archive entry has empty name",
		}
	}

	// Reject absolute paths.
	if filepath.IsAbs(name) {
		return &HardSecurityError{
			Violation: "absolute-path",
			Path:      name,
			Detail:    "archive entry contains absolute path",
		}
	}

	// Clean the path and check for traversal.
	cleaned := filepath.Clean(name)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return &HardSecurityError{
			Violation: "path-traversal",
			Path:      name,
			Detail:    "archive entry attempts path traversal",
		}
	}

	// Resolve the full target path and verify containment.
	fullPath := filepath.Join(baseDir, cleaned)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return &HardSecurityError{
			Violation: "path-resolution",
			Path:      name,
			Detail:    fmt.Sprintf("cannot resolve base dir: %v", err),
		}
	}
	absTarget, err := filepath.Abs(fullPath)
	if err != nil {
		return &HardSecurityError{
			Violation: "path-resolution",
			Path:      name,
			Detail:    fmt.Sprintf("cannot resolve target path: %v", err),
		}
	}

	// Ensure the target is within the base directory.
	if !strings.HasPrefix(absTarget, absBase+string(filepath.Separator)) && absTarget != absBase {
		return &HardSecurityError{
			Violation: "path-escape",
			Path:      name,
			Detail:    fmt.Sprintf("resolved path %s escapes base %s", absTarget, absBase),
		}
	}

	return nil
}

// ValidateEntry checks an archive entry against size, ratio, and file-type
// constraints. It enforces both hard security checks (symlinks, special files)
// and resource limits (file count, total size, per-entry size, compression ratio).
//
// Parameters:
//   - header: metadata about the archive entry
//   - limits: configured extraction limits
//   - stats: cumulative extraction statistics (updated on success)
//
// Returns a HardSecurityError for symlinks/special files, a ResourceLimitError
// for limit violations, or nil if the entry passes all checks.
func ValidateEntry(header EntryHeader, limits config.Limits, stats *ExtractionStats) error {
	// Hard security: reject symlinks.
	if header.IsSymlink {
		return &HardSecurityError{
			Violation: "symlink",
			Path:      header.Name,
			Detail:    fmt.Sprintf("symlink targeting %q", header.LinkTarget),
		}
	}

	// Hard security: reject special files (devices, pipes, sockets).
	if !header.IsDir && !header.Mode.IsRegular() && header.Mode != 0 {
		return &HardSecurityError{
			Violation: "special-file",
			Path:      header.Name,
			Detail:    fmt.Sprintf("file mode %v indicates special file", header.Mode),
		}
	}

	// Skip resource limit checks for directories.
	if header.IsDir {
		return nil
	}

	// Hard security: reject negative sizes. A malicious archive can report
	// negative UncompressedSize or CompressedSize to underflow cumulative
	// size counters and bypass total-size limits.
	if header.UncompressedSize < 0 {
		return &HardSecurityError{
			Violation: "negative-size",
			Path:      header.Name,
			Detail:    fmt.Sprintf("negative uncompressed size %d", header.UncompressedSize),
		}
	}
	if header.CompressedSize < 0 {
		return &HardSecurityError{
			Violation: "negative-size",
			Path:      header.Name,
			Detail:    fmt.Sprintf("negative compressed size %d", header.CompressedSize),
		}
	}

	// Resource limit: per-entry size.
	if header.UncompressedSize > limits.MaxEntrySize {
		return &ResourceLimitError{
			Limit:   "max-entry-size",
			Current: header.UncompressedSize,
			Max:     limits.MaxEntrySize,
			Path:    header.Name,
		}
	}

	// Resource limit: compression ratio. Uses multiplication instead of
	// division to avoid truncation toward zero and division-by-zero.
	// CompressedSize==0 is skipped because TAR and other uncompressed
	// archive formats don't provide compressed sizes; the per-entry size
	// limit provides the backstop for those formats.
	if header.CompressedSize > 0 && limits.MaxRatio > 0 {
		if header.UncompressedSize > int64(limits.MaxRatio)*header.CompressedSize {
			ratio := header.UncompressedSize / header.CompressedSize
			return &ResourceLimitError{
				Limit:   "max-ratio",
				Current: ratio,
				Max:     int64(limits.MaxRatio),
				Path:    header.Name,
			}
		}
	}

	// Resource limit: total file count.
	if stats.FileCount >= limits.MaxFiles {
		return &ResourceLimitError{
			Limit:   "max-files",
			Current: int64(stats.FileCount) + 1,
			Max:     int64(limits.MaxFiles),
			Path:    header.Name,
		}
	}

	// Resource limit: total uncompressed size.
	if header.UncompressedSize > limits.MaxTotalSize-stats.TotalSize {
		current := saturatingAddInt64(stats.TotalSize, header.UncompressedSize)
		return &ResourceLimitError{
			Limit:   "max-total-size",
			Current: current,
			Max:     limits.MaxTotalSize,
			Path:    header.Name,
		}
	}

	// Update stats on successful validation.
	stats.FileCount++
	stats.TotalSize += header.UncompressedSize

	return nil
}

func saturatingAddInt64(a int64, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

// ValidatePostExtraction walks an extraction output directory and validates
// all resulting paths and file types. This is used for external tool
// extractions (7-Zip, unshield) where per-entry validation is not possible
// during extraction.
//
// Parameters:
//   - outputDir: the directory that was extracted into
//   - limits: configured extraction limits
//
// Returns a HardSecurityError on the first path traversal, symlink, or
// special file found. Returns a ResourceLimitError if file count or total
// size limits are exceeded. Returns nil if all entries pass validation.
func ValidatePostExtraction(outputDir string, limits config.Limits) error {
	stats := &ExtractionStats{}

	return filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("safeguard: walk error at %s: %w", path, err)
		}

		// Get the path relative to the output directory.
		relPath, err := filepath.Rel(outputDir, path)
		if err != nil {
			return &HardSecurityError{
				Violation: "path-resolution",
				Path:      path,
				Detail:    fmt.Sprintf("cannot compute relative path: %v", err),
			}
		}

		// Skip the root directory itself.
		if relPath == "." {
			return nil
		}

		// Validate path safety.
		if err := ValidatePath(relPath, outputDir); err != nil {
			return err
		}

		// Check for symlinks (os.Lstat is needed, but filepath.Walk uses os.Stat
		// which follows symlinks; we need to re-check).
		linfo, lerr := os.Lstat(path)
		if lerr != nil {
			return fmt.Errorf("safeguard: lstat error at %s: %w", path, lerr)
		}

		if linfo.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(path)
			return &HardSecurityError{
				Violation: "symlink",
				Path:      relPath,
				Detail:    fmt.Sprintf("symlink targeting %q", target),
			}
		}

		header := EntryHeader{
			Name:             relPath,
			UncompressedSize: info.Size(),
			Mode:             info.Mode(),
			IsDir:            info.IsDir(),
			IsSymlink:        false,
		}

		return ValidateEntry(header, limits, stats)
	})
}
