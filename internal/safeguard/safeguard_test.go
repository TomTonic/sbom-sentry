// Safeguard module tests: Validate that the hard security boundary correctly
// prevents path traversal, symlink escapes, special files, and resource
// exhaustion. This belongs to the security subsystem which protects against
// malicious archive contents.
package safeguard

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// TestValidatePathRejectsPathTraversal verifies that archive entries
// attempting to escape the extraction directory via ".." segments are
// blocked. This is a critical defense against zip-slip attacks.
func TestValidatePathRejectsPathTraversal(t *testing.T) {
	t.Parallel()
	baseDir := t.TempDir()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"safe relative path", "dir/file.txt", false},
		{"simple filename", "file.txt", false},
		{"nested safe path", "a/b/c/d.txt", false},
		{"dot-dot traversal", "../etc/passwd", true},
		{"hidden traversal", "dir/../../etc/passwd", true},
		{"absolute path", "/etc/passwd", true},
		{"empty path", "", true},
		{"single dot is safe", ".", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePath(tt.path, baseDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if _, ok := err.(*HardSecurityError); !ok {
					t.Errorf("expected HardSecurityError, got %T", err)
				}
			}
		})
	}
}

// TestValidateEntryRejectsSymlinks verifies that symlink archive entries
// are always rejected. Symlinks could be used to escape the extraction
// directory and overwrite arbitrary files.
func TestValidateEntryRejectsSymlinks(t *testing.T) {
	t.Parallel()

	header := EntryHeader{
		Name:       "link.txt",
		IsSymlink:  true,
		LinkTarget: "/etc/passwd",
	}

	limits := config.DefaultLimits()
	stats := &ExtractionStats{}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for symlink")
	}
	if _, ok := err.(*HardSecurityError); !ok {
		t.Errorf("expected HardSecurityError, got %T", err)
	}
}

// TestValidateEntryRejectsSpecialFiles verifies that special file types
// (devices, pipes, sockets) are rejected. These could be used to create
// device nodes or named pipes that interfere with the system.
func TestValidateEntryRejectsSpecialFiles(t *testing.T) {
	t.Parallel()

	header := EntryHeader{
		Name: "device",
		Mode: os.ModeDevice | 0o666,
	}

	limits := config.DefaultLimits()
	stats := &ExtractionStats{}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for special file")
	}
	if _, ok := err.(*HardSecurityError); !ok {
		t.Errorf("expected HardSecurityError, got %T", err)
	}
}

// TestValidateEntryAcceptsRegularFiles verifies that normal files pass
// validation when within all limits. This is the happy path for the
// vast majority of archive entries.
func TestValidateEntryAcceptsRegularFiles(t *testing.T) {
	t.Parallel()

	header := EntryHeader{
		Name:             "lib/file.dll",
		UncompressedSize: 1024 * 1024,
		CompressedSize:   512 * 1024,
		Mode:             0o644,
	}

	limits := config.DefaultLimits()
	stats := &ExtractionStats{}

	if err := ValidateEntry(header, limits, stats); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if stats.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1", stats.FileCount)
	}
	if stats.TotalSize != 1024*1024 {
		t.Errorf("TotalSize = %d, want %d", stats.TotalSize, 1024*1024)
	}
}

// TestValidateEntryRejectsOversizedEntry verifies that entries exceeding
// the per-entry size limit are rejected. This prevents a single huge
// file from consuming all available disk space.
func TestValidateEntryRejectsOversizedEntry(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxEntrySize = 100

	header := EntryHeader{
		Name:             "huge.bin",
		UncompressedSize: 200,
		CompressedSize:   50,
		Mode:             0o644,
	}

	stats := &ExtractionStats{}
	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for oversized entry")
	}
	if _, ok := err.(*ResourceLimitError); !ok {
		t.Errorf("expected ResourceLimitError, got %T", err)
	}
}

// TestValidateEntryRejectsHighCompressionRatio verifies that entries with
// suspiciously high compression ratios are rejected. This prevents zip
// bomb attacks where a small compressed entry expands to enormous size.
func TestValidateEntryRejectsHighCompressionRatio(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxRatio = 10

	header := EntryHeader{
		Name:             "bomb.bin",
		UncompressedSize: 1100,
		CompressedSize:   100,
		Mode:             0o644,
	}

	stats := &ExtractionStats{}
	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for high compression ratio")
	}
	if _, ok := err.(*ResourceLimitError); !ok {
		t.Errorf("expected ResourceLimitError, got %T", err)
	}
}

// TestValidateEntryRejectsExcessiveFileCount verifies that the file count
// limit is enforced across entries. This prevents archives with millions
// of tiny files from exhausting filesystem resources.
func TestValidateEntryRejectsExcessiveFileCount(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxFiles = 2

	stats := &ExtractionStats{FileCount: 2}
	header := EntryHeader{
		Name:             "file3.txt",
		UncompressedSize: 10,
		Mode:             0o644,
	}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for excessive file count")
	}
	if _, ok := err.(*ResourceLimitError); !ok {
		t.Errorf("expected ResourceLimitError, got %T", err)
	}
}

// TestValidateEntryRejectsExcessiveTotalSize verifies that the cumulative
// uncompressed size limit is enforced. This prevents archives from
// consuming more disk space than allowed.
func TestValidateEntryRejectsExcessiveTotalSize(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxTotalSize = 100

	stats := &ExtractionStats{TotalSize: 90}
	header := EntryHeader{
		Name:             "extra.bin",
		UncompressedSize: 20,
		Mode:             0o644,
	}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for excessive total size")
	}
	if _, ok := err.(*ResourceLimitError); !ok {
		t.Errorf("expected ResourceLimitError, got %T", err)
	}
}

// TestValidateEntryRejectsOverflowingFileCount verifies that max-files checks
// cannot be bypassed by integer overflow in the next-count calculation.
func TestValidateEntryRejectsOverflowingFileCount(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxFiles = math.MaxInt

	stats := &ExtractionStats{FileCount: math.MaxInt}
	header := EntryHeader{
		Name:             "one-more.txt",
		UncompressedSize: 1,
		Mode:             0o644,
	}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for overflowing file count")
	}
	limitErr, ok := err.(*ResourceLimitError)
	if !ok {
		t.Fatalf("expected ResourceLimitError, got %T", err)
	}
	if limitErr.Limit != "max-files" {
		t.Fatalf("Limit = %q, want %q", limitErr.Limit, "max-files")
	}
}

// TestValidateEntryRejectsOverflowingTotalSize verifies that max-total-size
// checks are overflow-safe for near-int64-max cumulative sizes.
func TestValidateEntryRejectsOverflowingTotalSize(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxTotalSize = math.MaxInt64

	stats := &ExtractionStats{TotalSize: math.MaxInt64}
	header := EntryHeader{
		Name:             "one-more.bin",
		UncompressedSize: 1,
		Mode:             0o644,
	}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for overflowing total size")
	}
	limitErr, ok := err.(*ResourceLimitError)
	if !ok {
		t.Fatalf("expected ResourceLimitError, got %T", err)
	}
	if limitErr.Limit != "max-total-size" {
		t.Fatalf("Limit = %q, want %q", limitErr.Limit, "max-total-size")
	}
}

// TestValidateEntrySkipsLimitChecksForDirectories verifies that
// directory entries pass validation without consuming file count or
// size quotas. Directories are structural and don't carry payload data.
func TestValidateEntrySkipsLimitChecksForDirectories(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxFiles = 0 // would fail for regular files

	header := EntryHeader{
		Name:  "some/dir/",
		IsDir: true,
		Mode:  os.ModeDir | 0o750,
	}

	stats := &ExtractionStats{}
	if err := ValidateEntry(header, limits, stats); err != nil {
		t.Errorf("unexpected error for directory: %v", err)
	}
}

// TestValidatePostExtractionDetectsSymlinks verifies that the post-extraction
// walk catches symlinks created by external tools (7-Zip, unshield).
func TestValidatePostExtractionDetectsSymlinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a symlink in the output directory.
	symPath := filepath.Join(dir, "link")
	if err := os.Symlink("/etc/passwd", symPath); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	err := ValidatePostExtraction(dir, config.DefaultLimits())
	if err == nil {
		t.Fatal("expected error for symlink in post-extraction walk")
	}
}

// TestHardSecurityErrorIncludesDetails verifies that HardSecurityError
// produces useful diagnostic messages for the audit report.
func TestHardSecurityErrorIncludesDetails(t *testing.T) {
	t.Parallel()
	err := &HardSecurityError{
		Violation: "path-traversal",
		Path:      "../etc/passwd",
		Detail:    "archive entry attempts path traversal",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("error message is empty")
	}
}

// TestResourceLimitErrorIncludesDetails verifies that ResourceLimitError
// produces useful diagnostic messages with the limit name and values.
func TestResourceLimitErrorIncludesDetails(t *testing.T) {
	t.Parallel()
	err := &ResourceLimitError{
		Limit:   "max-entry-size",
		Current: 5000,
		Max:     1000,
		Path:    "huge.bin",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("error message is empty")
	}
}

// TestValidateEntryRejectsNegativeUncompressedSize verifies that archive
// entries with negative UncompressedSize are rejected as hard security
// violations. A crafted archive could use negative sizes to underflow the
// cumulative TotalSize counter and bypass MaxTotalSize limits.
func TestValidateEntryRejectsNegativeUncompressedSize(t *testing.T) {
	t.Parallel()

	header := EntryHeader{
		Name:             "evil.bin",
		UncompressedSize: -1,
		CompressedSize:   100,
		Mode:             0o644,
	}

	limits := config.DefaultLimits()
	stats := &ExtractionStats{}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for negative uncompressed size")
	}
	if _, ok := err.(*HardSecurityError); !ok {
		t.Errorf("expected HardSecurityError, got %T: %v", err, err)
	}
}

// TestValidateEntryRejectsNegativeCompressedSize verifies that archive
// entries with negative CompressedSize are rejected as hard security
// violations to prevent ratio-check bypass.
func TestValidateEntryRejectsNegativeCompressedSize(t *testing.T) {
	t.Parallel()

	header := EntryHeader{
		Name:             "evil.bin",
		UncompressedSize: 100,
		CompressedSize:   -1,
		Mode:             0o644,
	}

	limits := config.DefaultLimits()
	stats := &ExtractionStats{}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for negative compressed size")
	}
	if _, ok := err.(*HardSecurityError); !ok {
		t.Errorf("expected HardSecurityError, got %T: %v", err, err)
	}
}

// TestValidateEntryAllowsZeroCompressedSizeWithLargeUncompressed verifies
// that an archive entry with CompressedSize==0 and nonzero
// UncompressedSize is allowed. TAR and other uncompressed archive formats
// don't provide compressed sizes. The per-entry size limit provides the
// backstop for these formats; the ratio check only applies when
// CompressedSize is available (> 0).
func TestValidateEntryAllowsZeroCompressedSizeWithLargeUncompressed(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxRatio = 100

	header := EntryHeader{
		Name:             "tar-entry.bin",
		UncompressedSize: 999999,
		CompressedSize:   0,
		Mode:             0o644,
	}

	stats := &ExtractionStats{}
	err := ValidateEntry(header, limits, stats)
	// Should pass: CompressedSize==0 means ratio check is skipped.
	// The per-entry size limit is the backstop.
	if err != nil {
		t.Errorf("unexpected error for zero compressed size: %v", err)
	}
}

// TestValidateEntryRejectsNearBoundaryCompressionRatio verifies that the
// multiplication-based ratio check catches ratios that integer division
// would miss due to truncation. For example, with MaxRatio=10, an entry
// with uncompressed=109 and compressed=10 has a true ratio of 10.9 —
// integer division yields 10 (passes old check), but the new
// multiplication-based check correctly rejects it.
func TestValidateEntryRejectsNearBoundaryCompressionRatio(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxRatio = 10

	header := EntryHeader{
		Name:             "sneaky.bin",
		UncompressedSize: 109, // 109 / 10 = 10 (truncated), but 109 > 10*10
		CompressedSize:   10,
		Mode:             0o644,
	}

	stats := &ExtractionStats{}
	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for near-boundary compression ratio (10.9 > MaxRatio 10)")
	}
	if rle, ok := err.(*ResourceLimitError); !ok {
		t.Errorf("expected ResourceLimitError, got %T: %v", err, err)
	} else if rle.Limit != "max-ratio" {
		t.Errorf("Limit = %q, want %q", rle.Limit, "max-ratio")
	}
}

// TestValidateEntryAcceptsExactBoundaryCompressionRatio verifies that an
// entry whose compression ratio is exactly at the limit passes validation.
// With MaxRatio=10, uncompressed=100 and compressed=10 yields ratio
// exactly 10, which should be allowed.
func TestValidateEntryAcceptsExactBoundaryCompressionRatio(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxRatio = 10

	header := EntryHeader{
		Name:             "exact.bin",
		UncompressedSize: 100, // 100 / 10 = exactly 10, not > 10
		CompressedSize:   10,
		Mode:             0o644,
	}

	stats := &ExtractionStats{}
	if err := ValidateEntry(header, limits, stats); err != nil {
		t.Errorf("unexpected error for exact boundary ratio: %v", err)
	}
}

// TestValidateEntryNegativeSizeDoesNotDecreaseTotalSize verifies that a
// negative UncompressedSize cannot be used to reduce the cumulative
// TotalSize counter, which would create headroom for subsequent entries
// to bypass MaxTotalSize.
func TestValidateEntryNegativeSizeDoesNotDecreaseTotalSize(t *testing.T) {
	t.Parallel()

	limits := config.DefaultLimits()
	limits.MaxTotalSize = 100

	stats := &ExtractionStats{TotalSize: 90}
	header := EntryHeader{
		Name:             "underflow.bin",
		UncompressedSize: -50, // Would decrease TotalSize to 40 if not caught
		Mode:             0o644,
	}

	err := ValidateEntry(header, limits, stats)
	if err == nil {
		t.Fatal("expected error for negative uncompressed size")
	}
	// TotalSize must not have decreased.
	if stats.TotalSize != 90 {
		t.Errorf("TotalSize = %d, want 90 (must not decrease)", stats.TotalSize)
	}
}
