// Package extract implements recursive, auditable extraction of archive formats.
// It applies the Syft-first principle: every file is first checked for Syft-native
// handling; extract-sbom only extracts when Syft cannot see through a container
// format.
//
// Supported extraction paths:
//   - ZIP via Go stdlib archive/zip (in-process, per-entry safeguard)
//   - TAR and compressed TAR via Go stdlib archive/tar + compress/* (in-process)
//   - CAB, MSI, 7z, RAR via 7-Zip through sandbox interface (post-extraction walk)
//   - InstallShield CAB via unshield through sandbox interface
package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

const extractionProgressInterval = 2 * time.Second

// ExtractionStatus represents the outcome of processing an extraction node.
type ExtractionStatus int

const (
	// StatusPending indicates the node has not been processed yet.
	StatusPending ExtractionStatus = iota
	// StatusSyftNative indicates the file is handled directly by Syft.
	StatusSyftNative
	// StatusExtracted indicates the file was successfully extracted.
	StatusExtracted
	// StatusSkipped indicates extraction was skipped due to policy.
	StatusSkipped
	// StatusFailed indicates extraction failed.
	StatusFailed
	// StatusSecurityBlocked indicates extraction was blocked by a hard security violation.
	StatusSecurityBlocked
	// StatusToolMissing indicates the required extraction tool is not available.
	StatusToolMissing
)

// String returns the human-readable name of the extraction status.
func (s ExtractionStatus) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusSyftNative:
		return "syft-native"
	case StatusExtracted:
		return "extracted"
	case StatusSkipped:
		return "skipped"
	case StatusFailed:
		return "failed"
	case StatusSecurityBlocked:
		return "security-blocked"
	case StatusToolMissing:
		return "tool-missing"
	default:
		return "unknown"
	}
}

// ContainerMetadata holds structured product information extracted from
// container formats that carry it (currently: MSI Property table).
type ContainerMetadata struct {
	ProductName    string
	Manufacturer   string
	ProductVersion string
	ProductCode    string
	UpgradeCode    string
	Language       string
}

// ExtractionNode is the central processing data structure.
// Each node represents a container artifact encountered during traversal.
// The tree of nodes forms the extraction state from which both the SBOM
// and audit report are derived.
type ExtractionNode struct {
	Path          string              // physical artifact path relative to delivery root
	OriginalPath  string              // absolute filesystem path of the original file
	Format        identify.FormatInfo // detected format of this artifact
	Status        ExtractionStatus    // processing outcome
	StatusDetail  string              // human-readable explanation
	ExtractedDir  string              // filesystem path of extracted contents (empty if SyftNative)
	Children      []*ExtractionNode   // child nodes from recursive extraction
	Metadata      *ContainerMetadata  // non-nil for formats with structured metadata (MSI)
	InstallerHint string              // non-empty when installer-semantic mode could yield richer data
	Tool          string              // extraction tool used
	SandboxUsed   string              // sandbox mechanism used
	Duration      time.Duration       // time taken for extraction
	EntriesCount  int                 // number of entries extracted
	TotalSize     int64               // total uncompressed size of extracted entries
}

// Extract recursively processes the given file according to configuration.
// It builds and returns the root ExtractionNode tree representing the
// full extraction state. The tree is the single source of truth for what
// was processed, how, and with what outcome.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - inputPath: absolute filesystem path to the input file
//   - cfg: the run configuration (limits, policy, interpretation mode)
//   - sb: the sandbox to use for external tool invocations
//
// Returns the root ExtractionNode or an error if the initial file cannot
// be processed at all.
func Extract(ctx context.Context, inputPath string, cfg config.Config, sb sandbox.Sandbox) (*ExtractionNode, error) {
	baseName := filepath.Base(inputPath)
	root := &ExtractionNode{
		Path:         baseName,
		OriginalPath: inputPath,
	}

	stats := &safeguard.ExtractionStats{}
	if err := extractRecursive(ctx, root, inputPath, baseName, 0, cfg, sb, stats); err != nil {
		// If we have a tree at all, return it with the error info.
		return root, err
	}

	return root, nil
}

// extractRecursive handles one level of extraction and recurses into children.
func extractRecursive(ctx context.Context, node *ExtractionNode, filePath string, deliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox, stats *safeguard.ExtractionStats) error {
	// Check depth limit.
	if depth > cfg.Limits.MaxDepth {
		node.Status = StatusSkipped
		node.StatusDetail = fmt.Sprintf("depth limit %d exceeded", cfg.Limits.MaxDepth)
		return &safeguard.ResourceLimitError{
			Limit:   "max-depth",
			Current: int64(depth),
			Max:     int64(cfg.Limits.MaxDepth),
			Path:    deliveryPath,
		}
	}

	// Identify the format.
	info, err := identify.Identify(ctx, filePath)
	if err != nil {
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("format identification failed: %v", err)
		return nil // non-fatal, the node is recorded
	}
	node.Format = info

	// Syft-native: delegate to Syft, do not extract.
	if info.SyftNative {
		node.Status = StatusSyftNative
		node.Tool = "syft"
		node.StatusDetail = fmt.Sprintf("Syft-native format (%s), passed directly to Syft", info.Format)
		return nil
	}

	// Not a container format: plain leaf.
	if info.Format == identify.Unknown {
		node.Status = StatusSkipped
		node.StatusDetail = "not a recognized container format"
		return nil
	}

	// Extract based on format.
	start := time.Now()

	// Apply per-extraction timeout from configuration.
	extractCtx := ctx
	if cfg.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		extractCtx, cancel = context.WithTimeout(ctx, cfg.Limits.Timeout)
		defer cancel()
	}

	switch info.Format {
	case identify.ZIP:
		err = extractZIP(extractCtx, node, filePath, cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.TAR:
		err = extractTAR(extractCtx, node, filePath, nil, cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.GzipTAR:
		err = extractCompressedTAR(extractCtx, node, filePath, "gzip", cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.Bzip2TAR:
		err = extractCompressedTAR(extractCtx, node, filePath, "bzip2", cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.XzTAR, identify.ZstdTAR:
		// XZ and Zstd require external libraries; for now mark as needing 7zz.
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.CAB, identify.SevenZip, identify.RAR:
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.MSI:
		// Read MSI metadata directly from the OLE structure (independent of 7zz).
		if meta, msiErr := ReadMSIMetadata(filePath, cfg.Limits.MaxEntrySize); msiErr == nil {
			node.Metadata = meta
		}
		// In installer-semantic mode, flag that MSI File-table remapping
		// could provide richer path data (Phase 4 feature).
		if cfg.InterpretMode == config.InterpretInstallerSemantic && node.Metadata != nil {
			node.InstallerHint = "msi-file-table-remapping-available"
		}
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.InstallShieldCAB:
		err = extractUnshield(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	default:
		node.Status = StatusSkipped
		node.StatusDetail = fmt.Sprintf("no extraction handler for format %s", info.Format)
		return nil
	}

	node.Duration = time.Since(start)

	if err != nil {
		// Check if it's a timeout error from the per-extraction deadline.
		if extractCtx.Err() == context.DeadlineExceeded {
			node.Status = StatusFailed
			node.StatusDetail = fmt.Sprintf("per-extraction timeout (%s) exceeded", cfg.Limits.Timeout)
			return &safeguard.ResourceLimitError{
				Limit:   "timeout",
				Current: int64(node.Duration.Seconds()),
				Max:     int64(cfg.Limits.Timeout.Seconds()),
				Path:    deliveryPath,
			}
		}
		// Check if it's a security error.
		if _, ok := err.(*safeguard.HardSecurityError); ok {
			node.Status = StatusSecurityBlocked
			node.StatusDetail = err.Error()
			return err
		}
		// Resource limit errors propagate so the policy engine can evaluate them.
		if _, ok := err.(*safeguard.ResourceLimitError); ok {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
			return err
		}
		// Other extraction errors are recorded but not fatal to the tree.
		if node.Status == StatusPending {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
		}
		return nil
	}

	// Recurse into extracted contents.
	if node.ExtractedDir != "" {
		if walkErr := recurseIntoDir(ctx, node, node.ExtractedDir, deliveryPath, depth+1, cfg, sb, stats); walkErr != nil {
			return walkErr
		}
	}

	return nil
}

// recurseIntoDir walks the extracted directory and processes each file.
func recurseIntoDir(ctx context.Context, parent *ExtractionNode, dir string, parentDeliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox, stats *safeguard.ExtractionStats) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("extract: read dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Recurse into subdirectories.
			subDir := filepath.Join(dir, entry.Name())
			if walkErr := recurseIntoDir(ctx, parent, subDir, parentDeliveryPath+"/"+entry.Name(), depth, cfg, sb, stats); walkErr != nil {
				return walkErr
			}
			continue
		}

		childPath := filepath.Join(dir, entry.Name())
		childDeliveryPath := parentDeliveryPath + "/" + entry.Name()

		child := &ExtractionNode{
			Path:         childDeliveryPath,
			OriginalPath: childPath,
		}

		if err := extractRecursive(ctx, child, childPath, childDeliveryPath, depth, cfg, sb, stats); err != nil {
			if _, ok := err.(*safeguard.HardSecurityError); ok {
				child.Status = StatusSecurityBlocked
				child.StatusDetail = err.Error()
				// In partial mode, continue with other children.
				if cfg.PolicyMode == config.PolicyPartial {
					parent.Children = append(parent.Children, child)
					continue
				}
				parent.Children = append(parent.Children, child)
				return err
			}
			if _, ok := err.(*safeguard.ResourceLimitError); ok {
				if cfg.PolicyMode == config.PolicyPartial {
					parent.Children = append(parent.Children, child)
					continue
				}
				parent.Children = append(parent.Children, child)
				return err
			}
		}

		// Only add children that are actual container/archive nodes, not plain files.
		if child.Status != StatusSkipped || len(child.Children) > 0 {
			parent.Children = append(parent.Children, child)
		}
	}

	return nil
}

// extractZIP extracts a ZIP archive using Go's archive/zip stdlib.
// Each entry header is validated by safeguard before any bytes are written.
func extractZIP(ctx context.Context, node *ExtractionNode, filePath string, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return fmt.Errorf("extract: open zip %s: %w", filePath, err)
	}
	defer r.Close()

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-zip-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	// Clean up if extraction fails before node.ExtractedDir is assigned.
	var zipOK bool
	defer func() {
		if !zipOK {
			os.RemoveAll(outDir)
		}
	}()

	node.Tool = "archive/zip"
	sanitizedNames := 0
	nextProgress := time.Now().Add(extractionProgressInterval)

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entryName := sanitizeArchiveEntryName(f.Name)
		if entryName != f.Name {
			sanitizedNames++
		}

		// Validate path safety against both the original ZIP entry name and
		// the filesystem-safe name that will actually be written.
		if err := safeguard.ValidatePath(f.Name, outDir); err != nil {
			return err
		}
		if err := safeguard.ValidatePath(entryName, outDir); err != nil {
			return err
		}

		header := safeguard.EntryHeader{
			Name:             entryName,
			UncompressedSize: safeUint64ToInt64(f.UncompressedSize64),
			CompressedSize:   safeUint64ToInt64(f.CompressedSize64),
			Mode:             f.Mode(),
			IsDir:            f.FileInfo().IsDir(),
			IsSymlink:        f.Mode()&os.ModeSymlink != 0,
		}

		if err := safeguard.ValidateEntry(header, limits, stats); err != nil {
			return err
		}

		targetPath := filepath.Join(outDir, filepath.Clean(entryName))

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("extract: create dir %s: %w", targetPath, err)
			}
			continue
		}

		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
			return fmt.Errorf("extract: create parent dir for %s: %w", targetPath, err)
		}

		if err := extractZIPEntry(f, targetPath, limits); err != nil {
			return err
		}

		node.EntriesCount++
		node.TotalSize += safeUint64ToInt64(f.UncompressedSize64)

		if time.Now().After(nextProgress) {
			totalGiB := float64(node.TotalSize) / (1024.0 * 1024.0 * 1024.0)
			cfg.EmitProgress(config.ProgressNormal, "[extract] %s: %d files extracted, %.2f GiB unpacked", node.Path, node.EntriesCount, totalGiB)
			nextProgress = time.Now().Add(extractionProgressInterval)
		}
	}

	node.ExtractedDir = outDir
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", node.EntriesCount)
	if sanitizedNames > 0 {
		node.StatusDetail = fmt.Sprintf("%s (sanitized %d ZIP entry names for filesystem compatibility)", node.StatusDetail, sanitizedNames)
	}
	zipOK = true

	return nil
}

// sanitizeArchiveEntryName turns invalid UTF-8 bytes in archive entry names
// into a stable replacement sequence so hosts with strict filesystem APIs
// (notably macOS) can still create files.
func sanitizeArchiveEntryName(name string) string {
	if utf8.ValidString(name) {
		return name
	}

	normalized := strings.ToValidUTF8(name, "_")
	normalized = strings.ReplaceAll(normalized, "\\", "/")
	cleaned := path.Clean(normalized)
	if cleaned == "." {
		return "_"
	}
	return cleaned
}

// extractZIPEntry writes a single ZIP entry to disk with size-bounded copying.
func extractZIPEntry(f *zip.File, targetPath string, limits config.Limits) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("extract: open zip entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("extract: create file %s: %w", targetPath, err)
	}
	defer out.Close()

	// Use LimitReader to enforce per-entry size limit.
	limited := io.LimitReader(rc, limits.MaxEntrySize+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("extract: write zip entry %s: %w", f.Name, err)
	}

	if written > limits.MaxEntrySize {
		return &safeguard.ResourceLimitError{
			Limit:   "max-entry-size-actual",
			Current: written,
			Max:     limits.MaxEntrySize,
			Path:    f.Name,
		}
	}

	return nil
}

// extractTAR extracts a TAR archive using Go's archive/tar stdlib.
// If reader is nil, the file is opened directly.
func extractTAR(ctx context.Context, node *ExtractionNode, filePath string, reader io.Reader, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	if reader == nil {
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("extract: open tar %s: %w", filePath, err)
		}
		defer f.Close()
		reader = f
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-tar-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	// Clean up if extraction fails before node.ExtractedDir is assigned.
	var tarOK bool
	defer func() {
		if !tarOK {
			os.RemoveAll(outDir)
		}
	}()

	node.Tool = "archive/tar"
	nextProgress := time.Now().Add(extractionProgressInterval)

	tr := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("extract: read tar entry: %w", err)
		}

		// Validate path safety.
		if err := safeguard.ValidatePath(hdr.Name, outDir); err != nil {
			return err
		}

		header := safeguard.EntryHeader{
			Name:             hdr.Name,
			UncompressedSize: hdr.Size,
			Mode:             hdr.FileInfo().Mode(),
			IsDir:            hdr.Typeflag == tar.TypeDir,
			IsSymlink:        hdr.Typeflag == tar.TypeSymlink,
			LinkTarget:       hdr.Linkname,
		}

		if err := safeguard.ValidateEntry(header, limits, stats); err != nil {
			return err
		}

		targetPath := filepath.Join(outDir, filepath.Clean(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("extract: create dir %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
				return fmt.Errorf("extract: create parent dir for %s: %w", targetPath, err)
			}
			if err := extractTAREntry(tr, targetPath, hdr.Size, limits); err != nil {
				return err
			}
			node.EntriesCount++
			node.TotalSize += hdr.Size
			if time.Now().After(nextProgress) {
				totalGiB := float64(node.TotalSize) / (1024.0 * 1024.0 * 1024.0)
				cfg.EmitProgress(config.ProgressNormal, "[extract] %s: %d files extracted, %.2f GiB unpacked", node.Path, node.EntriesCount, totalGiB)
				nextProgress = time.Now().Add(extractionProgressInterval)
			}
		default:
			// Skip other types (symlinks are rejected by safeguard).
			continue
		}
	}

	node.ExtractedDir = outDir
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", node.EntriesCount)
	tarOK = true

	return nil
}

// extractTAREntry writes a single TAR entry to disk.
func extractTAREntry(tr *tar.Reader, targetPath string, size int64, limits config.Limits) error {
	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("extract: create file %s: %w", targetPath, err)
	}
	defer out.Close()

	limited := io.LimitReader(tr, limits.MaxEntrySize+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("extract: write tar entry %s: %w", targetPath, err)
	}

	if written > limits.MaxEntrySize {
		return &safeguard.ResourceLimitError{
			Limit:   "max-entry-size-actual",
			Current: written,
			Max:     limits.MaxEntrySize,
			Path:    targetPath,
		}
	}
	_ = size

	return nil
}

// extractCompressedTAR handles gzip and bzip2 compressed TAR archives.
func extractCompressedTAR(ctx context.Context, node *ExtractionNode, filePath string, compression string, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("extract: open %s: %w", filePath, err)
	}
	defer f.Close()

	var reader io.Reader
	switch compression {
	case "gzip":
		gr, gerr := gzip.NewReader(f)
		if gerr != nil {
			return fmt.Errorf("extract: create gzip reader: %w", gerr)
		}
		defer gr.Close()
		reader = gr
	case "bzip2":
		reader = bzip2.NewReader(f)
	default:
		return fmt.Errorf("extract: unsupported compression %s", compression)
	}

	return extractTAR(ctx, node, filePath, reader, workDir, limits, stats, cfg)
}

// extract7z extracts CAB, MSI, 7z, or RAR files using 7-Zip via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
func extract7z(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits) error {
	// Check if 7zz is available.
	if !isToolAvailable("7zz") {
		node.Status = StatusToolMissing
		node.StatusDetail = "7zz (7-Zip) is not installed; cannot extract " + node.Format.Format.String()
		node.Tool = "7zz"
		return nil
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-7z-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = "7zz"
	node.SandboxUsed = sb.Name()

	args := []string{"x", filePath, "-o" + outDir, "-y"}
	if err := sb.Run(ctx, "7zz", args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("7zz extraction failed: %v", err)
		return nil
	}

	return finalizeExternalExtraction(node, outDir, limits)
}

// extractUnshield extracts InstallShield CABs using unshield via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
func extractUnshield(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits) error {
	if !isToolAvailable("unshield") {
		node.Status = StatusToolMissing
		node.StatusDetail = "unshield is not installed; cannot extract InstallShield CAB"
		node.Tool = "unshield"
		return nil
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-unshield-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = "unshield"
	node.SandboxUsed = sb.Name()

	args := []string{"-d", outDir, "x", filePath}
	if err := sb.Run(ctx, "unshield", args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("unshield extraction failed: %v", err)
		return nil
	}

	return finalizeExternalExtraction(node, outDir, limits)
}

// finalizeExternalExtraction validates and summarizes an output directory created
// by an external extractor before attaching it to the extraction tree.
func finalizeExternalExtraction(node *ExtractionNode, outDir string, limits config.Limits) error {
	if err := safeguard.ValidatePostExtraction(outDir, limits); err != nil {
		os.RemoveAll(outDir)
		return err
	}

	entriesCount, totalSize, err := summarizeExtractedDir(outDir)
	if err != nil {
		os.RemoveAll(outDir)
		return fmt.Errorf("extract: summarize external extraction output: %w", err)
	}

	node.ExtractedDir = outDir
	node.EntriesCount = entriesCount
	node.TotalSize = totalSize
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", entriesCount)

	return nil
}

// summarizeExtractedDir walks an extracted directory and returns the count and
// total size of regular files so external-tool extraction metrics match the
// in-process ZIP and TAR extractors.
func summarizeExtractedDir(outDir string) (int, int64, error) {
	entriesCount := 0
	totalSize := int64(0)

	err := filepath.Walk(outDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		entriesCount++
		totalSize += info.Size()
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return entriesCount, totalSize, nil
}

// isToolAvailable checks if an external tool is on the PATH.
func isToolAvailable(tool string) bool {
	_, err := lookPath(tool)
	return err == nil
}

// lookPath is a variable to enable testing.
var lookPath = execLookPath

func execLookPath(file string) (string, error) {
	return lookPathImpl(file)
}

func lookPathImpl(file string) (string, error) {
	path := os.Getenv("PATH")
	for _, dir := range strings.Split(path, string(os.PathListSeparator)) {
		full := filepath.Join(dir, file)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("executable file not found in $PATH: %s", file)
}

// CleanupNode removes all temporary directories created during extraction.
// It walks the tree and removes ExtractedDir for each node that was extracted.
// Call this after all processing (scan, assembly, report) is complete.
//
// Parameters:
//   - node: the root of the extraction tree to clean up
func CleanupNode(node *ExtractionNode) {
	if node == nil {
		return
	}
	if node.ExtractedDir != "" {
		os.RemoveAll(node.ExtractedDir)
	}
	for _, child := range node.Children {
		CleanupNode(child)
	}
}

// safeUint64ToInt64 converts uint64 to int64 with clamping to prevent overflow.
func safeUint64ToInt64(v uint64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if v > uint64(maxInt64) {
		return maxInt64
	}
	return int64(v)
}
