package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

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

	if err := extractRecursive(ctx, root, inputPath, baseName, 0, cfg, sb); err != nil {
		// If we have a tree at all, return it with the error info.
		return root, err
	}

	return root, nil
}

// extractRecursive processes exactly one artifact node and, when extraction
// succeeds, descends into its extracted directory.
//
// Why this exists:
// It centralizes status assignment order (syft-native, extracted, skipped,
// failed, security-blocked, tool-missing) so behavior is consistent with
// DESIGN.md and SCAN_APPROACH.md semantics.
//
// Constraints:
// - depth limit is enforced before format handling
// - hard security errors are propagated (policy may decide continuation)
// - per-extraction timeout applies to one archive operation
func extractRecursive(ctx context.Context, node *ExtractionNode, filePath string, deliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox) error {
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

	info, err := identify.Identify(ctx, filePath)
	if err != nil {
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("format identification failed: %v", err)
		return nil
	}
	node.Format = info

	if isSkippedExtension(filePath, cfg.SkipExtensions) {
		ext := strings.ToLower(filepath.Ext(filePath))
		node.Status = StatusSkipped
		node.StatusDetail = "extension filter: " + ext + " is excluded from extraction"
		return nil
	}

	if info.SyftNative {
		node.Status = StatusSyftNative
		node.Tool = "syft"
		node.StatusDetail = fmt.Sprintf("Syft-native format (%s), passed directly to Syft", info.Format)
		return nil
	}

	if info.Format == identify.Unknown {
		node.Status = StatusSkipped
		node.StatusDetail = "not a recognized container format"
		return nil
	}

	start := time.Now()

	extractCtx := ctx
	if cfg.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		extractCtx, cancel = context.WithTimeout(ctx, cfg.Limits.Timeout)
		defer cancel()
	}

	switch info.Format {
	case identify.ZIP, identify.TAR:
		err = extract7zWithPasswords(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords)
	case identify.GzipTAR, identify.Bzip2TAR, identify.XzTAR, identify.ZstdTAR:
		err = extract7zWithPasswords(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords)
		// 7-Zip decompresses .tar.gz / .tgz / .tar.bz2 / .tar.xz / .tar.zst to a
		// single intermediate .tar file rather than extracting the tar contents
		// directly. Flatten that extra level so that the delivery-path hierarchy
		// mirrors the logical archive structure (e.g. foo.tar.gz/file.txt instead
		// of foo.tar.gz/foo.tar/file.txt).
		if err == nil && node.Status == StatusExtracted {
			if flatErr := flattenCompressedTAR(extractCtx, node, sb, cfg); flatErr != nil {
				return flatErr
			}
		}
	case identify.CAB, identify.SevenZip, identify.RAR:
		err = extract7zWithPasswords(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords)
	case identify.MSI:
		if meta, msiErr := ReadMSIMetadata(filePath, cfg.Limits.MaxEntrySize); msiErr == nil {
			node.Metadata = meta
		}
		if cfg.InterpretMode == config.InterpretInstallerSemantic && node.Metadata != nil {
			node.InstallerHint = "msi-file-table-remapping-available"
		}
		err = extract7zWithPasswords(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords)
	case identify.InstallShieldCAB:
		err = extractUnshield(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords)
	default:
		node.Status = StatusSkipped
		node.StatusDetail = fmt.Sprintf("no extraction handler for format %s", info.Format)
		return nil
	}

	node.Duration = time.Since(start)

	if err != nil {
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
		if _, ok := err.(*safeguard.HardSecurityError); ok {
			node.Status = StatusSecurityBlocked
			node.StatusDetail = err.Error()
			return err
		}
		if _, ok := err.(*safeguard.ResourceLimitError); ok {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
			return err
		}
		if node.Status == StatusPending {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
		}
		return nil
	}

	if node.ExtractedDir != "" {
		if walkErr := recurseIntoDir(ctx, node, node.ExtractedDir, deliveryPath, depth+1, cfg, sb); walkErr != nil {
			return walkErr
		}
	}

	return nil
}

// recurseIntoDir enumerates extracted files and attaches child container nodes
// to the current parent node.
//
// Why this exists:
// It enforces policy behavior (strict vs partial) for resource/security errors
// at child level while keeping an auditable tree of encountered artifacts.
func recurseIntoDir(ctx context.Context, parent *ExtractionNode, dir string, parentDeliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("extract: read dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDir := filepath.Join(dir, entry.Name())
			if walkErr := recurseIntoDir(ctx, parent, subDir, parentDeliveryPath+"/"+entry.Name(), depth, cfg, sb); walkErr != nil {
				return walkErr
			}
			continue
		}

		childPath := filepath.Join(dir, entry.Name())
		childDeliveryPath := parentDeliveryPath + "/" + entry.Name()

		child := &ExtractionNode{Path: childDeliveryPath, OriginalPath: childPath}

		if err := extractRecursive(ctx, child, childPath, childDeliveryPath, depth, cfg, sb); err != nil {
			if _, ok := err.(*safeguard.HardSecurityError); ok {
				child.Status = StatusSecurityBlocked
				child.StatusDetail = err.Error()
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

		if child.Status == StatusSkipped && strings.HasPrefix(child.StatusDetail, "extension filter:") {
			parent.ExtensionFilteredPaths = append(parent.ExtensionFilteredPaths, child.Path)
			continue
		}

		if child.Status != StatusSkipped || len(child.Children) > 0 {
			parent.Children = append(parent.Children, child)
		}
	}

	return nil
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

// isSkippedExtension reports whether filePath ends with an extension present
// in skipList. Matching is case-insensitive.
func isSkippedExtension(filePath string, skipList []string) bool {
	if len(skipList) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return false
	}
	for _, s := range skipList {
		if strings.EqualFold(s, ext) {
			return true
		}
	}
	return false
}

// flattenCompressedTAR unwraps the intermediate .tar file that 7-Zip produces
// when decompressing a compressed TAR archive (.tar.gz, .tgz, .tar.bz2, etc.).
//
// 7-Zip treats a compressed TAR as two separate layers: it decompresses the
// outer compression wrapper first (producing a .tar file), then requires a
// second extraction pass to unpack the .tar contents. Without flattening, this
// would add an extra level to every delivery path
// (e.g. foo.tar.gz/foo.tar/lib/file.jar instead of foo.tar.gz/lib/file.jar).
//
// Flattening is applied only when the extraction produced exactly one file and
// that file has a .tar extension. If the inner .tar extraction fails, the outer
// extraction result is kept as-is.
func flattenCompressedTAR(ctx context.Context, node *ExtractionNode, sb sandbox.Sandbox, cfg config.Config) error {
	entries, err := os.ReadDir(node.ExtractedDir)
	if err != nil || len(entries) != 1 || entries[0].IsDir() {
		return nil
	}
	name := entries[0].Name()
	if !strings.HasSuffix(strings.ToLower(name), ".tar") {
		return nil
	}

	tarPath := filepath.Join(node.ExtractedDir, name)
	oldDir := node.ExtractedDir

	innerNode := &ExtractionNode{Path: node.Path}
	if extractErr := extract7zWithPasswords(ctx, innerNode, tarPath, sb, cfg.WorkDir, cfg.Limits, cfg.Passwords); extractErr != nil {
		return extractErr
	}

	if innerNode.Status != StatusExtracted {
		// Inner .tar extraction failed; keep the outer result unchanged.
		return nil
	}

	// Adopt the inner extraction dir and counts; discard the intermediate dir.
	os.RemoveAll(oldDir)
	node.ExtractedDir = innerNode.ExtractedDir
	node.EntriesCount = innerNode.EntriesCount
	node.TotalSize = innerNode.TotalSize
	return nil
}
