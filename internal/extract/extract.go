package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // stable short directory keys only
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sbom-sentry/internal/config"
	"sbom-sentry/internal/identify"
	"sbom-sentry/internal/safeguard"
	"sbom-sentry/internal/sandbox"
)

// ExtractionStatus represents the processing outcome for one node.
type ExtractionStatus string

const (
	// SyftNative indicates the file is scanned directly by Syft/native scanner.
	SyftNative ExtractionStatus = "SyftNative"
	// Extracted indicates the archive was extracted successfully.
	Extracted ExtractionStatus = "Extracted"
	// Skipped indicates extraction was intentionally skipped.
	Skipped ExtractionStatus = "Skipped"
	// Failed indicates extraction failed due to a non-hard-security error.
	Failed ExtractionStatus = "Failed"
	// SecurityBlocked indicates extraction was blocked by hard security validation.
	SecurityBlocked ExtractionStatus = "SecurityBlocked"
	// Plain indicates a non-container leaf artifact.
	Plain ExtractionStatus = "Plain"
)

// ExtractionNode is the recursive processing tree node for one container artifact.
type ExtractionNode struct {
	Path         string
	OriginalPath string
	Format       identify.FormatInfo
	Status       ExtractionStatus
	StatusDetail string
	ExtractedDir string
	Children     []*ExtractionNode
	Metadata     *ContainerMetadata
	Tool         string
	SandboxUsed  string
	Duration     time.Duration
	EntriesCount int
	TotalSize    int64
}

// ContainerMetadata stores structured metadata from metadata-bearing containers.
type ContainerMetadata struct {
	ProductName    string
	Manufacturer   string
	ProductVersion string
	ProductCode    string
	UpgradeCode    string
	Language       string
}

// Extract recursively processes inputPath and returns the extraction tree root.
// The returned tree is the central source-of-truth for later scanning and reporting.
func Extract(ctx context.Context, inputPath string, cfg config.Config, sbox sandbox.Sandbox) (*ExtractionNode, error) {
	workDir := cfg.WorkDir
	if workDir == "" {
		workDir = cfg.OutputDir
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	absInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve input path: %w", err)
	}
	rootRel := filepath.Base(absInput)

	node, err := processFile(ctx, absInput, toSlash(rootRel), 0, cfg, sbox, workDir)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func processFile(ctx context.Context, absPath string, relPath string, depth int, cfg config.Config, sbox sandbox.Sandbox, workDir string) (*ExtractionNode, error) {
	start := time.Now()
	info, err := identify.Identify(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("identify %s: %w", relPath, err)
	}

	node := &ExtractionNode{
		Path:         relPath,
		OriginalPath: absPath,
		Format:       info,
	}

	if info.Format == identify.FormatMSI {
		if md, mdErr := extractMSIMetadata(absPath); mdErr == nil {
			node.Metadata = md
		}
	}

	defer func() {
		node.Duration = time.Since(start)
	}()

	if info.SyftNative {
		node.Status = SyftNative
		node.Tool = "syft"
		return node, nil
	}

	if !isContainerFormat(info.Format) {
		node.Status = Plain
		node.StatusDetail = "non-container leaf"
		return node, nil
	}

	if depth >= cfg.Limits.MaxDepth {
		node.Status = Skipped
		node.StatusDetail = "maximum extraction depth reached"
		return node, nil
	}

	if !info.Extractable {
		node.Status = Skipped
		node.StatusDetail = "format recognized but not extractable in this build"
		return node, nil
	}

	extractDir := filepath.Join(workDir, "extract-"+stableDirKey(relPath))
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return nil, fmt.Errorf("create extraction dir: %w", err)
	}

	stats := &safeguard.ExtractionStats{}
	node.ExtractedDir = extractDir

	switch info.Format {
	case identify.FormatZIP:
		node.Tool = "archive/zip"
		err = extractZIP(absPath, extractDir, cfg.Limits, stats)
	case identify.FormatTAR, identify.FormatGzipTAR, identify.FormatBzip2TAR:
		node.Tool = "archive/tar"
		err = extractTAR(absPath, extractDir, info.Format, cfg.Limits, stats)
	case identify.FormatCAB, identify.FormatMSI, identify.FormatSevenZip, identify.FormatRAR:
		node.Tool = "7zz"
		node.SandboxUsed = sbox.Name()
		err = extractWith7Zip(ctx, absPath, extractDir, sbox)
	case identify.FormatInstallShieldCAB:
		node.Tool = "unshield"
		node.SandboxUsed = sbox.Name()
		err = extractWithUnshield(ctx, absPath, extractDir, sbox)
	default:
		node.Status = Skipped
		node.StatusDetail = "unsupported container format"
		return node, nil
	}

	if err != nil {
		var hard *safeguard.HardSecurityError
		if errors.As(err, &hard) {
			node.Status = SecurityBlocked
			node.StatusDetail = err.Error()
			return node, nil
		}
		node.Status = Failed
		node.StatusDetail = err.Error()
		return node, nil
	}

	node.Status = Extracted
	node.EntriesCount = stats.Files
	node.TotalSize = stats.TotalSize

	children, err := collectChildFiles(extractDir)
	if err != nil {
		node.Status = Failed
		node.StatusDetail = fmt.Sprintf("walk extracted files: %v", err)
		return node, nil
	}

	for _, childAbs := range children {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		localRel, relErr := filepath.Rel(extractDir, childAbs)
		if relErr != nil {
			continue
		}
		childRel := toSlash(filepath.Join(relPath, localRel))
		childNode, childErr := processFile(ctx, childAbs, childRel, depth+1, cfg, sbox, workDir)
		if childErr != nil {
			return nil, childErr
		}
		node.Children = append(node.Children, childNode)
	}

	return node, nil
}

func isContainerFormat(format identify.Format) bool {
	switch format {
	case identify.FormatZIP,
		identify.FormatTAR,
		identify.FormatGzipTAR,
		identify.FormatBzip2TAR,
		identify.FormatXzTAR,
		identify.FormatZstdTAR,
		identify.FormatCAB,
		identify.FormatInstallShieldCAB,
		identify.FormatMSI,
		identify.FormatSevenZip,
		identify.FormatRAR:
		return true
	default:
		return false
	}
}

func extractZIP(inputPath string, outputDir string, limits config.Limits, stats *safeguard.ExtractionStats) error {
	r, err := zip.OpenReader(inputPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		h := safeguard.EntryHeader{
			Name:             f.Name,
			Mode:             uint32(f.Mode()),
			CompressedSize:   int64(f.CompressedSize64),
			UncompressedSize: int64(f.UncompressedSize64),
			IsDir:            f.FileInfo().IsDir(),
			IsSymlink:        f.Mode()&os.ModeSymlink != 0,
		}
		if err := safeguard.ValidatePath(f.Name, outputDir); err != nil {
			return err
		}
		if err := safeguard.ValidateEntry(h, limits, stats); err != nil {
			return err
		}

		target := filepath.Join(outputDir, filepath.Clean(strings.ReplaceAll(f.Name, "\\", "/")))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("mkdir extracted dir: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("mkdir extracted parent: %w", err)
		}

		src, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip member: %w", err)
		}

		if err := writeRegularFile(target, src, f.Mode(), h.UncompressedSize); err != nil {
			src.Close()
			return err
		}
		if err := src.Close(); err != nil {
			return fmt.Errorf("close zip member: %w", err)
		}
	}

	return nil
}

func extractTAR(inputPath string, outputDir string, format identify.Format, limits config.Limits, stats *safeguard.ExtractionStats) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open tar input: %w", err)
	}
	defer f.Close()

	var r io.Reader = f
	switch format {
	case identify.FormatTAR:
		// No additional wrapper.
	case identify.FormatGzipTAR:
		gz, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			return fmt.Errorf("open gzip stream: %w", gzErr)
		}
		defer gz.Close()
		r = gz
	case identify.FormatBzip2TAR:
		r = bzip2.NewReader(f)
	case identify.FormatXzTAR, identify.FormatZstdTAR:
		return errors.New("xz/zstd tar extraction requires optional decompressors")
	default:
		return fmt.Errorf("unsupported tar variant: %s", format)
	}

	tr := tar.NewReader(r)
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read tar header: %w", nextErr)
		}

		h := safeguard.EntryHeader{
			Name:             hdr.Name,
			Mode:             uint32(hdr.Mode),
			CompressedSize:   -1,
			UncompressedSize: hdr.Size,
			IsDir:            hdr.FileInfo().IsDir(),
			IsSymlink:        hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink,
		}
		if err := safeguard.ValidatePath(hdr.Name, outputDir); err != nil {
			return err
		}
		if err := safeguard.ValidateEntry(h, limits, stats); err != nil {
			return err
		}

		target := filepath.Join(outputDir, filepath.Clean(strings.ReplaceAll(hdr.Name, "\\", "/")))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("mkdir tar dir: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("mkdir tar parent: %w", err)
			}
			if err := writeRegularFile(target, tr, os.FileMode(hdr.Mode), hdr.Size); err != nil {
				return err
			}
		default:
			return &safeguard.HardSecurityError{Violation: "special tar entry blocked", Path: hdr.Name}
		}
	}

	return nil
}

func extractWith7Zip(ctx context.Context, inputPath string, outputDir string, sbox sandbox.Sandbox) error {
	if _, err := os.Stat(inputPath); err != nil {
		return fmt.Errorf("stat input for 7zz extraction: %w", err)
	}

	if _, err := os.Stat(outputDir); err != nil {
		return fmt.Errorf("stat output dir for 7zz extraction: %w", err)
	}

	if _, err := exec.LookPath("7zz"); err != nil {
		return fmt.Errorf("7zz unavailable: %w", err)
	}

	args := []string{"x", "{input}", "-o{output}", "-y"}
	if err := sbox.Run(ctx, "7zz", args, inputPath, outputDir); err != nil {
		return err
	}
	return nil
}

func extractWithUnshield(ctx context.Context, inputPath string, outputDir string, sbox sandbox.Sandbox) error {
	if _, err := exec.LookPath("unshield"); err != nil {
		return fmt.Errorf("unshield unavailable: %w", err)
	}

	args := []string{"x", "-d", "{output}", "{input}"}
	if err := sbox.Run(ctx, "unshield", args, inputPath, outputDir); err != nil {
		return err
	}
	return nil
}

func collectChildFiles(root string) ([]string, error) {
	out := make([]string, 0, 64)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func writeRegularFile(target string, r io.Reader, mode os.FileMode, size int64) error {
	if mode&os.ModeType != 0 {
		return &safeguard.HardSecurityError{Violation: "special file mode blocked", Path: target}
	}

	perm := mode.Perm()
	if perm == 0 {
		perm = 0o640
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	written, err := io.Copy(f, r)
	if err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	if size >= 0 && written != size {
		return fmt.Errorf("copied size mismatch for %s: wrote %d expected %d", target, written, size)
	}
	return nil
}

func stableDirKey(relPath string) string {
	h := sha1.Sum([]byte(relPath))
	return fmt.Sprintf("%x", h[:8])
}

func toSlash(path string) string {
	return strings.ReplaceAll(path, string(filepath.Separator), "/")
}

func extractMSIMetadata(_ string) (*ContainerMetadata, error) {
	return nil, nil
}
