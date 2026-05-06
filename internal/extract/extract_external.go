package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// sevenZipCandidates lists the binary names tried in priority order.
// 7zz is the official 7-Zip binary (package: 7zip on Debian/Ubuntu ≥22.04).
// 7za and 7z are provided by p7zip-full and are CLI-compatible for extraction.
var sevenZipCandidates = []string{"7zz", "7za", "7z"}

// resolve7zBinary returns the first available 7-Zip binary name and true,
// or ("7zz", false) if none is found (7zz is used as the canonical name in
// tool-missing diagnostics).
func resolve7zBinary() (string, bool) {
	for _, name := range sevenZipCandidates {
		if _, err := lookPath(name); err == nil {
			return name, true
		}
	}
	return "7zz", false
}

// extract7z extracts CAB, MSI, 7z, RAR files using 7-Zip via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
// password may be empty, in which case no -p flag is passed to 7-Zip.
func extract7z(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits, password string) error {
	binary, found := resolve7zBinary()
	if !found {
		node.Status = StatusToolMissing
		node.StatusDetail = "7zz (7-Zip) is not installed; cannot extract " + node.Format.Format.String()
		node.Tool = binary
		return nil
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-7z-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = binary
	node.SandboxUsed = sb.Name()

	args := []string{"x", filePath, "-o" + outDir, "-y"}
	if password != "" {
		args = append(args, "-p"+password)
	}
	if err := sb.Run(ctx, binary, args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("%s extraction failed: %v", binary, err)
		return nil
	}

	return finalizeExternalExtraction(node, outDir, limits)
}

// extract7zWithPasswords extracts an archive via 7-Zip, trying each supplied
// password in order until extraction succeeds.
//
// The empty string (no password) is always tried first, before any entries in
// passwords. This means non-encrypted archives succeed on the first attempt
// without any special-casing in the caller.
//
// If the archive is encrypted and no password matches, the node status is set
// to StatusFailed with a clear message and the function returns nil (not a
// hard error — the failure is captured in the node and surfaced in the report).
//
// Parameters:
//   - ctx: context for cancellation
//   - node: extraction node whose status will be updated
//   - filePath: absolute path to the archive file
//   - sb: sandbox for external tool execution
//   - workDir: base directory for temporary extraction directories
//   - limits: resource limits for post-extraction validation
//   - passwords: candidate passwords to try (in order); may be nil or empty
func extract7zWithPasswords(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits, passwords []string) error {
	// Build the full candidate list: no-password attempt first, then supplied
	// passwords. Using a sentinel value rather than an empty string lets us
	// distinguish "no -p flag" from "explicit empty password".
	type attempt struct {
		password string
		useFlag  bool // false → omit -p entirely
	}
	candidates := []attempt{{password: "", useFlag: false}}
	for _, pw := range passwords {
		candidates = append(candidates, attempt{password: pw, useFlag: true})
	}

	for i, cand := range candidates {
		// Reset mutable node fields before each attempt so a previous failure
		// does not pollute the next attempt's state.
		node.Status = StatusPending
		node.Tool = ""
		node.SandboxUsed = ""
		node.ExtractedDir = ""
		node.EntriesCount = 0
		node.TotalSize = 0
		node.StatusDetail = ""

		pw := ""
		if cand.useFlag {
			pw = cand.password
		}

		if err := extract7z(ctx, node, filePath, sb, workDir, limits, pw); err != nil {
			// Hard infrastructure error (e.g. temp dir creation) — propagate.
			return err
		}

		if node.Status == StatusExtracted {
			// Success.
			if cand.useFlag {
				node.StatusDetail += fmt.Sprintf(" (password index %d matched)", i)
			}
			return nil
		}

		if node.Status == StatusToolMissing {
			// Tool not available — no point trying further passwords.
			return nil
		}

		// StatusFailed: clean up the output dir (already done by extract7z on
		// failure) and try the next candidate.
	}

	// All candidates exhausted. If we tried at least one password (beyond the
	// no-password attempt), emit a clear "no matching password" message.
	// If only the no-password attempt was made (no passwords were configured),
	// the StatusDetail already carries the raw 7-Zip or sandbox error — keep it
	// so sandbox-denial and tool-crash errors are not masked.
	if len(candidates) > 1 {
		node.Status = StatusFailed
		node.StatusDetail = "encrypted archive: extraction failed (no matching password found)"
	}
	return nil
}

// extractUnshield extracts InstallShield CABs using unshield via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
// passwords is the ordered list of candidate passwords to try; may be nil.
func extractUnshield(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits, passwords []string) error {
	if !isToolAvailable("unshield") {
		node.Status = StatusToolMissing
		node.StatusDetail = "unshield is not installed; cannot extract InstallShield CAB"
		node.Tool = "unshield"
		return nil
	}

	// Build candidate list: no-password first, then each supplied password.
	type attempt struct {
		password string
		useFlag  bool
	}
	candidates := []attempt{{password: "", useFlag: false}}
	for _, pw := range passwords {
		candidates = append(candidates, attempt{password: pw, useFlag: true})
	}

	for i, cand := range candidates {
		node.Status = StatusPending
		node.Tool = ""
		node.SandboxUsed = ""
		node.ExtractedDir = ""
		node.EntriesCount = 0
		node.TotalSize = 0
		node.StatusDetail = ""

		outDir, err := os.MkdirTemp(workDir, "extract-sbom-unshield-*")
		if err != nil {
			return fmt.Errorf("extract: create temp dir: %w", err)
		}

		node.Tool = "unshield"
		node.SandboxUsed = sb.Name()

		args := []string{"-d", outDir, "x", filePath}
		if cand.useFlag && cand.password != "" {
			args = append(args, "-P", cand.password)
		}

		if runErr := sb.Run(ctx, "unshield", args, filePath, outDir); runErr != nil {
			os.RemoveAll(outDir)
			node.Status = StatusFailed
			node.StatusDetail = fmt.Sprintf("unshield extraction failed: %v", runErr)
			continue // try next password
		}

		if finalErr := finalizeExternalExtraction(node, outDir, limits); finalErr != nil {
			return finalErr
		}

		if node.Status == StatusExtracted {
			if cand.useFlag {
				node.StatusDetail += fmt.Sprintf(" (password index %d matched)", i)
			}
			return nil
		}
	}

	if node.Status != StatusExtracted {
		node.Status = StatusFailed
		if len(passwords) > 0 {
			node.StatusDetail = "encrypted archive: extraction failed (no matching password found)"
		}
	}
	return nil
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

// isToolAvailable checks whether an external tool can be resolved from PATH.
func isToolAvailable(tool string) bool {
	_, err := lookPath(tool)
	return err == nil
}

// IsToolAvailable exposes tool availability checks for other modules.
func IsToolAvailable(tool string) bool {
	return isToolAvailable(tool)
}

// Resolve7zBinary returns the first available 7-Zip binary name and true,
// or ("7zz", false) if none of the known candidates (7zz, 7za, 7z) is found.
func Resolve7zBinary() (string, bool) {
	return resolve7zBinary()
}

// lookPath is injected in tests to simulate tool presence.
var lookPath = execLookPath

// execLookPath delegates to lookPathImpl to keep a test-swappable boundary.
func execLookPath(file string) (string, error) {
	return lookPathImpl(file)
}

// lookPathImpl performs a minimal PATH search without shelling out.
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
