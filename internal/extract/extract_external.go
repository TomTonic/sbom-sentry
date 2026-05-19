package extract

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// sevenZipCandidates lists the binary names tried in priority order.
// 7zz is the official 7-Zip binary (package: 7zip on Debian/Ubuntu ≥22.04).
// 7za and 7z are provided by p7zip-full and are CLI-compatible for extraction.
var sevenZipCandidates = []string{"7zz", "7za", "7z"}

// lazily captured tool versions — populated on first successful use.
var (
	sevenZipVersionOnce  sync.Once
	sevenZipVersionValue string
	unshieldVersionOnce  sync.Once
	unshieldVersionValue string
)

// captureSevenZipVersion runs "binary i" once and stores the first non-empty
// line up to the " : " separator as the version identifier
// (e.g. "7-Zip (z) 26.01 (arm64)").
func captureSevenZipVersion(binary string) {
	sevenZipVersionOnce.Do(func() {
		out, err := exec.Command(binary, "i").Output() //nolint:gosec // binary is from a fixed candidate list
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if idx := strings.Index(line, " : "); idx != -1 {
				sevenZipVersionValue = line[:idx]
			} else {
				sevenZipVersionValue = line
			}
			return
		}
	})
}

// captureUnshieldVersion runs "unshield --version" once and stores the
// result up to (not including) the first period (e.g. "Unshield version 1.6.2").
func captureUnshieldVersion() {
	unshieldVersionOnce.Do(func() {
		out, err := exec.Command("unshield", "--version").Output() //nolint:gosec // fixed binary name
		if err != nil {
			return
		}
		s := strings.TrimSpace(string(out))
		// "Unshield version 1.6.2. MIT License..." — keep through the version number.
		if idx := strings.Index(s, ". "); idx != -1 {
			unshieldVersionValue = strings.TrimSpace(s[:idx])
		} else {
			unshieldVersionValue = s
		}
	})
}

// GetUsedSevenZipVersion returns the 7-Zip version string captured on first
// use, or an empty string if 7-Zip was never invoked during this run.
func GetUsedSevenZipVersion() string { return sevenZipVersionValue }

// GetUsedUnshieldVersion returns the unshield version string captured on first
// use, or an empty string if unshield was never invoked during this run.
func GetUsedUnshieldVersion() string { return unshieldVersionValue }

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
// After extraction, safeguard validates the materialized output tree for
// symlinks, special files, and resource limit violations. Path normalization
// is delegated to the extractor/sandbox boundary.
// password may be empty, in which case no -p flag is passed to 7-Zip.
func extract7z(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits, password string) error {
	binary, found := resolve7zBinary()
	if !found {
		node.Status = StatusToolMissing
		node.StatusDetail = "7zz (7-Zip) is not installed; cannot extract " + node.Format.Format.String()
		node.Tool = binary
		return nil
	}
	captureSevenZipVersion(binary)

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-7z-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = binary
	node.SandboxUsed = sb.Name()
	if meta := collect7zListMetadata(ctx, binary, filePath); meta != nil {
		node.ArchiveMeta = meta
	}

	args := []string{"x", filePath, "-o" + outDir, "-y"}
	if password != "" {
		args = append(args, "-p"+password)
	}
	if err := sb.Run(ctx, binary, args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = formatExtractionFailureDetail(binary, node, filePath, err)
		if ctx.Err() == context.DeadlineExceeded {
			return ctx.Err()
		}
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
// After extraction, safeguard validates the materialized output tree for
// symlinks, special files, and resource limit violations.
// passwords is the ordered list of candidate passwords to try; may be nil.
func extractUnshield(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits, passwords []string) error {
	if !isToolAvailable("unshield") {
		node.Status = StatusToolMissing
		node.StatusDetail = "unshield is not installed; cannot extract InstallShield CAB"
		node.Tool = "unshield"
		return nil
	}
	captureUnshieldVersion()

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
			if ctx.Err() == context.DeadlineExceeded {
				return ctx.Err()
			}
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

// extractSquashfs extracts a SquashFS image using unsquashfs when available,
// falling back to 7-Zip if unsquashfs is not installed.
func extractSquashfs(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits) error {
	if !isToolAvailable("unsquashfs") {
		// Fall back to 7z extraction.
		return extract7zWithPasswords(ctx, node, filePath, sb, workDir, limits, nil)
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-squashfs-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = "unsquashfs"
	node.SandboxUsed = sb.Name()
	args := []string{"-d", outDir, "-f", filePath}
	if err := sb.Run(ctx, "unsquashfs", args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("unsquashfs extraction failed: %v", err)
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

func formatExtractionFailureDetail(binary string, node *ExtractionNode, filePath string, err error) string {
	base := summarizeToolError(err)
	detail := ""
	if base != "" {
		detail = fmt.Sprintf("%s extraction failed: %s", binary, base)
	}

	lower := strings.ToLower(base)
	switch {
	case strings.Contains(lower, "invalid tar header"):
		detail += "; hint: file appears truncated/corrupt, or it is not a real TAR stream"
	case strings.Contains(lower, "can not open the file as archive"):
		detail += "; hint: file content does not match the detected archive format, or archive is damaged"
	case strings.Contains(lower, "wrong password") || strings.Contains(lower, "data error in encrypted file"):
		detail += "; hint: archive is encrypted; configure a matching password via --password"
	case strings.Contains(lower, "headers error") || strings.Contains(lower, "unconfirmed start of archive"):
		detail += "; hint: central directory/header structure is inconsistent (often truncated file or appended payload)"
	}

	if detail == "" {
		detail = fmt.Sprintf("%s extraction failed (%s)", binary, filepath.Base(filePath))
		if node.Format.Format != 0 {
			detail += ": detected=" + node.Format.Format.String()
		}
	}

	return detail
}

func summarizeToolError(err error) string {
	type parseSection int
	const (
		sectionGeneric parseSection = iota
		sectionErrors
		sectionWarnings
	)

	lines := strings.Split(err.Error(), "\n")
	errors := make([]string, 0, 3)
	warnings := make([]string, 0, 2)
	generic := make([]string, 0, 2)
	section := sectionGeneric

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Strip the sandbox stderr-prefix FIRST so that section headers
		// that appear on the first stderr line (e.g. "stderr: ERRORS:") are
		// still recognised by the switch below.
		if strings.HasPrefix(line, "stderr:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "stderr:"))
			if line == "" {
				continue
			}
		}
		switch line {
		case "ERRORS:":
			section = sectionErrors
			continue
		case "WARNINGS:":
			section = sectionWarnings
			continue
		case "--":
			continue
		}
		if isToolNoiseLine(line) {
			continue
		}

		switch section {
		case sectionErrors:
			errors = append(errors, line)
		case sectionWarnings:
			warnings = append(warnings, line)
		default:
			generic = append(generic, line)
		}
	}

	if len(errors) > 0 {
		parts := limitStrings(errors, 3)
		extra := len(errors) - len(parts)
		if len(warnings) > 0 {
			parts = append(parts, "warning: "+warnings[0])
		}
		result := strings.Join(parts, "; ")
		if extra > 0 {
			result += fmt.Sprintf("; [%d more error(s)]", extra)
		}
		return result
	}
	if len(generic) > 0 {
		// Return all captured non-noise lines so that unrecognised or
		// localised output variants never silently lose information.
		parts := limitStrings(generic, 3)
		extra := len(generic) - len(parts)
		if len(warnings) > 0 {
			parts = append(parts, "warning: "+warnings[0])
		}
		result := strings.Join(parts, "; ")
		if extra > 0 {
			result += fmt.Sprintf("; [%d more line(s)]", extra)
		}
		return result
	}
	if len(warnings) > 0 {
		parts := make([]string, 0, min(len(warnings), 2))
		for _, w := range limitStrings(warnings, 2) {
			parts = append(parts, "warning: "+w)
		}
		return strings.Join(parts, "; ")
	}
	return strings.TrimSpace(err.Error())
}

func isToolNoiseLine(line string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	if l == "" {
		return true
	}
	// The sandbox wrapper always prefixes its own error with "sandbox:"; that
	// line is noise.  The former "execution failed" substring check was
	// redundant (covered by the prefix) and too broad — it would also
	// accidentally filter real 7-Zip error messages containing those words.
	if strings.HasPrefix(l, "sandbox:") {
		return true
	}
	if strings.HasPrefix(l, "7-zip") || strings.HasPrefix(l, "scanning the drive") ||
		strings.HasPrefix(l, "extracting archive:") || strings.HasPrefix(l, "path =") ||
		strings.HasPrefix(l, "type =") || strings.HasPrefix(l, "physical size =") ||
		strings.HasPrefix(l, "headers size =") || strings.HasPrefix(l, "tail size =") ||
		strings.HasPrefix(l, "characteristics =") {
		return true
	}
	return false
}

func limitStrings(values []string, maxItems int) []string {
	if len(values) <= maxItems {
		return values
	}
	return values[:maxItems]
}

// collect7zListMetadata performs a best-effort `7zz l -slt` and extracts
// compact archive metadata for report rendering.
func collect7zListMetadata(ctx context.Context, binary string, filePath string) *ArchiveMetadata {
	cmd := exec.CommandContext(ctx, binary, "l", "-slt", filePath) //nolint:gosec // G204: binary is resolved from fixed 7-Zip candidate names.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	meta := &ArchiveMetadata{}
	methods := map[string]struct{}{}
	inHeader := true

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "----------") {
			inHeader = false
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if inHeader {
			switch key {
			case "Type":
				meta.Type = val
			case "Physical Size":
				meta.PhysicalSize = val
			case "Headers Size":
				meta.HeadersSize = val
			case "Solid":
				meta.Solid = val
			case "Blocks":
				meta.Blocks = val
			}
		}

		switch key {
		case "Method":
			if val != "" {
				methods[val] = struct{}{}
			}
		case "Encrypted":
			if val == "+" || strings.EqualFold(val, "true") {
				meta.HasEncryptedItem = true
			}
		}
	}

	_ = cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return nil
	}

	if len(methods) > 0 {
		meta.Methods = make([]string, 0, len(methods))
		for m := range methods {
			meta.Methods = append(meta.Methods, m)
		}
		sort.Strings(meta.Methods)
	}

	if meta.Type == "" && len(meta.Methods) == 0 && meta.PhysicalSize == "" && meta.HeadersSize == "" &&
		meta.Solid == "" && meta.Blocks == "" && !meta.HasEncryptedItem {
		return nil
	}
	return meta
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
		if info, err := os.Stat(full); err == nil && info.Mode().IsRegular() && (info.Mode()&0o111) != 0 {
			return full, nil
		}
	}
	return "", fmt.Errorf("executable file not found in $PATH: %s", file)
}
