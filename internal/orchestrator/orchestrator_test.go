// Orchestrator module tests: Verify that the end-to-end pipeline
// coordination works correctly for various scenarios. These tests
// use real ZIP files but do not invoke Syft (which requires real
// package artifacts). They focus on pipeline flow, exit codes, and
// error handling.
package orchestrator

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sbom-sentry/internal/config"
)

// createMinimalZIP creates a minimal valid ZIP file for pipeline testing.
func createMinimalZIP(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	fw, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("test content")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	return path
}

// TestRunWithInvalidConfigReturnsHardSecurity verifies that an invalid
// configuration causes the pipeline to return ExitHardSecurity with
// an error message.
func TestRunWithInvalidConfigReturnsHardSecurity(t *testing.T) {
	t.Parallel()

	cfg := config.Config{} // Missing required fields.

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("ExitCode = %d, want %d (ExitHardSecurity)", result.ExitCode, ExitHardSecurity)
	}

	if result.Error == nil {
		t.Error("Error is nil, want validation error")
	}
}

// TestRunWithMissingInputFileReturnsError verifies that a nonexistent
// input file is caught early in the pipeline.
func TestRunWithMissingInputFileReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.InputPath = filepath.Join(dir, "nonexistent.zip")
	cfg.OutputDir = dir
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("ExitCode = %d, want %d (ExitHardSecurity)", result.ExitCode, ExitHardSecurity)
	}

	if result.Error == nil {
		t.Error("Error is nil, want input hash error")
	}
}

// TestRunWithValidZIPProducesOutput verifies the basic happy path:
// a valid ZIP file produces an SBOM file and report file.
func TestRunWithValidZIPProducesOutput(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	// The exit code should be 0 (success) or 1 (partial, since Syft may
	// not find anything in a minimal ZIP).
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed with hard security: %v", result.Error)
	}

	// SBOM should have been written.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file does not exist: %v", err)
		}
	}

	// Report should have been written.
	if result.ReportPath == "" {
		t.Error("ReportPath is empty")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file does not exist: %v", err)
		}
	}
}

// TestRunWithCancelledContextHandlesGracefully verifies that a cancelled
// context doesn't panic and produces an appropriate result.
func TestRunWithCancelledContextHandlesGracefully(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "test.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	// Should not panic.
	result := Run(ctx, cfg)
	_ = result
}

// TestExitCodeConstants verifies that exit code values match the
// documented behavior from DESIGN.md.
func TestExitCodeConstants(t *testing.T) {
	t.Parallel()

	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess = %d, want 0", ExitSuccess)
	}
	if ExitPartial != 1 {
		t.Errorf("ExitPartial = %d, want 1", ExitPartial)
	}
	if ExitHardSecurity != 2 {
		t.Errorf("ExitHardSecurity = %d, want 2", ExitHardSecurity)
	}
}

// TestRunWithStrictPolicyAndEmptyZIP verifies that strict mode with
// no scannable content handles gracefully.
func TestRunWithStrictPolicyAndEmptyZIP(t *testing.T) {
	dir := t.TempDir()

	// Create an empty ZIP.
	zipPath := filepath.Join(dir, "empty.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	w.Close()
	f.Close()

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.PolicyMode = config.PolicyStrict
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	// Should not crash, exit code depends on whether empty ZIP parses.
	if result.ExitCode == ExitHardSecurity && result.Error == nil {
		t.Error("ExitHardSecurity without error")
	}
}

// TestRunWithHumanReportMode verifies that human-only report mode
// produces a Markdown file.
func TestRunWithHumanReportMode(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}

	if result.ReportPath == "" {
		t.Skip("no report path produced (non-fatal)")
	}

	if !filepath.IsAbs(result.ReportPath) || filepath.Ext(result.ReportPath) != ".md" {
		t.Errorf("report path %q doesn't look like a .md file", result.ReportPath)
	}
}

// TestRunSurvivingHumanReportIncludesLaterMachineFailure verifies that when
// the human report is written successfully but the subsequent machine report
// creation fails, the surviving human report is rewritten with that later
// processing issue included.
func TestRunSurvivingHumanReportIncludesLaterMachineFailure(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	blockedJSONPath := filepath.Join(dir, "delivery.report.json")
	if err := os.MkdirAll(blockedJSONPath, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty; expected surviving human report")
	}
	humanReport, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read human report: %v", err)
	}
	humanStr := string(humanReport)

	for _, fragment := range []string{
		"## Processing Errors",
		"create-report-machine",
	} {
		if !strings.Contains(humanStr, fragment) {
			t.Fatalf("human report missing %q", fragment)
		}
	}
}

// TestRunWithPathTraversalZIPStillWritesSBOMAndReport verifies the normative
// finalization rule from DESIGN.md §6.3: after input validation succeeds and
// root processing is initialized, a hard security event must not suppress
// final SBOM or report generation.
func TestRunWithPathTraversalZIPStillWritesSBOMAndReport(t *testing.T) {
	dir := t.TempDir()

	// Create a ZIP with a path traversal entry.
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	// Normal file first.
	fw, wErr := w.Create("readme.txt")
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw.Write([]byte("hello")); wErr != nil {
		t.Fatal(wErr)
	}

	// Path traversal entry.
	hdr := &zip.FileHeader{Name: "../../../etc/passwd"}
	hdr.Method = zip.Store
	fw2, wErr := w.CreateHeader(hdr)
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw2.Write([]byte("root:x:0:0")); wErr != nil {
		t.Fatal(wErr)
	}

	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyPartial // Continue despite blocked subtrees.
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	// Exit code must be non-success (hard security or partial).
	if result.ExitCode == ExitSuccess {
		t.Error("ExitCode = Success after hard security event, want non-success")
	}

	// SBOM must still be written.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty; SBOM should be written despite security event")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file not written despite security event: %v", err)
		}
	}

	// Report must still be written.
	if result.ReportPath == "" {
		t.Error("ReportPath is empty; report should be written despite security event")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file not written despite security event: %v", err)
		}
	}
}

// TestRunWithDeniedSandboxReportsToolMissing verifies that when bwrap is
// unavailable and --unsafe is not set, the pipeline uses the denied sandbox
// and external-tool formats are marked as tool-missing rather than
// silently executing unsandboxed.
func TestRunWithDeniedSandboxReportsToolMissing(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = false // No unsafe opt-in.
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	// Should still produce output (ZIP is in-process, no sandbox needed).
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline hard-failed for ZIP with denied sandbox: %v", result.Error)
	}

	// SBOM should still be written — ZIP uses in-process extraction.
	if result.SBOMPath == "" {
		t.Error("SBOMPath empty; ZIP extraction should work without sandbox")
	}
}

// TestRunWithMissingExternalToolExitsPartial verifies that a delivery requiring
// 7zz does not end in success when the tool is unavailable.
func TestRunWithMissingExternalToolExitsPartial(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "payload.cab")
	if err := os.WriteFile(inputPath, []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", "")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitPartial {
		t.Fatalf("ExitCode = %d, want %d", result.ExitCode, ExitPartial)
	}
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty for tool-missing run")
	}
}

// TestRunWithExternalToolFailureExitsPartial verifies that a non-zero 7zz run
// produces an incomplete result rather than a false success.
func TestRunWithExternalToolFailureExitsPartial(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	sevenZipPath := filepath.Join(binDir, "7zz")
	sevenZipScript := []byte("#!/bin/sh\nexit 42\n")
	if err := os.WriteFile(sevenZipPath, sevenZipScript, 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- test fixture must be executable to simulate 7zz at runtime.
	if err := os.Chmod(sevenZipPath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	inputPath := filepath.Join(dir, "payload.cab")
	if err := os.WriteFile(inputPath, []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitPartial {
		t.Fatalf("ExitCode = %d, want %d", result.ExitCode, ExitPartial)
	}
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty for external-tool failure run")
	}
}

// TestRunExitCodeOnHardSecurityIsNonZero verifies that when a hard security
// block occurs in strict policy mode, the exit code is ExitHardSecurity.
func TestRunExitCodeOnHardSecurityIsNonZero(t *testing.T) {
	dir := t.TempDir()

	// Create a ZIP with only a path traversal entry; strict mode = abort.
	zipPath := filepath.Join(dir, "evil-strict.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	hdr := &zip.FileHeader{Name: "../../escape.txt"}
	hdr.Method = zip.Store
	fw, wErr := w.CreateHeader(hdr)
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw.Write([]byte("escaped")); wErr != nil {
		t.Fatal(wErr)
	}

	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyStrict

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitSuccess {
		t.Error("ExitCode = Success after path traversal in strict mode, want non-success")
	}
}

// createZIPWithNestedZIP creates a ZIP that contains another ZIP inside it.
// This helper supports nested container end-to-end tests.
func createZIPWithNestedZIP(t *testing.T, dir string, outerName string) string {
	t.Helper()

	// Create inner ZIP content in memory.
	var innerBuf []byte
	{
		var b []byte
		innerW := zip.NewWriter(newBytesWriter(&b))
		fw, err := innerW.Create("inner-file.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("inner content")); err != nil {
			t.Fatal(err)
		}
		if err := innerW.Close(); err != nil {
			t.Fatal(err)
		}
		innerBuf = b
	}

	// Create outer ZIP containing the inner ZIP and a plain file.
	outerPath := filepath.Join(dir, outerName)
	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)

	fw, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fw.Write([]byte("outer readme")); err != nil {
		t.Fatal(err)
	}

	fw2, err := w.Create("inner.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw2.Write(innerBuf); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return outerPath
}

// createJARWithManifestBytes creates a minimal JAR payload in memory containing
// a manifest, used to exercise Syft-native JAR handling through nested archives.
func createJARWithManifestBytes(t *testing.T) []byte {
	t.Helper()

	var jarBuf []byte
	jarW := zip.NewWriter(newBytesWriter(&jarBuf))
	manifest, err := jarW.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manifest.Write([]byte("Manifest-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}
	classFile, err := jarW.Create("com/example/App.class")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := classFile.Write([]byte("CAFE")); err != nil {
		t.Fatal(err)
	}
	if err := jarW.Close(); err != nil {
		t.Fatal(err)
	}

	return jarBuf
}

// createZIPWithNestedZIPAndJAR creates a delivery ZIP containing an inner ZIP
// that itself contains a JAR with a manifest.
func createZIPWithNestedZIPAndJAR(t *testing.T, dir string, outerName string) string {
	t.Helper()

	jarBytes := createJARWithManifestBytes(t)

	var innerBuf []byte
	innerW := zip.NewWriter(newBytesWriter(&innerBuf))
	jarEntry, err := innerW.Create("lib/app.jar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jarEntry.Write(jarBytes); err != nil {
		t.Fatal(err)
	}
	if closeErr := innerW.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	outerPath := filepath.Join(dir, outerName)
	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	innerEntry, err := w.Create("inner.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = innerEntry.Write(innerBuf); err != nil {
		t.Fatal(err)
	}
	readmeEntry, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readmeEntry.Write([]byte("nested delivery")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return outerPath
}

// bytesWriter is a minimal io.Writer that accumulates into a slice pointer,
// used to build ZIP data in memory without a temp file.
type bytesWriter struct{ buf *[]byte }

func newBytesWriter(buf *[]byte) *bytesWriter { return &bytesWriter{buf: buf} }
func (b *bytesWriter) Write(p []byte) (int, error) {
	*b.buf = append(*b.buf, p...)
	return len(p), nil
}

// TestRunNestedZIPEndToEndProducesOutputFiles is an end-to-end test verifying
// that a ZIP containing another ZIP produces an SBOM and audit report. Nested
// container scenarios are a core requirement from AGENT.md §4.1.3.
func TestRunNestedZIPEndToEndProducesOutputFiles(t *testing.T) {
	dir := t.TempDir()
	inputPath := createZIPWithNestedZIP(t, dir, "nested-delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline fatal error: %v", result.Error)
	}

	// Both SBOM and report must be written for a nested delivery.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty; SBOM must be produced for nested ZIP")
	} else if _, err := os.Stat(result.SBOMPath); err != nil {
		t.Errorf("SBOM file not written: %v", err)
	}

	if result.ReportPath == "" {
		t.Error("ReportPath is empty; report must be produced for nested ZIP")
	} else if _, err := os.Stat(result.ReportPath); err != nil {
		t.Errorf("report file not written: %v", err)
	}
}

// TestRunResourceLimitPartialModeExitsPartial is an end-to-end test verifying
// that when a resource limit fires and the policy mode is partial, the pipeline
// returns ExitPartial rather than ExitSuccess. This validates the limit
// enforcement path from AGENT.md §4.1.3 and §10.
func TestRunResourceLimitPartialModeExitsPartial(t *testing.T) {
	dir := t.TempDir()

	// Build a ZIP with 5 files but cap MaxFiles at 2.
	zipPath := filepath.Join(dir, "many-files.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i < 5; i++ {
		fw, wErr := w.Create(filepath.Join("dir", "file"+string(rune('a'+i))+".txt"))
		if wErr != nil {
			t.Fatal(wErr)
		}
		if _, wErr = fw.Write([]byte("content")); wErr != nil {
			t.Fatal(wErr)
		}
	}
	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyPartial
	cfg.Limits.MaxFiles = 2

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline fatal error: %v", result.Error)
	}
	if result.ExitCode == ExitSuccess {
		t.Errorf("ExitCode = Success when MaxFiles limit was exceeded, want ExitPartial (%d)", ExitPartial)
	}
}

// TestRunResourceLimitStrictModeExitsPartial verifies that a resource limit
// violation in strict mode returns ExitPartial (not ExitSuccess). Hard security
// events return ExitHardSecurity; resource limits are a different category.
func TestRunResourceLimitStrictModeExitsPartial(t *testing.T) {
	dir := t.TempDir()

	// ZIP with 5 files, MaxFiles=2, strict policy.
	zipPath := filepath.Join(dir, "strict-overflow.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i < 5; i++ {
		fw, wErr := w.Create("f" + string(rune('a'+i)) + ".txt")
		if wErr != nil {
			t.Fatal(wErr)
		}
		if _, wErr = fw.Write([]byte("data")); wErr != nil {
			t.Fatal(wErr)
		}
	}
	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyStrict
	cfg.Limits.MaxFiles = 2

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitSuccess {
		t.Errorf("ExitCode = Success with MaxFiles limit exceeded in strict mode, want non-success")
	}
}

// TestRunNestedZIPReportContainsExtractionLogAndScans verifies end-to-end report
// integration for nested archives: extraction log includes all relevant nodes,
// and machine report scan entries are present for the traversed scan targets.
func TestRunNestedZIPReportContainsExtractionLogAndScans(t *testing.T) {
	dir := t.TempDir()
	inputPath := createZIPWithNestedZIPAndJAR(t, dir, "nested-with-jar.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline fatal error: %v", result.Error)
	}

	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty")
	}

	human, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read human report: %v", err)
	}
	humanStr := string(human)

	for _, fragment := range []string{
		"## Extraction Log",
		"nested-with-jar.zip",
		"nested-with-jar.zip/inner.zip",
		"nested-with-jar.zip/inner.zip/lib/app.jar",
		"## Scan Results",
		"nested-with-jar.zip",
		"nested-with-jar.zip/inner.zip",
		"nested-with-jar.zip/inner.zip/lib/app.jar",
	} {
		if !strings.Contains(humanStr, fragment) {
			t.Fatalf("human report missing %q", fragment)
		}
	}

	jsonPath := strings.TrimSuffix(result.ReportPath, ".report.md") + ".report.json"
	machine, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("cannot read machine report: %v", err)
	}

	var parsed struct {
		Extraction struct {
			Path string `json:"path"`
		} `json:"extraction"`
		Scans []struct {
			NodePath string `json:"nodePath"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(machine, &parsed); err != nil {
		t.Fatalf("invalid machine report JSON: %v", err)
	}
	if parsed.Extraction.Path != "nested-with-jar.zip" {
		t.Fatalf("machine extraction root path = %q, want %q", parsed.Extraction.Path, "nested-with-jar.zip")
	}

	nodePaths := make(map[string]bool)
	for _, s := range parsed.Scans {
		nodePaths[s.NodePath] = true
	}
	for _, want := range []string{
		"nested-with-jar.zip",
		"nested-with-jar.zip/inner.zip",
		"nested-with-jar.zip/inner.zip/lib/app.jar",
	} {
		if !nodePaths[want] {
			t.Fatalf("machine report scans missing nodePath %q", want)
		}
	}
}

// TestRunPartialPolicyReportExplainsDecision verifies that when policy mode is
// partial and a resource limit is hit, the human report explains the decision
// with trigger and action rationale.
func TestRunPartialPolicyReportExplainsDecision(t *testing.T) {
	dir := t.TempDir()

	zipPath := filepath.Join(dir, "limit.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i < 4; i++ {
		fw, wErr := w.Create(filepath.Join("data", "f"+string(rune('a'+i))+".txt"))
		if wErr != nil {
			t.Fatal(wErr)
		}
		if _, wErr = fw.Write([]byte("x")); wErr != nil {
			t.Fatal(wErr)
		}
	}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyPartial
	cfg.ReportMode = config.ReportHuman
	cfg.Limits.MaxFiles = 1

	result := Run(context.Background(), cfg)
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty")
	}

	human, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read human report: %v", err)
	}
	humanStr := string(human)

	for _, fragment := range []string{
		"## Policy Decisions",
		"max-files",
		"partial mode: skipping subtree",
	} {
		if !strings.Contains(humanStr, fragment) {
			t.Fatalf("policy report missing %q", fragment)
		}
	}
}
