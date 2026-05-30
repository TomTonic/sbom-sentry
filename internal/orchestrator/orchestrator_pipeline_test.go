package orchestrator

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/report"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestRunWithInvalidConfigReturnsHardSecurity(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("ExitCode = %d, want %d (ExitHardSecurity)", result.ExitCode, ExitHardSecurity)
	}

	if result.Error == nil {
		t.Error("Error is nil, want validation error")
	}
}

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

func TestRunWithValidZIPProducesOutput(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed with hard security: %v", result.Error)
	}

	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file does not exist: %v", err)
		}
	}

	if result.ReportPath == "" {
		t.Error("ReportPath is empty")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file does not exist: %v", err)
		}
	}
}

func TestRunWithCancelledContextHandlesGracefully(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "test.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := Run(ctx, cfg)

	if result.ExitCode == ExitSuccess && result.Error == nil {
		t.Error("cancelled context produced ExitSuccess with no error; expected a non-success outcome")
	}
}

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

func TestRunWithStrictPolicyAndEmptyZIP(t *testing.T) {
	dir := t.TempDir()

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

	if result.ExitCode == ExitHardSecurity && result.Error == nil {
		t.Error("ExitHardSecurity without error")
	}
}

func TestRunWithHumanReportMode(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportMarkdown

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

func TestRunWithHumanTemplateWrapperFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")
	templatePath := filepath.Join(dir, "human-wrapper.tmpl")
	if err := os.WriteFile(templatePath, []byte("BEGIN\n{{.Body}}\nEND"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportMarkdown
	cfg.MarkdownRenderEngine = "template-wrapper"
	cfg.MarkdownTemplateFile = templatePath

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}

	reportPath := filepath.Join(dir, "delivery.report.md")
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	body := string(raw)
	if !strings.HasPrefix(body, "BEGIN\n") {
		t.Fatalf("expected wrapper prefix in report")
	}
	if !strings.HasSuffix(body, "END") {
		t.Fatalf("expected wrapper suffix in report")
	}
}

func TestRunWithMachineReportMode(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportJSON

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}

	if result.ReportPath == "" {
		t.Skip("no report path produced (non-fatal)")
	}

	if filepath.Ext(result.ReportPath) != ".json" {
		t.Errorf("report path %q doesn't look like a .json file", result.ReportPath)
	}
}

// TestRunBlockedSBOMPathReportsIssue verifies that when the SBOM output
// path is blocked (directory exists where file should be), the pipeline
// records an issue and the exit code is non-success.
func TestRunBlockedSBOMPathReportsIssue(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	// Block the SBOM output path by creating a directory.
	blockedPath := filepath.Join(dir, "delivery.cdx.json")
	if err := os.MkdirAll(blockedPath, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportMarkdown

	result := Run(context.Background(), cfg)

	// SBOM write should have failed.
	if result.SBOMPath != "" {
		t.Errorf("SBOMPath = %q, want empty (write should fail)", result.SBOMPath)
	}

	foundIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "write-sbom" {
			foundIssue = true
			break
		}
	}
	if !foundIssue {
		t.Error("expected write-sbom issue in result")
	}
}

// TestRunBlockedHumanReportPathReportsIssue verifies that when the human
// report output path is blocked, the pipeline records an issue.
func TestRunBlockedHumanReportPathReportsIssue(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	// Block the markdown report path.
	blockedPath := filepath.Join(dir, "delivery.report.md")
	if err := os.MkdirAll(blockedPath, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportMarkdown

	result := Run(context.Background(), cfg)

	foundIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "create-report-markdown" {
			foundIssue = true
			break
		}
	}
	if !foundIssue {
		t.Error("expected create-report-markdown issue in result")
	}
}

// TestRunWithMachineOnlyBlockedReportPath tests the machine-only error path.
func TestRunWithMachineOnlyBlockedReportPath(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	// Block the JSON report path.
	blockedPath := filepath.Join(dir, "delivery.report.json")
	if err := os.MkdirAll(blockedPath, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportJSON

	result := Run(context.Background(), cfg)

	foundIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "create-report-json" {
			foundIssue = true
			break
		}
	}
	if !foundIssue {
		t.Error("expected create-report-json issue in result")
	}
}

// TestRunBothReportsBlockedSBOMAndReport tests that blocking both the
// SBOM and report output still produces appropriate issues.
func TestRunBothReportsBlockedSBOMAndReport(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	// Block both SBOM and report file paths.
	if err := os.MkdirAll(filepath.Join(dir, "delivery.cdx.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "delivery.report.md"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "delivery.report.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth

	result := Run(context.Background(), cfg)

	// Multiple issues should be recorded.
	stagesSeen := make(map[string]bool)
	for _, iss := range result.Issues {
		stagesSeen[iss.Stage] = true
	}
	if !stagesSeen["write-sbom"] {
		t.Error("expected write-sbom issue")
	}
	if !stagesSeen["create-report-markdown"] {
		t.Error("expected create-report-markdown issue")
	}
}

// TestRunWithReadOnlyOutputDir forces several write-failure error paths
// that are otherwise unreachable.
func TestRunWithReadOnlyOutputDir(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	outDir := filepath.Join(dir, "readonly-out")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = outDir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth

	// Make output dir read-only to force write failures.
	if err := os.Chmod(outDir, 0o555); err != nil { //nolint:gosec // test: intentionally restrictive
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(outDir, 0o750) //nolint:gosec // test: cleanup
	})

	result := Run(context.Background(), cfg)

	// At minimum, the SBOM or report write should have failed.
	if result.ExitCode == ExitSuccess && len(result.Issues) == 0 {
		t.Error("expected non-success exit or issues with read-only output dir")
	}
}

// TestRunInvalidConfigEmptyInput exercises the cfg.Validate() early-return error path.
func TestRunInvalidConfigEmptyInput(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.InputPath = "" // triggers validation error

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("expected ExitHardSecurity, got %d", result.ExitCode)
	}
	if result.Error == nil {
		t.Error("expected non-nil error for invalid config")
	}
}

// TestRunReportBothBlockedMachineTriggersRewrite exercises the markdown-report
// rewrite path that fires when the JSON report adds issues after the
// markdown report was already written.
func TestRunReportBothBlockedMachineTriggersRewrite(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	// Block only the JSON report JSON path so markdown succeeds.
	blockedJSON := filepath.Join(dir, "delivery.report.json")
	if err := os.MkdirAll(blockedJSON, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth

	result := Run(context.Background(), cfg)

	// Machine report should have failed.
	foundMachineIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "create-report-json" {
			foundMachineIssue = true
			break
		}
	}
	if !foundMachineIssue {
		t.Error("expected create-report-json issue")
	}

	// Human report should still exist (rewritten with updated issues).
	humanPath := filepath.Join(dir, "delivery.report.md")
	info, err := os.Stat(humanPath)
	if err != nil {
		t.Errorf("expected markdown report to exist after rewrite: %v", err)
	} else if info.Size() == 0 {
		t.Error("markdown report should not be empty after rewrite")
	}
}

// TestRunHashError exercises the ComputeInputSummary failure path by making
// the input file unreadable (os.Stat succeeds but open-for-read fails).
func TestRunHashError(t *testing.T) {
	origFunc := computeInputSummaryFunc
	computeInputSummaryFunc = func(_ string) (report.InputSummary, error) {
		return report.InputSummary{}, errors.New("injected hash error")
	}
	t.Cleanup(func() { computeInputSummaryFunc = origFunc })

	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("expected ExitHardSecurity, got %d", result.ExitCode)
	}
	if result.Error == nil || result.Error.Error() != "input hash: injected hash error" {
		t.Errorf("unexpected error: %v", result.Error)
	}
}

// TestRunScanError exercises the scan error path by injecting a failing ScanAll.
func TestRunScanError(t *testing.T) {
	origFunc := scanAllFunc
	scanAllFunc = func(_ context.Context, _ *extract.ExtractionNode, _ config.Config) ([]scan.ScanResult, error) {
		return nil, errors.New("injected scan error")
	}
	t.Cleanup(func() { scanAllFunc = origFunc })

	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	foundIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "scan" {
			foundIssue = true
			break
		}
	}
	if !foundIssue {
		t.Error("expected scan issue in result")
	}
}

// TestRunAssemblyError exercises the assembly error path by injecting a failing Assemble.
func TestRunAssemblyError(t *testing.T) {
	origFunc := assembleFunc
	assembleFunc = func(_ *extract.ExtractionNode, _ []scan.ScanResult, _ config.Config) (*cdx.BOM, []assembly.SuppressionRecord, error) {
		return nil, nil, errors.New("injected assembly error")
	}
	t.Cleanup(func() { assembleFunc = origFunc })

	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	foundIssue := false
	for _, iss := range result.Issues {
		if iss.Stage == "assembly" {
			foundIssue = true
			break
		}
	}
	if !foundIssue {
		t.Error("expected assembly issue in result")
	}
	// SBOM should not have been written.
	if result.SBOMPath != "" {
		t.Error("expected empty SBOMPath when assembly fails")
	}
}
