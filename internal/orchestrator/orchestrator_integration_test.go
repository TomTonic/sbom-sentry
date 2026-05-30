package orchestrator

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
)

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
	cfg.ReportSelection = config.ReportBoth

	result := Run(context.Background(), cfg)

	foundMachineIssue := false
	for _, issue := range result.Issues {
		if issue.Stage == "create-report-json" {
			foundMachineIssue = true
			break
		}
	}
	if !foundMachineIssue {
		t.Fatal("result issues missing create-report-json")
	}

	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty; expected surviving markdown report")
	}
	humanReport, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read markdown report: %v", err)
	}
	humanStr := string(humanReport)

	for _, fragment := range []string{
		"## Processing Errors",
		"create-report-json",
	} {
		if !strings.Contains(humanStr, fragment) {
			t.Fatalf("markdown report missing %q", fragment)
		}
	}
}

func TestRunWithPathTraversalZIPStillWritesSBOMAndReport(t *testing.T) {
	dir := t.TempDir()

	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	fw, wErr := w.Create("readme.txt")
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw.Write([]byte("hello")); wErr != nil {
		t.Fatal(wErr)
	}

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
	cfg.PolicyMode = config.PolicyPartial
	cfg.ReportSelection = config.ReportBoth

	result := Run(context.Background(), cfg)

	// The project relies on 7-Zip path normalization for traversal-style entry
	// names (e.g. ../../../etc/passwd -> etc/passwd inside extraction output).
	// The extraction therefore succeeds: SBOM and report must both be produced.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty; SBOM should be written")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file not written: %v", err)
		}
	}

	if result.ReportPath == "" {
		t.Error("ReportPath is empty; report should be written")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file not written: %v", err)
		}
	}
}

func TestRunWithDeniedSandboxReportsToolMissing(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = false
	cfg.ReportSelection = config.ReportMarkdown

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline hard-failed for ZIP with denied sandbox: %v", result.Error)
	}

	if result.SBOMPath == "" {
		t.Error("SBOMPath empty; ZIP extraction should work without sandbox")
	}
}

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
	cfg.ReportSelection = config.ReportMarkdown

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitPartial {
		t.Fatalf("ExitCode = %d, want %d", result.ExitCode, ExitPartial)
	}
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty for tool-missing run")
	}
}

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
	cfg.ReportSelection = config.ReportMarkdown

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitPartial {
		t.Fatalf("ExitCode = %d, want %d", result.ExitCode, ExitPartial)
	}
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty for external-tool failure run")
	}
}

func TestRunExitCodeOnHardSecurityIsNonZero(t *testing.T) {
	dir := t.TempDir()

	// Create a ZIP with more files than the MaxFiles limit. With PolicyStrict,
	// the resource limit violation propagates and the exit code must be non-zero.
	zipPath := filepath.Join(dir, "many-files.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i < 5; i++ {
		fw, wErr := w.Create(fmt.Sprintf("file%d.txt", i))
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
	cfg.Limits.MaxFiles = 2 // fewer than the 5 files in the ZIP

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitSuccess {
		t.Error("ExitCode = Success after resource limit in strict mode, want non-success")
	}
}

func TestRunNestedZIPEndToEndProducesOutputFiles(t *testing.T) {
	dir := t.TempDir()
	inputPath := createZIPWithNestedZIP(t, dir, "nested-delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth
	cfg.ParallelScanners = 1

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline fatal error: %v", result.Error)
	}

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

func TestRunResourceLimitPartialModeExitsPartial(t *testing.T) {
	dir := t.TempDir()

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

func TestRunResourceLimitStrictModeExitsPartial(t *testing.T) {
	dir := t.TempDir()

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

func TestRunNestedZIPReportContainsExtractionLogAndScans(t *testing.T) {
	dir := t.TempDir()
	inputPath := createZIPWithNestedZIPAndJAR(t, dir, "nested-with-jar.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportSelection = config.ReportBoth
	cfg.ParallelScanners = 1

	result := Run(context.Background(), cfg)
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline fatal error: %v", result.Error)
	}

	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty")
	}

	human, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read markdown report: %v", err)
	}
	humanStr := string(human)

	for _, fragment := range []string{
		"## Extraction Log",
		"nested-with-jar.zip",
		"nested-with-jar.zip/inner.zip",
		"nested-with-jar.zip/inner.zip/lib/app.jar",
		"## Package Scan Log",
		"This is a per-item package scan log",
		"nested-with-jar.zip",
		"nested-with-jar.zip/inner.zip",
		"nested-with-jar.zip/inner.zip/lib/app.jar",
	} {
		if !strings.Contains(humanStr, fragment) {
			t.Fatalf("markdown report missing %q", fragment)
		}
	}

	jsonPath := strings.TrimSuffix(result.ReportPath, ".report.md") + ".report.json"
	machine, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("cannot read JSON report: %v", err)
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
		t.Fatalf("invalid JSON report JSON: %v", err)
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
			t.Fatalf("JSON report scans missing nodePath %q", want)
		}
	}
}

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
	cfg.ReportSelection = config.ReportMarkdown
	cfg.Limits.MaxFiles = 1

	result := Run(context.Background(), cfg)
	if result.ReportPath == "" {
		t.Fatal("ReportPath is empty")
	}

	human, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("cannot read markdown report: %v", err)
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
