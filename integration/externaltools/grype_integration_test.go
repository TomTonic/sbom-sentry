package externaltools_test

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/orchestrator"
)

func createZIPInput(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for filePath, content := range files {
		w, err := zw.Create(filePath)
		if err != nil {
			_ = zw.Close()
			t.Fatalf("zip create entry %s: %v", filePath, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			_ = zw.Close()
			t.Fatalf("zip write entry %s: %v", filePath, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

// TestGrypeIntegrationFakeBinary verifies deterministic end-to-end report
// enrichment when --grype is enabled and a controlled fake grype binary is
// available on PATH.
func TestGrypeIntegrationFakeBinary(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "grype", `
[ "$2" = "-o" ] || exit 11
[ "$3" = "json" ] || exit 12
case "$1" in
  sbom:*) ;;
  *) exit 13 ;;
esac
cat <<'JSON'
{
  "descriptor": {
    "name": "grype",
    "version": "0.111.0",
    "timestamp": "2026-05-01T10:00:00Z",
    "db": {
      "status": {
        "schemaVersion": "v6.1.4",
        "built": "2026-04-15T11:48:47Z"
      }
    }
  },
  "matches": []
}
JSON
`)
	prependPath(t, binDir)

	input := createZIPInput(t, dir, "delivery.zip", map[string]string{
		"README.txt": "hello",
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = input
	cfg.OutputDir = dir
	cfg.ReportSelection = config.ReportBoth
	cfg.Unsafe = true
	cfg.GrypeEnabled = true

	result := orchestrator.Run(context.Background(), cfg)
	if result.Error != nil {
		t.Fatalf("orchestrator run failed: %v", result.Error)
	}
	if result.ExitCode == orchestrator.ExitHardSecurity {
		t.Fatalf("unexpected hard-security exit: %d", result.ExitCode)
	}

	humanReport := filepath.Join(dir, "delivery.report.md")
	rawHuman, err := os.ReadFile(humanReport)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	outHuman := string(rawHuman)
	for _, want := range []string{
		"Vulnerability enrichment state: `completed`",
		"Vulnerability findings: no matched vulnerabilities",
	} {
		if !strings.Contains(outHuman, want) {
			t.Fatalf("markdown report missing %q", want)
		}
	}

	machineReport := filepath.Join(dir, "delivery.report.json")
	rawMachine, err := os.ReadFile(machineReport)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	outMachine := string(rawMachine)
	for _, want := range []string{
		`"vulnerabilities": {`,
		`"state": "completed"`,
		`"requested": true`,
		`"grypeVersion": "0.111.0"`,
		`"dbSchemaVersion": "v6.1.4"`,
	} {
		if !strings.Contains(outMachine, want) {
			t.Fatalf("JSON report missing %q", want)
		}
	}
}

// TestGrypeIntegrationBinaryMissing verifies that the orchestrator continues
// and records state=unavailable when grype is absent from PATH.
func TestGrypeIntegrationBinaryMissing(t *testing.T) {
	dir := t.TempDir()
	emptyBinDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(emptyBinDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Replace PATH entirely so no grype binary can be found.
	// A plain-zip with a single text file only needs syft (Go library) and no
	// external archiving tools, so replacing PATH is safe for this input.
	t.Setenv("PATH", emptyBinDir)

	input := createZIPInput(t, dir, "delivery.zip", map[string]string{
		"README.txt": "hello",
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = input
	cfg.OutputDir = dir
	cfg.ReportSelection = config.ReportBoth
	cfg.Unsafe = true
	cfg.GrypeEnabled = true

	result := orchestrator.Run(context.Background(), cfg)
	if result.Error != nil {
		t.Fatalf("orchestrator run failed: %v", result.Error)
	}
	if result.ExitCode == orchestrator.ExitHardSecurity {
		t.Fatalf("unexpected hard-security exit: %d", result.ExitCode)
	}

	humanReport := filepath.Join(dir, "delivery.report.md")
	rawHuman, err := os.ReadFile(humanReport)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	if !strings.Contains(string(rawHuman), "Vulnerability enrichment state: `unavailable`") {
		t.Fatalf("markdown report should record unavailable state; got:\n%s", string(rawHuman))
	}

	machineReport := filepath.Join(dir, "delivery.report.json")
	rawMachine, err := os.ReadFile(machineReport)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	for _, want := range []string{
		`"state": "unavailable"`,
		`"requested": true`,
		`"grype-not-found"`,
	} {
		if !strings.Contains(string(rawMachine), want) {
			t.Fatalf("JSON report missing %q\nfull output:\n%s", want, string(rawMachine))
		}
	}
}

// TestGrypeIntegrationInvalidJSON verifies that invalid JSON output from grype
// results in state=unavailable with the grype-parse error code recorded and
// that report generation still completes successfully.
func TestGrypeIntegrationInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "grype", `
echo "this is not valid json"
`)
	prependPath(t, binDir)

	input := createZIPInput(t, dir, "delivery.zip", map[string]string{
		"README.txt": "hello",
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = input
	cfg.OutputDir = dir
	cfg.ReportSelection = config.ReportBoth
	cfg.Unsafe = true
	cfg.GrypeEnabled = true

	result := orchestrator.Run(context.Background(), cfg)
	if result.Error != nil {
		t.Fatalf("orchestrator run failed: %v", result.Error)
	}
	if result.ExitCode == orchestrator.ExitHardSecurity {
		t.Fatalf("unexpected hard-security exit: %d", result.ExitCode)
	}

	humanReport := filepath.Join(dir, "delivery.report.md")
	rawHuman, err := os.ReadFile(humanReport)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	if !strings.Contains(string(rawHuman), "Vulnerability enrichment state: `unavailable`") {
		t.Fatalf("markdown report should record unavailable state; got:\n%s", string(rawHuman))
	}

	machineReport := filepath.Join(dir, "delivery.report.json")
	rawMachine, err := os.ReadFile(machineReport)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	for _, want := range []string{
		`"state": "unavailable"`,
		`"requested": true`,
		`"grype-parse"`,
	} {
		if !strings.Contains(string(rawMachine), want) {
			t.Fatalf("JSON report missing %q\nfull output:\n%s", want, string(rawMachine))
		}
	}
}
