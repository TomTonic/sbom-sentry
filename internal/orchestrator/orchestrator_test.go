package orchestrator

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sbom-sentry/internal/config"
)

// TestRunCreatesSBOMAndReport verifies the full user-visible behavior of the
// default command pipeline: one input archive yields one SBOM and one report.
func TestRunCreatesSBOMAndReport(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	input := filepath.Join(tmp, "delivery.zip")
	if err := createZipFixture(input); err != nil {
		t.Fatalf("create zip fixture: %v", err)
	}

	outDir := filepath.Join(tmp, "out")
	cfg := config.Config{
		InputPath:     input,
		OutputDir:     outDir,
		SBOMFormat:    "cyclonedx-json",
		PolicyMode:    config.PolicyStrict,
		InterpretMode: config.InterpretInstallerSemantic,
		ReportMode:    config.ReportBoth,
		Language:      "en",
		RootMetadata: config.RootMetadata{
			Name:       "DeliveryRoot",
			Properties: map[string]string{"env": "test"},
		},
		Limits: config.DefaultLimits(),
	}

	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("run pipeline: %v", err)
	}

	sbomPath := filepath.Join(outDir, "sbom.cyclonedx.json")
	reportPath := filepath.Join(outDir, "audit-report.md")
	if _, err := os.Stat(sbomPath); err != nil {
		t.Fatalf("missing SBOM output: %v", err)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("missing human report output: %v", err)
	}

	var sbom map[string]any
	raw, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read SBOM: %v", err)
	}
	if err := json.Unmarshal(raw, &sbom); err != nil {
		t.Fatalf("parse SBOM JSON: %v", err)
	}
	if sbom["bomFormat"] != "CycloneDX" {
		t.Fatalf("unexpected bomFormat: %v", sbom["bomFormat"])
	}
}

func createZipFixture(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create("bin/tool.exe")
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("binary-data")); err != nil {
		return err
	}
	return zw.Close()
}
