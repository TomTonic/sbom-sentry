package orchestrator

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"sbom-sentry/internal/assembly"
	"sbom-sentry/internal/config"
	"sbom-sentry/internal/extract"
	"sbom-sentry/internal/policy"
	"sbom-sentry/internal/report"
	"sbom-sentry/internal/sandbox"
	"sbom-sentry/internal/scan"
)

// ExitError carries a deterministic process exit code for CLI integration.
type ExitError struct {
	Code int
	Err  error
}

// Error returns a user-facing error string.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("process failed with exit code %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ExitError) Unwrap() error {
	return e.Err
}

// Run executes the end-to-end sbom-sentry pipeline and writes outputs.
func Run(ctx context.Context, cfg config.Config) error {
	start := time.Now()

	if err := cfg.Validate(); err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("config validation failed: %w", err)}
	}

	if cfg.WorkDir == "" {
		workDir, err := os.MkdirTemp(cfg.OutputDir, "sbom-sentry-work-")
		if err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("create work dir: %w", err)}
		}
		cfg.WorkDir = workDir
		defer os.RemoveAll(workDir)
	}

	inputSummary, err := summarizeInput(cfg.InputPath)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("input hashing failed: %w", err)}
	}

	sbox, err := sandbox.Resolve(cfg)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("sandbox resolution failed: %w", err)}
	}

	tree, err := extract.Extract(ctx, cfg.InputPath, cfg, sbox)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("extraction failed: %w", err)}
	}

	scans, err := scan.ScanAll(tree)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("scan stage failed: %w", err)}
	}

	bom, err := assembly.Assemble(tree, scans, cfg)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("assembly failed: %w", err)}
	}

	sbomPath := filepath.Join(cfg.OutputDir, "sbom.cyclonedx.json")
	if err := writeBOM(sbomPath, bom); err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("write SBOM: %w", err)}
	}

	engine := policy.NewEngine(cfg.PolicyMode)
	_ = engine

	reportData := report.ReportData{
		Input:  inputSummary,
		Config: cfg,
		Tree:   tree,
		Scans:  scans,
		SandboxInfo: report.SandboxSummary{
			Name:   sbox.Name(),
			Unsafe: cfg.Unsafe,
		},
		PolicyDecisions: engine.Decisions(),
		StartTime:       start,
		EndTime:         time.Now(),
	}

	if cfg.ReportMode == config.ReportHuman || cfg.ReportMode == config.ReportBoth {
		humanPath := filepath.Join(cfg.OutputDir, "audit-report.md")
		if err := writeHumanReport(humanPath, reportData, cfg.Language); err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("write human report: %w", err)}
		}
	}
	if cfg.ReportMode == config.ReportMachine || cfg.ReportMode == config.ReportBoth {
		machinePath := filepath.Join(cfg.OutputDir, "audit-report.json")
		if err := writeMachineReport(machinePath, reportData); err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("write machine report: %w", err)}
		}
	}

	code := determineExitCode(tree, scans)
	if code != 0 {
		return &ExitError{Code: code, Err: fmt.Errorf("run completed with non-success status")}
	}
	return nil
}

func summarizeInput(path string) (report.InputSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return report.InputSummary{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return report.InputSummary{}, err
	}

	h256 := sha256.New() //nolint:gosec // SHA-256 required by output contract.
	h512 := sha512.New() //nolint:gosec // SHA-512 required by output contract.
	mw := io.MultiWriter(h256, h512)
	if _, err := io.Copy(mw, f); err != nil {
		return report.InputSummary{}, err
	}

	return report.InputSummary{
		FileName: filepath.Base(path),
		Size:     st.Size(),
		SHA256:   hex.EncodeToString(h256.Sum(nil)),
		SHA512:   hex.EncodeToString(h512.Sum(nil)),
	}, nil
}

func writeBOM(path string, bom *cyclonedx.BOM) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := cyclonedx.NewBOMEncoder(f, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

func writeHumanReport(path string, data report.ReportData, lang string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return report.GenerateHuman(data, lang, f)
}

func writeMachineReport(path string, data report.ReportData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return report.GenerateMachine(data, f)
}

func determineExitCode(root *extract.ExtractionNode, scans []scan.ScanResult) int {
	code := 0
	var walk func(*extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}
		switch n.Status {
		case extract.SecurityBlocked:
			code = max(code, 2)
		case extract.Skipped, extract.Failed:
			code = max(code, 1)
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(root)

	for _, s := range scans {
		if s.Error != nil {
			code = max(code, 1)
		}
	}
	return code
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
