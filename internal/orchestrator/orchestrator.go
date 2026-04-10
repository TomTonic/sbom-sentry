// Package orchestrator coordinates the end-to-end processing pipeline of
// sbom-sentry. It validates configuration, computes input hashes, resolves
// the sandbox, performs extraction, scanning, SBOM assembly, and report
// generation in sequence. It owns the lifecycle of temporary directories
// and produces deterministic exit codes.
package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sbom-sentry/internal/assembly"
	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/extract"
	"github.com/sbom-sentry/internal/policy"
	"github.com/sbom-sentry/internal/report"
	"github.com/sbom-sentry/internal/sandbox"
	"github.com/sbom-sentry/internal/scan"
)

// ExitCode represents the process exit status.
type ExitCode int

const (
	// ExitSuccess indicates all subtrees were fully processed.
	ExitSuccess ExitCode = 0
	// ExitPartial indicates some subtrees were skipped or incomplete.
	ExitPartial ExitCode = 1
	// ExitHardSecurity indicates a hard security incident or fatal runtime failure.
	ExitHardSecurity ExitCode = 2
)

// Result holds the outcome of a complete sbom-sentry run.
type Result struct {
	ExitCode   ExitCode
	SBOMPath   string
	ReportPath string
	Error      error
}

// Run executes the complete sbom-sentry processing pipeline.
// It validates configuration, computes input hashes, resolves the sandbox,
// extracts archives recursively, invokes Syft for SBOM generation, assembles
// the consolidated SBOM, and generates the audit report.
//
// The pipeline is designed to always produce output when possible: even if
// hard security events occur after initialization, the SBOM and report are
// still written with affected subtrees marked incomplete.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - cfg: the validated run configuration
//
// Returns a Result containing the exit code, output paths, and any fatal error.
func Run(ctx context.Context, cfg config.Config) Result {
	startTime := time.Now()
	issues := make([]report.ProcessingIssue, 0)
	addIssue := func(stage string, err error) {
		if err == nil {
			return
		}
		issues = append(issues, report.ProcessingIssue{Stage: stage, Message: err.Error()})
	}

	var fatalErr error

	// Step 1: Validate configuration.
	if err := cfg.Validate(); err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("configuration: %w", err)}
	}

	// Step 2: Compute input file hashes.
	inputSummary, err := report.ComputeInputSummary(cfg.InputPath)
	if err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("input hash: %w", err)}
	}

	// Step 3: Resolve sandbox.
	sb, resolveErr := sandbox.Resolve(cfg)
	addIssue("sandbox-resolve", resolveErr)
	sandboxInfo := report.SandboxSummary{
		UnsafeOvr: cfg.Unsafe,
		Name:      sb.Name(),
		Available: sb.Available(),
	}

	// Step 4: Extract.
	policyEngine := policy.NewEngine(cfg.PolicyMode)

	tree, extractErr := extract.Extract(ctx, cfg.InputPath, cfg, sb)
	if extractErr != nil {
		addIssue("extract", extractErr)
		// Record the policy decision.
		decision := policyEngine.Evaluate(policy.Violation{
			Type:     "extraction",
			NodePath: filepath.Base(cfg.InputPath),
			Error:    extractErr,
		})

		if decision.Action == policy.ActionAbort && tree == nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("extraction: %w", extractErr)}
		}
	}

	// Step 5: Scan with Syft.
	var scans []scan.ScanResult
	if tree != nil {
		scans, err = scan.ScanAll(ctx, tree, cfg)
		if err != nil {
			addIssue("scan", err)
			// Non-fatal: proceed with whatever we have.
			policyEngine.Evaluate(policy.Violation{
				Type:     "scan",
				NodePath: "root",
				Error:    err,
			})
		}
	}

	// Step 6: Assemble SBOM.
	var sbomPath string
	if tree != nil {
		bom, asmErr := assembly.Assemble(tree, scans, cfg)
		if asmErr != nil {
			addIssue("assembly", asmErr)
			policyEngine.Evaluate(policy.Violation{
				Type:     "assembly",
				NodePath: "root",
				Error:    asmErr,
			})
		} else {
			// Write SBOM.
			inputBase := strings.TrimSuffix(filepath.Base(cfg.InputPath), filepath.Ext(cfg.InputPath))
			sbomCandidate := filepath.Join(cfg.OutputDir, inputBase+".cdx.json")
			sbomPath = sbomCandidate
			if writeErr := assembly.WriteSBOM(bom, sbomPath); writeErr != nil {
				addIssue("write-sbom", writeErr)
				policyEngine.Evaluate(policy.Violation{
					Type:     "write-sbom",
					NodePath: "root",
					Error:    writeErr,
				})
				sbomPath = ""
				if fatalErr == nil {
					fatalErr = fmt.Errorf("write SBOM: %w", writeErr)
				}
			}
		}
	}

	// Step 7: Generate report.
	endTime := time.Now()
	buildReportData := func() report.ReportData {
		processingIssues := append([]report.ProcessingIssue(nil), issues...)
		return report.ReportData{
			Input:            inputSummary,
			Config:           cfg,
			Tree:             tree,
			Scans:            scans,
			PolicyDecisions:  policyEngine.Decisions(),
			SandboxInfo:      sandboxInfo,
			ProcessingIssues: processingIssues,
			StartTime:        startTime,
			EndTime:          endTime,
			SBOMPath:         sbomPath,
		}
	}

	inputBase := strings.TrimSuffix(filepath.Base(cfg.InputPath), filepath.Ext(cfg.InputPath))
	var reportPath string
	var humanPath string
	humanIssueCount := -1

	switch cfg.ReportMode {
	case config.ReportHuman, config.ReportBoth:
		humanPath = filepath.Join(cfg.OutputDir, inputBase+".report.md")
		f, ferr := os.Create(humanPath)
		if ferr != nil {
			addIssue("create-report-human", ferr)
			if fatalErr == nil {
				fatalErr = fmt.Errorf("create report: %w", ferr)
			}
		} else {
			if werr := report.GenerateHuman(buildReportData(), cfg.Language, f); werr != nil {
				if cerr := f.Close(); cerr != nil {
					addIssue("close-report-human", cerr)
					if fatalErr == nil {
						fatalErr = fmt.Errorf("close report: %w", cerr)
					}
				}
				addIssue("write-report-human", werr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("write report: %w", werr)
				}
			} else if cerr := f.Close(); cerr != nil {
				addIssue("close-report-human", cerr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("close report: %w", cerr)
				}
			} else {
				reportPath = humanPath
				humanIssueCount = len(issues)
			}
		}
	}

	switch cfg.ReportMode {
	case config.ReportMachine, config.ReportBoth:
		jsonPath := filepath.Join(cfg.OutputDir, inputBase+".report.json")
		f, ferr := os.Create(jsonPath)
		if ferr != nil {
			addIssue("create-report-machine", ferr)
			if fatalErr == nil {
				fatalErr = fmt.Errorf("create JSON report: %w", ferr)
			}
		} else {
			if werr := report.GenerateMachine(buildReportData(), f); werr != nil {
				if cerr := f.Close(); cerr != nil {
					addIssue("close-report-machine", cerr)
					if fatalErr == nil {
						fatalErr = fmt.Errorf("close JSON report: %w", cerr)
					}
				}
				addIssue("write-report-machine", werr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("write JSON report: %w", werr)
				}
			} else if cerr := f.Close(); cerr != nil {
				addIssue("close-report-machine", cerr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("close JSON report: %w", cerr)
				}
			} else if reportPath == "" {
				reportPath = jsonPath
			}
		}
	}

	if humanIssueCount >= 0 && len(issues) > humanIssueCount {
		f, rewriteErr := os.Create(humanPath)
		if rewriteErr != nil {
			addIssue("rewrite-report-human", rewriteErr)
			if fatalErr == nil {
				fatalErr = fmt.Errorf("rewrite report: %w", rewriteErr)
			}
		} else {
			if writeErr := report.GenerateHuman(buildReportData(), cfg.Language, f); writeErr != nil {
				if closeErr := f.Close(); closeErr != nil {
					addIssue("rewrite-report-human", closeErr)
					if fatalErr == nil {
						fatalErr = fmt.Errorf("rewrite report: %w", closeErr)
					}
				}
				addIssue("rewrite-report-human", writeErr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("rewrite report: %w", writeErr)
				}
			} else if closeErr := f.Close(); closeErr != nil {
				addIssue("rewrite-report-human", closeErr)
				if fatalErr == nil {
					fatalErr = fmt.Errorf("rewrite report: %w", closeErr)
				}
			}
		}
	}

	// Step 8: Clean up temporary directories.
	if tree != nil {
		extract.CleanupNode(tree)
	}

	// Step 9: Determine exit code.
	exitCode := ExitSuccess
	switch {
	case fatalErr != nil:
		exitCode = ExitHardSecurity
	case policyEngine.HasHardSecurityIncident() || treeHasHardSecurity(tree):
		exitCode = ExitHardSecurity
	case policyEngine.HasSkip() || policyEngine.HasAbort() || treeHasIncomplete(tree) || hasScanFailures(scans):
		exitCode = ExitPartial
	}

	return Result{
		ExitCode:   exitCode,
		SBOMPath:   sbomPath,
		ReportPath: reportPath,
		Error:      fatalErr,
	}
}

func treeHasHardSecurity(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	if node.Status == extract.StatusSecurityBlocked {
		return true
	}
	for _, child := range node.Children {
		if treeHasHardSecurity(child) {
			return true
		}
	}
	return false
}

func treeHasIncomplete(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	switch node.Status {
	case extract.StatusFailed, extract.StatusSkipped, extract.StatusToolMissing:
		return true
	}
	for _, child := range node.Children {
		if treeHasIncomplete(child) {
			return true
		}
	}
	return false
}

func hasScanFailures(scans []scan.ScanResult) bool {
	for _, scanResult := range scans {
		if scanResult.Error != nil {
			return true
		}
	}
	return false
}
