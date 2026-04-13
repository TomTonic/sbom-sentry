// Package orchestrator coordinates the end-to-end processing pipeline of
// extract-sbom. It validates configuration, computes input hashes, resolves
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

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/report"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
	"github.com/TomTonic/extract-sbom/internal/scan"
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

// Result holds the outcome of a complete extract-sbom run.
type Result struct {
	ExitCode   ExitCode
	SBOMPath   string
	ReportPath string
	Issues     []report.ProcessingIssue
	Error      error
}

// Run executes the complete extract-sbom processing pipeline.
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
	generatorInfo := buildinfo.Read()
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] start: %s", filepath.Base(cfg.InputPath))
	issues := make([]report.ProcessingIssue, 0)
	addIssue := func(stage string, err error) {
		if err == nil {
			return
		}
		issues = append(issues, report.ProcessingIssue{Stage: stage, Message: err.Error()})
	}

	var fatalErr error

	// Step 1: Validate configuration.
	cfg.EmitProgress(config.ProgressVerbose, "[extract-sbom] step 1/7: validating configuration")
	if err := cfg.Validate(); err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("configuration: %w", err)}
	}

	// Step 2: Compute input file hashes.
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 2/7: hashing input file")
	hashStart := time.Now()
	inputSummary, err := report.ComputeInputSummary(cfg.InputPath)
	if err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("input hash: %w", err)}
	}
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] hashing done in %s", time.Since(hashStart).Round(time.Millisecond))

	// Step 3: Resolve sandbox.
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 3/7: resolving sandbox")
	sb, resolveErr := sandbox.Resolve(cfg)
	addIssue("sandbox-resolve", resolveErr)
	sandboxInfo := report.SandboxSummary{
		UnsafeOvr: cfg.Unsafe,
		Name:      sb.Name(),
		Available: sb.Available(),
	}
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] sandbox: %s (available=%t)", sandboxInfo.Name, sandboxInfo.Available)

	// Check external tool availability early so users don't wait minutes
	// before discovering that MSI/CAB/7z extraction will fail.
	if !sb.Available() {
		cfg.EmitProgress(config.ProgressNormal,
			"[extract-sbom] WARNING: sandbox unavailable and --unsafe not set. "+
				"Extraction of MSI, CAB, 7z, ISO, and InstallShield formats will be skipped. "+
				"Pass --unsafe to allow unsandboxed extraction.")
	} else {
		if !extract.IsToolAvailable("7zz") {
			cfg.EmitProgress(config.ProgressNormal,
				"[extract-sbom] WARNING: 7zz not found on PATH. Extraction of MSI, CAB, 7z, and ISO archives will fail.")
			addIssue("tool-availability", fmt.Errorf("7zz not found on PATH"))
		}
		if !extract.IsToolAvailable("unshield") {
			cfg.EmitProgress(config.ProgressNormal,
				"[extract-sbom] WARNING: unshield not found on PATH. InstallShield CAB extraction will fail.")
			addIssue("tool-availability", fmt.Errorf("unshield not found on PATH"))
		}
	}

	// Step 4: Extract.
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 4/7: extracting containers")
	extractStart := time.Now()
	policyEngine := policy.NewEngine(cfg.PolicyMode)

	tree, extractErr := extract.Extract(ctx, cfg.InputPath, cfg, sb)
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] extraction done in %s", time.Since(extractStart).Round(time.Millisecond))
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
	var totalScannedComponents int
	if tree != nil {
		cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 5/7: scanning with syft")
		scanStart := time.Now()
		scans, err = scan.ScanAll(ctx, tree, cfg)
		totalScannedComponents = scan.CountScannedComponents(scans)
		cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] scanning done in %s: %d tasks → %s found",
			time.Since(scanStart).Round(time.Millisecond), len(scans), scan.FormatComponentCount(totalScannedComponents))
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
	var assembledBOM *cdx.BOM
	var sbomPath string
	var suppressions []assembly.SuppressionRecord
	if tree != nil {
		cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 6/7: assembling sbom")
		assembleStart := time.Now()
		bom, asmSuppressions, asmErr := assembly.Assemble(tree, scans, cfg)
		suppressions = asmSuppressions
		cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] assembly done in %s", time.Since(assembleStart).Round(time.Millisecond))
		if asmErr == nil {
			finalBOMCount := 0
			if bom != nil && bom.Components != nil {
				finalBOMCount = len(*bom.Components)
			}
			fsCount, lvCount, weakCount, purlCount := 0, 0, 0, 0
			for _, s := range asmSuppressions {
				switch s.Reason {
				case assembly.SuppressionFSArtifact:
					fsCount++
				case assembly.SuppressionLowValueFile:
					lvCount++
				case assembly.SuppressionWeakDuplicate:
					weakCount++
				case assembly.SuppressionPURLDuplicate:
					purlCount++
				}
			}
			cfg.EmitProgress(config.ProgressNormal,
				"[extract-sbom] components: %d raw → removed %d (fs-artifacts=%d, low-value=%d, weak-duplicates=%d, purl-duplicates=%d) → \033[1m%d\033[0m in BOM",
				totalScannedComponents, len(asmSuppressions), fsCount, lvCount, weakCount, purlCount, finalBOMCount)
		}
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
				fatalErr = fmt.Errorf("write SBOM: %w", writeErr)
			} else {
				assembledBOM = bom
			}
		}
	}

	// Step 7: Generate report.
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] step 7/7: writing report(s)")
	endTime := time.Now()
	buildReportData := func() report.ReportData {
		processingIssues := append([]report.ProcessingIssue(nil), issues...)
		return report.ReportData{
			Input:            inputSummary,
			Generator:        generatorInfo,
			Config:           cfg,
			Tree:             tree,
			Scans:            scans,
			PolicyDecisions:  policyEngine.Decisions(),
			SandboxInfo:      sandboxInfo,
			ProcessingIssues: processingIssues,
			StartTime:        startTime,
			EndTime:          endTime,
			BOM:              assembledBOM,
			SBOMPath:         sbomPath,
			Suppressions:     suppressions,
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
	cfg.EmitProgress(config.ProgressNormal, "[extract-sbom] done in %s (exit=%d)", time.Since(startTime).Round(time.Millisecond), exitCode)

	return Result{
		ExitCode:   exitCode,
		SBOMPath:   sbomPath,
		ReportPath: reportPath,
		Issues:     append([]report.ProcessingIssue(nil), issues...),
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
