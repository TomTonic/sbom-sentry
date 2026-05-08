// Package report generates audit reports from the processing state.
// It supports human-readable Markdown output and machine-readable JSON output,
// in English or German. The report documents everything that was processed,
// how, and with what limitations — enabling a third party to assess the
// completeness and reliability of the inspection.
package report

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/scan"
)

// ComputeInputSummary computes the file hashes and metadata for the input file.
// This is called once by the orchestrator before any processing begins.
//
// Parameters:
//   - path: the filesystem path to the input file
//
// Returns an InputSummary with filename, size, SHA-256, and SHA-512 hashes
// (all lowercase hex), or an error if the file cannot be read.
func ComputeInputSummary(path string) (InputSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: open input: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: stat input: %w", err)
	}

	h256 := sha256.New()
	h512 := sha512.New()
	w := io.MultiWriter(h256, h512)

	if _, err := io.Copy(w, f); err != nil {
		return InputSummary{}, fmt.Errorf("report: hash input: %w", err)
	}

	return InputSummary{
		Filename: info.Name(),
		Size:     info.Size(),
		SHA256:   hex.EncodeToString(h256.Sum(nil)),
		SHA512:   hex.EncodeToString(h512.Sum(nil)),
	}, nil
}

// GenerateHuman writes a human-readable Markdown audit report to the writer.
// The report follows the structure required by DESIGN.md §10.4.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - lang: the output language ("en" or "de")
//   - w: the writer to write the Markdown report to
//
// Returns an error if writing fails.
func GenerateHuman(data ReportData, lang string, w io.Writer) error {
	t := getTranslations(lang)
	sections := reportSections(t)
	occurrences, indexStats := collectComponentOccurrences(data.BOM)
	extStats := collectExtractionStats(data.Tree)
	scnStats := collectScanStats(data.Scans)
	polStats := collectPolicyStats(data.PolicyDecisions)
	fmt.Fprintf(w, "# %s\n\n", t.title)
	// Generator header with date and version information
	generatorDate := time.Now().Format("2006-01-02 15:04:05")
	syftVersion := getSyftVersion()
	if syftVersion == "" {
		syftVersion = "github.com/anchore/syft (unknown version)"
	}
	linkedVersion := "[" + data.Generator.Version + "](" + generatorGitHubURL(data.Generator.Version) + ")"
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.reportHeaderGeneratorVersionTemplate, generatorDate, linkedVersion, syftVersion))

	// Tools line — only emitted if at least one external tool was used.
	var toolParts []string
	if data.ToolVersions.Grype != "" {
		entry := data.ToolVersions.Grype
		if data.ToolVersions.GrypeDB != "" {
			entry += " (" + data.ToolVersions.GrypeDB + ")"
		}
		toolParts = append(toolParts, entry)
	}
	if data.ToolVersions.SevenZip != "" {
		toolParts = append(toolParts, data.ToolVersions.SevenZip)
	}
	if data.ToolVersions.Unshield != "" {
		toolParts = append(toolParts, data.ToolVersions.Unshield)
	}
	if len(toolParts) > 0 {
		fmt.Fprintf(w, "%s %s\n\n", t.reportHeaderToolsLabel, strings.Join(toolParts, " | "))
	}
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	// Executive summary and reader guidance.
	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, data, extStats, scnStats, polStats, indexStats, occurrences, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
	writeMethodOverview(w, t)
	fmt.Fprintln(w)

	// Actionable limitations and known blind spots.
	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, data, extStats, scnStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, data, extStats, scnStats, indexStats, t)
	fmt.Fprintln(w)

	// Appendix: complete raw audit trail.
	writeSectionHeading(w, t.appendixSection, anchorAppendix)
	fmt.Fprintln(w, t.appendixLead)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, occurrences, indexStats, data.Vulnerabilities, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
	writeSuppressionReport(w, data.Suppressions, data.BOM, t)
	fmt.Fprintln(w)

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	writeSectionHeading(w, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, data.Config.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, data.Config.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, data.Config.Language)
	fmt.Fprintf(w, "| grype | %v |\n", data.Config.GrypeEnabled)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, data.Config.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, data.Config.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(data.Config.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
	fmt.Fprintln(w)

	// Extension filter section: configured list and files excluded in this run.
	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, data, extStats, t)
	fmt.Fprintln(w)

	// Root SBOM metadata.
	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, data, t)

	// Sandbox information.
	writeSectionHeading(w, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
	if data.SandboxInfo.UnsafeOvr {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, data.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	fmt.Fprintln(w, t.scanSectionLead)
	fmt.Fprintln(w)
	for _, sr := range data.Scans {
		evidencePaths := scan.FlattenEvidencePaths(sr)
		switch {
		case sr.Error != nil:
			fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
		case sr.BOM != nil && sr.BOM.Components != nil:
			fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
			for _, evidencePath := range evidencePaths {
				fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, evidencePath)
			}
		default:
			fmt.Fprintf(w, "- **%s**: %s\n", sr.NodePath, t.noComponents)
		}
	}
	fmt.Fprintln(w)
	writeScanNoPackageIdentitiesSubsection(w, scnStats, t)
	fmt.Fprintln(w)

	// Extraction log.
	writeSectionHeading(w, t.extractionSection, anchorExtraction)
	writeExtractionTree(w, data.Tree, 0, t)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", t.endOfReport)

	return nil
}

// generatorGitHubURL returns a GitHub URL for the given generator version string.
// For clean release tags (e.g. v1.2.3) it points to the release page;
// for pseudo-versions (e.g. v0.4.1-0.20260508110356-abcdef012345) it points
// to the specific commit. A +dirty suffix is stripped before evaluation.
func generatorGitHubURL(version string) string {
	const repoBase = "https://github.com/TomTonic/extract-sbom"
	v := strings.TrimSuffix(version, "+dirty")
	// Pseudo-version: vX.Y.Z-0.YYYYMMDDHHMMSS-COMMITHASH — hash is the last segment.
	if idx := strings.LastIndex(v, "-"); idx != -1 {
		hash := v[idx+1:]
		if len(hash) >= 12 {
			return repoBase + "/commit/" + hash
		}
	}
	// Clean release tag or unrecognised pattern.
	if strings.HasPrefix(v, "v") {
		return repoBase + "/releases/tag/" + v
	}
	return repoBase
}

// getSyftVersion reads the Syft dependency version from build info at runtime.
// If Syft is not found in the dependencies, returns an empty string.
func getSyftVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return ""
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/anchore/syft" {
			return dep.Path + " " + dep.Version
		}
	}
	return ""
}
