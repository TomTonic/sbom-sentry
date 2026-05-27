package report

import (
	"bytes"
	"fmt"
	"io"
	texttemplate "text/template"

	"github.com/TomTonic/extract-sbom/internal/scan"
)

// humanTemplateSections contains pre-rendered Markdown blocks for each major
// section so optional document templates can reorder or selectively include
// report content.
type humanTemplateSections struct {
	Summary                string
	MethodOverview         string
	ProcessingIssues       string
	ResidualRisk           string
	Appendix               string
	ComponentIndex         string
	ComponentNormalization string
	Input                  string
	Configuration          string
	ExtensionFilter        string
	RootMetadata           string
	Sandbox                string
	Policy                 string
	Scan                   string
	Extraction             string
}

// humanTemplateDocumentModel is the template input for
// GenerateHumanWithTemplateDocument.
type humanTemplateDocumentModel struct {
	Header          string
	TableOfContents string
	Sections        humanTemplateSections
	EndOfReport     string
	Report          ReportData
	Language        string
}

func executeHumanDocumentTemplate(w io.Writer, model humanTemplateDocumentModel, documentTemplate string) error {
	tpl, err := texttemplate.New("human-document").Parse(documentTemplate)
	if err != nil {
		return fmt.Errorf("report: parse human document template: %w", err)
	}
	if err := tpl.Execute(w, model); err != nil {
		return fmt.Errorf("report: execute human document template: %w", err)
	}
	return nil
}

func buildHumanTemplateDocumentModel(vm humanReportViewModel) humanTemplateDocumentModel {
	data := vm.data
	t := vm.translations

	var toc bytes.Buffer
	fmt.Fprintf(&toc, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(&toc, vm.sections)
	fmt.Fprintln(&toc)

	return humanTemplateDocumentModel{
		Header:          buildHumanHeaderBlock(vm),
		TableOfContents: toc.String(),
		Sections:        buildHumanTemplateSections(vm),
		EndOfReport:     t.endOfReport + "\n",
		Report:          data,
		Language:        vm.language,
	}
}

func buildHumanTemplateSections(vm humanReportViewModel) humanTemplateSections {
	data := vm.data
	t := vm.translations

	render := func(fn func(io.Writer)) string {
		var b bytes.Buffer
		fn(&b)
		return b.String()
	}

	return humanTemplateSections{
		Summary: render(func(w io.Writer) {
			writeSectionHeading(w, t.summarySection, anchorSummary)
			writeSummary(w, data, vm.extStats, vm.scnStats, vm.polStats, vm.indexStats, vm.occurrences, t)
			fmt.Fprintln(w)
		}),
		MethodOverview: render(func(w io.Writer) {
			writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
			writeMethodOverview(w, t)
			fmt.Fprintln(w)
		}),
		ProcessingIssues: render(func(w io.Writer) {
			writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
			writeProcessingIssues(w, data, vm.extStats, vm.scnStats, t)
			fmt.Fprintln(w)
		}),
		ResidualRisk: render(func(w io.Writer) {
			writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
			writeResidualRisk(w, data, vm.extStats, vm.scnStats, vm.indexStats, t)
			fmt.Fprintln(w)
		}),
		Appendix: render(func(w io.Writer) {
			writeSectionHeading(w, t.appendixSection, anchorAppendix)
			fmt.Fprintln(w, t.appendixLead)
			fmt.Fprintln(w)
		}),
		ComponentIndex: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
			writeComponentOccurrenceIndex(w, vm.occurrences, vm.indexStats, data.Vulnerabilities, t)
			fmt.Fprintln(w)
		}),
		ComponentNormalization: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
			writeSuppressionReport(w, data.Suppressions, data.BOM, t)
			fmt.Fprintln(w)
		}),
		Input: render(func(w io.Writer) {
			writeSectionHeading(w, t.inputSection, anchorInputFile)
			fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
			fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
			fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
			fmt.Fprintln(w)
		}),
		Configuration: render(func(w io.Writer) {
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
		}),
		ExtensionFilter: render(func(w io.Writer) {
			writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
			writeExtensionFilterSection(w, data, vm.extStats, t)
			fmt.Fprintln(w)
		}),
		RootMetadata: render(func(w io.Writer) {
			writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
			writeRootMetadata(w, data, t)
		}),
		Sandbox: render(func(w io.Writer) {
			writeSectionHeading(w, t.sandboxSection, anchorSandbox)
			fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
			fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
			if data.SandboxInfo.UnsafeOvr {
				fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
			}
			fmt.Fprintln(w)
		}),
		Policy: render(func(w io.Writer) {
			writeSectionHeading(w, t.policySection, anchorPolicy)
			writePolicyDecisions(w, data.PolicyDecisions, t)
			fmt.Fprintln(w)
		}),
		Scan: render(func(w io.Writer) {
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
			writeScanNoPackageIdentitiesSubsection(w, vm.scnStats, t)
			fmt.Fprintln(w)
		}),
		Extraction: render(func(w io.Writer) {
			writeSectionHeading(w, t.extractionSection, anchorExtraction)
			writeExtractionTree(w, data.Tree, 0, t)
			fmt.Fprintln(w)
		}),
	}
}
