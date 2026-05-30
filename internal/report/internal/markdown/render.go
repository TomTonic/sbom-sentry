package markdown

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	texttemplate "text/template"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// RenderEngine selects the backend used for human Markdown rendering.
type RenderEngine string

const (
	// RenderEngineWriter uses the canonical deterministic writer backend.
	RenderEngineWriter RenderEngine = "writer"
	// RenderEngineTemplateWrapper wraps the canonical report body via a
	// text/template wrapper.
	RenderEngineTemplateWrapper RenderEngine = "template-wrapper"
	// RenderEngineTemplateDocument renders from a caller-supplied
	// document template with pre-rendered section blocks.
	RenderEngineTemplateDocument RenderEngine = "template-document"
)

// RenderOptions configures optional markdown report rendering backends.
//
// Zero value means deterministic default writer rendering.
type RenderOptions struct {
	Engine RenderEngine
	// WrapperTemplate is used when Engine is template-wrapper.
	WrapperTemplate string
	// DocumentTemplate is used when Engine is template-document.
	DocumentTemplate string
}

// markdownReportViewModel is the precomputed state consumed by human renderers.
// It separates expensive aggregation from output formatting.
type markdownReportViewModel struct {
	data         ReportData
	report       reportjson.ReportV2
	language     string
	translations translations
	sections     []reportSection
	occurrences  []componentOccurrence
	indexStats   componentIndexStats
	extStats     extractionStats
	scnStats     scanStats
	polStats     policyStats
}

// buildMarkdownReportViewModel derives deterministic section and statistics data
// once so different renderer backends can reuse the same snapshot.
func buildMarkdownReportViewModel(data ReportData, lang string) markdownReportViewModel {
	report := reportjson.BuildV2Report(data)
	// ReportData was just serialized in the same process; parse errors cannot occur.
	sourceData, _ := reportjson.ReportDataFromV2(report)
	occurrences, indexStats := reportjson.CollectComponentOccurrences(sourceData.BOM)
	t := getTranslations(lang)
	return markdownReportViewModel{
		data:         sourceData,
		report:       report,
		language:     lang,
		translations: t,
		sections:     reportSections(t),
		occurrences:  occurrences,
		indexStats:   indexStats,
		extStats:     reportjson.CollectExtractionStats(sourceData.Tree),
		scnStats:     reportjson.CollectScanStats(sourceData.Scans),
		polStats:     reportjson.CollectPolicyStats(sourceData.PolicyDecisions),
	}
}

// markdownWriterRenderer renders the markdown report via direct writes.
// It is the default deterministic backend.
type markdownWriterRenderer struct{}

// Render writes the full Markdown report from a precomputed view model.
func (markdownWriterRenderer) Render(w io.Writer, vm markdownReportViewModel) error {
	return renderCanonicalHumanMarkdown(w, vm)
}

// GenerateMarkdownWithOptions writes the markdown report using the selected rendering
// backend. Unknown engine values return an error.
func GenerateMarkdownWithOptions(data ReportData, lang string, w io.Writer, opts RenderOptions) error {
	vm := buildMarkdownReportViewModel(data, lang)
	engine := opts.Engine
	if engine == "" {
		engine = RenderEngineWriter
	}

	switch engine {
	case RenderEngineWriter:
		return markdownWriterRenderer{}.Render(w, vm)
	case RenderEngineTemplateWrapper:
		return templateWrapperMarkdownRenderer{wrapperTemplate: opts.WrapperTemplate}.Render(w, vm)
	case RenderEngineTemplateDocument:
		if opts.DocumentTemplate == "" {
			return fmt.Errorf("report: document template must not be empty")
		}
		model := buildMarkdownTemplateDocumentModel(vm)
		return executeMarkdownDocumentTemplate(w, model, opts.DocumentTemplate)
	default:
		return fmt.Errorf("report: unsupported markdown render engine %q", engine)
	}
}

// GenerateMarkdownWithTemplate writes the markdown report through an optional
// text/template wrapper. The wrapper receives one field, Body, containing the
// complete deterministic Markdown report produced by the default writer engine.
//
// When wrapperTemplate is empty, "{{.Body}}" is used.
func GenerateMarkdownWithTemplate(data ReportData, lang string, w io.Writer, wrapperTemplate string) error {
	return GenerateMarkdownWithOptions(data, lang, w, RenderOptions{
		Engine:          RenderEngineTemplateWrapper,
		WrapperTemplate: wrapperTemplate,
	})
}

// templateWrapperMarkdownRenderer wraps the deterministic writer output in a
// caller-provided text/template (for optional branded framing or embedding).
type templateWrapperMarkdownRenderer struct {
	wrapperTemplate string
}

// Render executes the optional wrapper template around the canonical Markdown
// report body.
func (r templateWrapperMarkdownRenderer) Render(w io.Writer, vm markdownReportViewModel) error {
	var body bytes.Buffer
	if err := (markdownWriterRenderer{}).Render(&body, vm); err != nil {
		return err
	}

	tplText := r.wrapperTemplate
	if strings.TrimSpace(tplText) == "" {
		tplText = "{{.Body}}"
	}

	tpl, err := texttemplate.New("human-wrapper").Parse(tplText)
	if err != nil {
		return fmt.Errorf("report: parse human wrapper template: %w", err)
	}

	model := struct {
		Body     string
		Report   ReportData
		Language string
	}{
		Body:     body.String(),
		Report:   vm.data,
		Language: vm.language,
	}
	if err := tpl.Execute(w, model); err != nil {
		return fmt.Errorf("report: execute human wrapper template: %w", err)
	}
	return nil
}

// GenerateMarkdownWithTemplateDocument renders the markdown report using a
// caller-provided text/template fed with pre-rendered Markdown section blocks.
//
// This optional API enables structural customization (for example reordered
// sections or custom framing) while preserving deterministic section content
// generation from the canonical writer helpers.
func GenerateMarkdownWithTemplateDocument(data ReportData, lang string, w io.Writer, documentTemplate string) error {
	return GenerateMarkdownWithOptions(data, lang, w, RenderOptions{
		Engine:           RenderEngineTemplateDocument,
		DocumentTemplate: documentTemplate,
	})
}
