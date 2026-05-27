package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	texttemplate "text/template"
)

// markdownWriterHumanRenderer renders the human report via direct writes.
// It is the default deterministic backend.
type markdownWriterHumanRenderer struct{}

// Render writes the full Markdown report from a precomputed view model.
func (markdownWriterHumanRenderer) Render(w io.Writer, vm humanReportViewModel) error {
	return renderCanonicalHumanMarkdown(w, vm)
}

// GenerateHumanWithTemplate writes the human report through an optional
// text/template wrapper. The wrapper receives one field, Body, containing the
// complete deterministic Markdown report produced by the default writer engine.
//
// When wrapperTemplate is empty, "{{.Body}}" is used.
func GenerateHumanWithTemplate(data ReportData, lang string, w io.Writer, wrapperTemplate string) error {
	return GenerateHumanWithOptions(data, lang, w, HumanRenderOptions{
		Engine:          HumanRenderEngineTemplateWrapper,
		WrapperTemplate: wrapperTemplate,
	})
}

// templateWrapperHumanRenderer wraps the deterministic writer output in a
// caller-provided text/template (for optional branded framing or embedding).
type templateWrapperHumanRenderer struct {
	wrapperTemplate string
}

// Render executes the optional wrapper template around the canonical Markdown
// report body.
func (r templateWrapperHumanRenderer) Render(w io.Writer, vm humanReportViewModel) error {
	var body bytes.Buffer
	if err := (markdownWriterHumanRenderer{}).Render(&body, vm); err != nil {
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

// GenerateHumanWithTemplateDocument renders the human report using a
// caller-provided text/template fed with pre-rendered Markdown section blocks.
//
// This optional API enables structural customization (for example reordered
// sections or custom framing) while preserving deterministic section content
// generation from the canonical writer helpers.
func GenerateHumanWithTemplateDocument(data ReportData, lang string, w io.Writer, documentTemplate string) error {
	return GenerateHumanWithOptions(data, lang, w, HumanRenderOptions{
		Engine:           HumanRenderEngineTemplateDocument,
		DocumentTemplate: documentTemplate,
	})
}
