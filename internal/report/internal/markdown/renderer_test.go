package markdown

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateHumanWithTemplateIdentityWrapperMatchesDefault(t *testing.T) {
	data := makeTestReportData()

	var base bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &base, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions: %v", err)
	}

	var wrapped bytes.Buffer
	if err := GenerateMarkdownWithTemplate(data, "en", &wrapped, "{{.Body}}"); err != nil {
		t.Fatalf("GenerateMarkdownWithTemplate: %v", err)
	}

	baseNormalized := normalizeHumanGeneratedTimestamp(base.String())
	wrappedNormalized := normalizeHumanGeneratedTimestamp(wrapped.String())
	if baseNormalized != wrappedNormalized {
		t.Fatalf("identity wrapper changed report body")
	}
}

func TestGenerateHumanWithTemplateCanWrapOutput(t *testing.T) {
	data := makeTestReportData()

	const wrapper = "BEGIN\n{{.Body}}\nEND"
	var out bytes.Buffer
	if err := GenerateMarkdownWithTemplate(data, "en", &out, wrapper); err != nil {
		t.Fatalf("GenerateMarkdownWithTemplate: %v", err)
	}

	s := out.String()
	if !strings.HasPrefix(s, "BEGIN\n") {
		t.Fatalf("missing wrapper prefix")
	}
	if !strings.HasSuffix(s, "\nEND") {
		t.Fatalf("missing wrapper suffix")
	}
	if !strings.Contains(s, "# ") {
		t.Fatalf("wrapped output does not contain report body")
	}
}

func TestGenerateHumanWithTemplateInvalidTemplateReturnsError(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithTemplate(data, "en", &out, "{{")
	if err == nil {
		t.Fatal("expected template parse error")
	}
}

func TestGenerateHumanWithTemplateDocumentRendersSelectedSections(t *testing.T) {
	data := makeTestReportData()

	const tpl = "{{.Header}}{{.TableOfContents}}{{.Sections.Summary}}{{.Sections.Extraction}}{{.EndOfReport}}"
	var out bytes.Buffer
	if err := GenerateMarkdownWithTemplateDocument(data, "en", &out, tpl); err != nil {
		t.Fatalf("GenerateMarkdownWithTemplateDocument: %v", err)
	}

	s := out.String()
	if !strings.Contains(s, "# ") {
		t.Fatalf("missing report title header")
	}
	if !strings.Contains(s, "## ") {
		t.Fatalf("missing section heading")
	}
	if !strings.Contains(s, "test.zip") {
		t.Fatalf("expected extraction content")
	}
}

func TestGenerateHumanWithTemplateDocumentRejectsEmptyTemplate(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithTemplateDocument(data, "en", &out, "")
	if err == nil {
		t.Fatal("expected empty-template error")
	}
}

func TestGenerateHumanWithTemplateDocumentInvalidTemplateReturnsError(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithTemplateDocument(data, "en", &out, "{{")
	if err == nil {
		t.Fatal("expected document template parse error")
	}
}

func TestGenerateHumanWithOptionsDefaultMatchesWriterEngine(t *testing.T) {
	data := makeTestReportData()

	var base bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &base, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions: %v", err)
	}

	var viaWriter bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &viaWriter, RenderOptions{Engine: RenderEngineWriter}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions: %v", err)
	}

	baseNormalized := normalizeHumanGeneratedTimestamp(base.String())
	viaWriterNormalized := normalizeHumanGeneratedTimestamp(viaWriter.String())
	if baseNormalized != viaWriterNormalized {
		t.Fatalf("default options changed report body")
	}
}

func TestGenerateHumanWithOptionsRejectsUnknownEngine(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithOptions(data, "en", &out, RenderOptions{Engine: RenderEngine("unknown")})
	if err == nil {
		t.Fatal("expected unsupported-engine error")
	}
}

func TestGenerateHumanWithOptionsTemplateWrapper(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithOptions(data, "en", &out, RenderOptions{
		Engine:          RenderEngineTemplateWrapper,
		WrapperTemplate: "HEAD\n{{.Body}}\nTAIL",
	})
	if err != nil {
		t.Fatalf("GenerateMarkdownWithOptions: %v", err)
	}

	s := out.String()
	if !strings.HasPrefix(s, "HEAD\n") {
		t.Fatalf("missing wrapper header")
	}
	if !strings.HasSuffix(s, "\nTAIL") {
		t.Fatalf("missing wrapper footer")
	}
}

func TestGenerateHumanWithOptionsTemplateDocumentRequiresTemplate(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateMarkdownWithOptions(data, "en", &out, RenderOptions{Engine: RenderEngineTemplateDocument})
	if err == nil {
		t.Fatal("expected missing document template error")
	}
}
