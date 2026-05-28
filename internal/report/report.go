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

	htmlpkg "github.com/TomTonic/extract-sbom/internal/report/internal/html"
	humanpkg "github.com/TomTonic/extract-sbom/internal/report/internal/human"
	machinepkg "github.com/TomTonic/extract-sbom/internal/report/internal/machine"
	sarifpkg "github.com/TomTonic/extract-sbom/internal/report/internal/sarif"
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

// GenerateHuman writes the human report using the default deterministic
// writer backend.
func GenerateHuman(data ReportData, lang string, w io.Writer) error {
	return GenerateHumanWithEngine(data, lang, w, "", "")
}

// GenerateHumanWithEngine writes the human report using a selected renderer
// backend. The engine can be "writer", "template-wrapper", or
// "template-document". For template engines, templateContent is applied as the
// wrapper or document template respectively.
func GenerateHumanWithEngine(data ReportData, lang string, w io.Writer, engineName, templateContent string) error {
	engine := humanpkg.RenderEngine(engineName)
	if engine == "" {
		engine = humanpkg.RenderEngineWriter
	}
	humanOpts := humanpkg.RenderOptions{
		Engine: engine,
	}
	if engine == humanpkg.RenderEngineTemplateWrapper {
		humanOpts.WrapperTemplate = templateContent
	}
	if engine == humanpkg.RenderEngineTemplateDocument {
		humanOpts.DocumentTemplate = templateContent
	}
	return humanpkg.GenerateHumanWithOptions(data, lang, w, humanOpts)
}

// GenerateHTML writes a self-contained HTML audit report to w.
func GenerateHTML(data ReportData, language string, w io.Writer) error {
	return htmlpkg.Generate(data, language, w)
}

// GenerateMachine writes a structured JSON audit report to the writer.
func GenerateMachine(data ReportData, w io.Writer) error {
	return machinepkg.Generate(data, w)
}

// GenerateSARIF writes a SARIF 2.1.0 JSON report to w.
func GenerateSARIF(data ReportData, w io.Writer) error {
	return sarifpkg.Generate(data, w)
}
