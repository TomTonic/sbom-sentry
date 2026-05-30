package html

import "io"

// Generate writes a self-contained HTML audit report to w.
func Generate(data ReportData, language string, w io.Writer) error {
	td := buildReportData(data, language)
	return reportTemplate.Execute(w, td)
}
