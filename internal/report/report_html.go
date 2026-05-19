package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

// htmlReportData is the template data structure for the HTML report.
type htmlReportData struct {
	Title       string
	Generated   string
	Generator   string
	InputFile   string
	InputSize   int64
	InputSHA256 string
	Duration    string
	SBOMPath    string
	SandboxName string
	Language    string

	ExtractionTotal     int
	ExtractionExtracted int
	ExtractionFailed    int
	ExtractionSkipped   int

	ComponentCount int
	VulnCount      int
	IssueCount     int

	Vulns     []htmlVuln
	Issues    []htmlIssue
	ExtrNodes []htmlNode
}

type htmlVuln struct {
	ID          string
	Severity    string
	SeverityCSS string
	Package     string
	Version     string
	Description string
}

type htmlIssue struct {
	Stage   string
	Message string
}

type htmlNode struct {
	Depth  int
	Path   string
	Status string
	Format string
	Tool   string
	Detail string
}

const htmlReportCSS = `
body{font-family:system-ui,sans-serif;margin:0;padding:1rem 2rem;color:#1a1a1a;background:#fff}
h1{font-size:1.6rem;margin-bottom:0.3rem;border-bottom:2px solid #333;padding-bottom:0.3rem}
h2{font-size:1.2rem;margin-top:1.5rem;margin-bottom:0.5rem;border-bottom:1px solid #ccc}
.meta{color:#555;font-size:0.85rem;margin-bottom:1rem}
table{border-collapse:collapse;width:100%;margin-bottom:1rem;font-size:0.9rem}
th{background:#f0f0f0;text-align:left;padding:0.4rem 0.6rem;border:1px solid #ccc}
td{padding:0.35rem 0.6rem;border:1px solid #ddd;vertical-align:top}
tr:nth-child(even){background:#f9f9f9}
.badge{display:inline-block;padding:0.15rem 0.4rem;border-radius:3px;font-size:0.8rem;font-weight:bold;color:#fff}
.critical{background:#c0392b}.high{background:#e67e22}.medium{background:#f1c40f;color:#333}
.low{background:#2980b9}.negligible{background:#7f8c8d}.unknown-sev{background:#7f8c8d}
.ok{color:#27ae60;font-weight:bold}.err{color:#c0392b;font-weight:bold}
details>summary{cursor:pointer;padding:0.3rem 0}
details summary h2{display:inline;margin:0}
code{background:#f4f4f4;padding:0.1rem 0.3rem;border-radius:2px;font-size:0.85rem}
.d0{padding-left:0}.d1{padding-left:1rem}.d2{padding-left:2rem}
.d3{padding-left:3rem}.d4{padding-left:4rem}.d5{padding-left:5rem}
`

const htmlReportTemplateText = `<!DOCTYPE html>
<html lang="{{.Language}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>` + htmlReportCSS + `</style>
</head>
<body>
<h1>{{.Title}}</h1>
<div class="meta">Generated: {{.Generated}} &nbsp;|&nbsp; Generator: {{.Generator}}</div>

<h2>Summary</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Input file</td><td>{{.InputFile}}</td></tr>
<tr><td>Input size</td><td>{{.InputSize}} bytes</td></tr>
<tr><td>SHA-256</td><td><code>{{.InputSHA256}}</code></td></tr>
<tr><td>Duration</td><td>{{.Duration}}</td></tr>
<tr><td>SBOM output</td><td>{{if .SBOMPath}}{{.SBOMPath}}{{else}}&#8212;{{end}}</td></tr>
<tr><td>Sandbox</td><td>{{.SandboxName}}</td></tr>
<tr><td>Components found</td><td>{{.ComponentCount}}</td></tr>
<tr><td>Vulnerabilities</td><td>{{if gt .VulnCount 0}}<span class="badge high">{{.VulnCount}}</span>{{else}}<span class="ok">0</span>{{end}}</td></tr>
<tr><td>Processing issues</td><td>{{if gt .IssueCount 0}}<span class="badge err">{{.IssueCount}}</span>{{else}}<span class="ok">0</span>{{end}}</td></tr>
</table>

<h2>Extraction Overview</h2>
<table>
<tr><th>Status</th><th>Count</th></tr>
<tr><td>Extracted</td><td>{{.ExtractionExtracted}}</td></tr>
<tr><td>Failed</td><td>{{if gt .ExtractionFailed 0}}<span class="err">{{.ExtractionFailed}}</span>{{else}}0{{end}}</td></tr>
<tr><td>Skipped / tool missing</td><td>{{.ExtractionSkipped}}</td></tr>
<tr><td>Total nodes</td><td>{{.ExtractionTotal}}</td></tr>
</table>

{{if .Vulns}}
<details open>
<summary><h2>Vulnerability Table ({{len .Vulns}} matches)</h2></summary>
<table>
<tr><th>ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Description</th></tr>
{{range .Vulns}}<tr>
<td>{{.ID}}</td>
<td><span class="badge {{.SeverityCSS}}">{{.Severity}}</span></td>
<td>{{.Package}}</td>
<td>{{.Version}}</td>
<td>{{.Description}}</td>
</tr>{{end}}
</table>
</details>
{{end}}

{{if .Issues}}
<details open>
<summary><h2>Processing Issues ({{len .Issues}})</h2></summary>
<table>
<tr><th>Stage</th><th>Message</th></tr>
{{range .Issues}}<tr><td>{{.Stage}}</td><td>{{.Message}}</td></tr>{{end}}
</table>
</details>
{{end}}

{{if .ExtrNodes}}
<details>
<summary><h2>Extraction Log</h2></summary>
<table>
<tr><th>Path</th><th>Format</th><th>Status</th><th>Tool</th><th>Detail</th></tr>
{{range .ExtrNodes}}<tr>
<td class="d{{.Depth}}">{{.Path}}</td>
<td>{{.Format}}</td>
<td>{{.Status}}</td>
<td>{{.Tool}}</td>
<td>{{.Detail}}</td>
</tr>{{end}}
</table>
</details>
{{end}}
</body>
</html>`

var htmlReportTmpl = template.Must(template.New("html-report").Parse(htmlReportTemplateText))

// GenerateHTML writes a self-contained HTML audit report to w.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - language: the output language code ("en" or "de")
//   - w: the writer to write the HTML report to
//
// Returns an error if writing fails.
func GenerateHTML(data ReportData, language string, w io.Writer) error {
	extStats := collectExtractionStats(data.Tree)

	compCount := 0
	if data.BOM != nil && data.BOM.Components != nil {
		compCount = len(*data.BOM.Components)
	}

	// Collect vulnerability matches.
	var vulns []htmlVuln
	if data.Vulnerabilities != nil && data.Vulnerabilities.MatchesByBOMRef != nil {
		// Build a component BOMRef → name+version lookup.
		bomRefName := make(map[string]string)
		bomRefVersion := make(map[string]string)
		if data.BOM != nil && data.BOM.Components != nil {
			for _, c := range *data.BOM.Components {
				bomRefName[c.BOMRef] = c.Name
				bomRefVersion[c.BOMRef] = c.Version
			}
		}

		// Flatten and sort vulns for deterministic output.
		type vulnEntry struct {
			id     string
			bomRef string
			m      interface{ getSeverity() string }
		}
		var keys []struct {
			id     string
			bomRef string
		}
		for bomRef, matches := range data.Vulnerabilities.MatchesByBOMRef {
			for _, m := range matches {
				keys = append(keys, struct {
					id     string
					bomRef string
				}{id: m.VulnerabilityID, bomRef: bomRef})
				_ = vulnEntry{}
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].id != keys[j].id {
				return keys[i].id < keys[j].id
			}
			return keys[i].bomRef < keys[j].bomRef
		})
		seen := make(map[string]bool)
		for _, k := range keys {
			dedupeKey := k.id + "|" + k.bomRef
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			for _, m := range data.Vulnerabilities.MatchesByBOMRef[k.bomRef] {
				if m.VulnerabilityID != k.id {
					continue
				}
				sev := strings.ToLower(m.Severity)
				desc := m.Description
				if len([]rune(desc)) > 120 {
					desc = string([]rune(desc)[:120]) + "…"
				}
				vulns = append(vulns, htmlVuln{
					ID:          template.HTMLEscapeString(m.VulnerabilityID),
					Severity:    template.HTMLEscapeString(m.Severity),
					SeverityCSS: severityCSSClass(sev),
					Package:     template.HTMLEscapeString(bomRefName[k.bomRef]),
					Version:     template.HTMLEscapeString(bomRefVersion[k.bomRef]),
					Description: template.HTMLEscapeString(desc),
				})
				break
			}
		}
	}

	// Collect processing issues.
	var issues []htmlIssue
	for _, iss := range data.ProcessingIssues {
		issues = append(issues, htmlIssue{
			Stage:   template.HTMLEscapeString(iss.Stage),
			Message: template.HTMLEscapeString(iss.Message),
		})
	}

	// Collect extraction log nodes (flatten tree).
	var nodes []htmlNode
	flattenExtractionNodes(data.Tree, 0, &nodes)

	dur := data.EndTime.Sub(data.StartTime).Round(time.Millisecond).String()
	genInfo := template.HTMLEscapeString(data.Generator.String())

	td := htmlReportData{
		Title:               "extract-sbom Audit Report",
		Generated:           time.Now().Format("2006-01-02 15:04:05"),
		Generator:           genInfo,
		InputFile:           template.HTMLEscapeString(data.Input.Filename),
		InputSize:           data.Input.Size,
		InputSHA256:         template.HTMLEscapeString(data.Input.SHA256),
		Duration:            template.HTMLEscapeString(dur),
		SBOMPath:            template.HTMLEscapeString(data.SBOMPath),
		SandboxName:         template.HTMLEscapeString(data.SandboxInfo.Name),
		Language:            template.HTMLEscapeString(language),
		ExtractionTotal:     extStats.Total,
		ExtractionExtracted: extStats.Extracted,
		ExtractionFailed:    extStats.Failed,
		ExtractionSkipped:   extStats.Skipped + extStats.ToolMissing,
		ComponentCount:      compCount,
		VulnCount:           len(vulns),
		IssueCount:          len(issues),
		Vulns:               vulns,
		Issues:              issues,
		ExtrNodes:           nodes,
	}

	return htmlReportTmpl.Execute(w, td)
}

// severityCSSClass maps a lowercase severity string to a CSS class name.
func severityCSSClass(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown-sev"
	}
}

// flattenExtractionNodes recursively collects extraction nodes for display.
func flattenExtractionNodes(node *extract.ExtractionNode, depth int, out *[]htmlNode) {
	if node == nil {
		return
	}
	d := depth
	if d > 5 {
		d = 5
	}
	*out = append(*out, htmlNode{
		Depth:  d,
		Path:   template.HTMLEscapeString(node.Path),
		Status: template.HTMLEscapeString(node.Status.String()),
		Format: template.HTMLEscapeString(node.Format.Format.String()),
		Tool:   template.HTMLEscapeString(node.Tool),
		Detail: template.HTMLEscapeString(node.StatusDetail),
	})
	for _, child := range node.Children {
		flattenExtractionNodes(child, depth+1, out)
	}
}
