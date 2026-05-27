package report

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// normalizeSeverity lowercases and trims raw, returning "unknown" for empty input.
func normalizeSeverity(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return s
	default:
		if s == "" {
			return "unknown"
		}
		return s
	}
}

// severityRank returns a numeric sort key for raw severity (0=critical, 5=unknown).
func severityRank(raw string) int {
	s := normalizeSeverity(raw)
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "negligible":
		return 4
	default:
		return 5
	}
}

// emptyDash returns v unchanged, or "-" when v is empty.
func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// formatEPSS formats EPSS and percentile values as human-readable text.
func formatEPSS(epss *float64, percentile *float64) string {
	if epss == nil {
		return "-"
	}
	p := fmt.Sprintf("%.1f%%", (*epss)*100)
	if percentile == nil {
		return p
	}
	return fmt.Sprintf("%s (%s)", p, formatPercentileRank((*percentile)*100))
}

// formatRisk formats risk values.
func formatRisk(risk *float64) string {
	if risk == nil {
		return "-"
	}
	return formatNumber(*risk)
}

// formatKEV formats the KEV indicator used by grype-like output.
func formatKEV(kev bool, t translations) string {
	if kev {
		return t.vulnKEVYes
	}
	return t.vulnKEVNo
}

// formatNumber renders v with a single decimal place.
func formatNumber(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// formatSeverity renders severity and appends CVSS score in parentheses.
func formatSeverity(severity string, cvss *float64) string {
	if cvss == nil {
		return strings.ToUpper(normalizeSeverity(severity))
	}
	return fmt.Sprintf("%s (%s)", strings.ToUpper(normalizeSeverity(severity)), formatNumber(*cvss))
}

// formatPercentileRank renders percentile values as ordinal ranks, e.g. 99th.
func formatPercentileRank(pct float64) string {
	whole := int(pct + 0.5)
	if whole <= 0 {
		return "0th"
	}
	if whole%100 >= 11 && whole%100 <= 13 {
		return fmt.Sprintf("%dth", whole)
	}
	switch whole % 10 {
	case 1:
		return fmt.Sprintf("%dst", whole)
	case 2:
		return fmt.Sprintf("%dnd", whole)
	case 3:
		return fmt.Sprintf("%drd", whole)
	default:
		return fmt.Sprintf("%dth", whole)
	}
}

// formatVulnerabilityReference renders plausible web URLs as Markdown links,
// while keeping non-web values as plain text.
func formatVulnerabilityReference(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if !isPlausibleWebReference(value) {
		return escapeMarkdownCell(value)
	}
	return fmt.Sprintf("[%s](<%s>)", escapeMarkdownCell(value), value)
}

// isPlausibleWebReference applies lightweight URL validation for report links.
func isPlausibleWebReference(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return true
}
