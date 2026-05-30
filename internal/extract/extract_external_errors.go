package extract

import (
	"fmt"
	"path/filepath"
	"strings"
)

// formatExtractionFailureDetail converts low-level sandbox/tool errors into a
// concise, user-facing failure detail that remains auditable in reports.
//
// The formatter keeps the original tool message, then appends deterministic
// hints for known failure patterns (corruption, wrong format, encrypted input).
func formatExtractionFailureDetail(binary string, node *ExtractionNode, filePath string, err error) string {
	base := summarizeToolError(err)
	detail := ""
	if base != "" {
		detail = fmt.Sprintf("%s extraction failed: %s", binary, base)
	}

	lower := strings.ToLower(base)
	switch {
	case strings.Contains(lower, "invalid tar header"):
		detail += "; hint: file appears truncated/corrupt, or it is not a real TAR stream"
	case strings.Contains(lower, "can not open the file as archive"):
		detail += "; hint: file content does not match the detected archive format, or archive is damaged"
	case strings.Contains(lower, "wrong password") || strings.Contains(lower, "data error in encrypted file"):
		detail += "; hint: archive is encrypted; configure a matching password via --password"
	case strings.Contains(lower, "headers error") || strings.Contains(lower, "unconfirmed start of archive"):
		detail += "; hint: central directory/header structure is inconsistent (often truncated file or appended payload)"
	}

	if detail == "" {
		detail = fmt.Sprintf("%s extraction failed (%s)", binary, filepath.Base(filePath))
		if node.Format.Format != 0 {
			detail += ": detected=" + node.Format.Format.String()
		}
	}

	return detail
}

// summarizeToolError extracts stable, high-signal lines from tool stderr.
//
// It strips wrapper noise, preserves up to a bounded number of actionable
// lines, and keeps warnings visible so reports explain why extraction failed.
func summarizeToolError(err error) string {
	type parseSection int
	const (
		sectionGeneric parseSection = iota
		sectionErrors
		sectionWarnings
	)

	lines := strings.Split(err.Error(), "\n")
	errors := make([]string, 0, 3)
	warnings := make([]string, 0, 2)
	generic := make([]string, 0, 2)
	section := sectionGeneric

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Strip the sandbox stderr-prefix FIRST so that section headers
		// that appear on the first stderr line (e.g. "stderr: ERRORS:") are
		// still recognised by the switch below.
		if strings.HasPrefix(line, "stderr:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "stderr:"))
			if line == "" {
				continue
			}
		}
		switch line {
		case "ERRORS:":
			section = sectionErrors
			continue
		case "WARNINGS:":
			section = sectionWarnings
			continue
		case "--":
			continue
		}
		if isToolNoiseLine(line) {
			continue
		}

		switch section {
		case sectionErrors:
			errors = append(errors, line)
		case sectionWarnings:
			warnings = append(warnings, line)
		default:
			generic = append(generic, line)
		}
	}

	if len(errors) > 0 {
		parts := limitStrings(errors, 3)
		extra := len(errors) - len(parts)
		if len(warnings) > 0 {
			parts = append(parts, "warning: "+warnings[0])
		}
		result := strings.Join(parts, "; ")
		if extra > 0 {
			result += fmt.Sprintf("; [%d more error(s)]", extra)
		}
		return result
	}
	if len(generic) > 0 {
		// Return all captured non-noise lines so that unrecognised or
		// localised output variants never silently lose information.
		parts := limitStrings(generic, 3)
		extra := len(generic) - len(parts)
		if len(warnings) > 0 {
			parts = append(parts, "warning: "+warnings[0])
		}
		result := strings.Join(parts, "; ")
		if extra > 0 {
			result += fmt.Sprintf("; [%d more line(s)]", extra)
		}
		return result
	}
	if len(warnings) > 0 {
		parts := make([]string, 0, min(len(warnings), 2))
		for _, w := range limitStrings(warnings, 2) {
			parts = append(parts, "warning: "+w)
		}
		return strings.Join(parts, "; ")
	}
	return strings.TrimSpace(err.Error())
}

// isToolNoiseLine returns true for extractor banner/status lines that do not
// carry actionable failure context.
func isToolNoiseLine(line string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	if l == "" {
		return true
	}
	// The sandbox wrapper always prefixes its own error with "sandbox:"; that
	// line is noise. The former "execution failed" substring check was
	// redundant (covered by the prefix) and too broad, as it could also filter
	// real 7-Zip diagnostics that contain those words.
	if strings.HasPrefix(l, "sandbox:") {
		return true
	}
	if strings.HasPrefix(l, "7-zip") || strings.HasPrefix(l, "scanning the drive") ||
		strings.HasPrefix(l, "extracting archive:") || strings.HasPrefix(l, "path =") ||
		strings.HasPrefix(l, "type =") || strings.HasPrefix(l, "physical size =") ||
		strings.HasPrefix(l, "headers size =") || strings.HasPrefix(l, "tail size =") ||
		strings.HasPrefix(l, "characteristics =") {
		return true
	}
	return false
}

// limitStrings returns at most maxItems values while preserving input order.
func limitStrings(values []string, maxItems int) []string {
	if len(values) <= maxItems {
		return values
	}
	return values[:maxItems]
}
