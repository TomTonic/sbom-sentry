package json

import (
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

// MarkdownProcessingEntry is one flattened processing-table row for markdown rendering.
type MarkdownProcessingEntry struct {
	Source         string
	Location       string
	Classification string
	Status         string
	DetectedFormat string
	Tool           string
	ArchiveType    string
	ArchiveMethod  string
	Encrypted      string
	PhysicalSize   string
	Detail         string
}

// CollectMarkdownProcessingEntries flattens pipeline, extraction, and scan issues
// into a deterministic processing table model.
func CollectMarkdownProcessingEntries(data ReportData) []MarkdownProcessingEntry {
	entries := make([]MarkdownProcessingEntry, 0, len(data.ProcessingIssues)+len(data.Scans))

	for i := range data.ProcessingIssues {
		entries = append(entries, MarkdownProcessingEntry{
			Source:         "pipeline",
			Location:       data.ProcessingIssues[i].Stage,
			Classification: "pipeline-error",
			Detail:         data.ProcessingIssues[i].Message,
		})
	}

	var walk func(node *extract.ExtractionNode)
	walk = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if node.Status == extract.StatusFailed || node.Status == extract.StatusToolMissing || node.Status == extract.StatusSecurityBlocked {
			detail := node.StatusDetail
			if detail == "" {
				detail = "status=" + node.Status.String()
			}
			metaType := ""
			metaMethod := ""
			metaEncrypted := ""
			metaPhysicalSize := ""
			if node.ArchiveMeta != nil {
				metaType = node.ArchiveMeta.Type
				if len(node.ArchiveMeta.Methods) > 0 {
					metaMethod = strings.Join(node.ArchiveMeta.Methods, " / ")
				}
				if node.ArchiveMeta.HasEncryptedItem {
					metaEncrypted = "yes"
				}
				metaPhysicalSize = node.ArchiveMeta.PhysicalSize
			}
			entries = append(entries, MarkdownProcessingEntry{
				Source:         "extraction",
				Location:       node.Path,
				Classification: classifyExtractionIssue(node),
				Status:         node.Status.String(),
				DetectedFormat: node.Format.Format.String(),
				Tool:           node.Tool,
				ArchiveType:    metaType,
				ArchiveMethod:  metaMethod,
				Encrypted:      metaEncrypted,
				PhysicalSize:   metaPhysicalSize,
				Detail:         compactExtractionDetail(detail),
			})
		}
		for i := range node.Children {
			walk(node.Children[i])
		}
	}
	walk(data.Tree)

	for i := range data.Scans {
		if data.Scans[i].Error == nil {
			continue
		}
		entries = append(entries, MarkdownProcessingEntry{
			Source:         "scan",
			Location:       data.Scans[i].NodePath,
			Classification: "scan-error",
			Tool:           "syft",
			Detail:         data.Scans[i].Error.Error(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		if entries[i].Classification != entries[j].Classification {
			return entries[i].Classification < entries[j].Classification
		}
		return entries[i].Detail < entries[j].Detail
	})

	return entries
}

func classifyExtractionIssue(node *extract.ExtractionNode) string {
	if node.Status == extract.StatusToolMissing {
		return "tool-missing"
	}
	if node.Status == extract.StatusSecurityBlocked {
		return "security-blocked"
	}
	lower := strings.ToLower(node.StatusDetail)
	switch {
	case strings.Contains(lower, "wrong password") || strings.Contains(lower, "encrypted archive"):
		return "password-required"
	case strings.Contains(lower, "timeout"):
		return "timeout"
	case strings.Contains(lower, "invalid tar header") || strings.Contains(lower, "headers error") || strings.Contains(lower, "unconfirmed start of archive") || strings.Contains(lower, "unexpected end of archive"):
		return "archive-corrupt-or-truncated"
	case strings.Contains(lower, "not a valid zip") || strings.Contains(lower, "can not open the file as archive") || strings.Contains(lower, "cannot open the file as") || strings.Contains(lower, "is not archive"):
		return "format-mismatch-or-invalid-archive"
	default:
		return "extraction-failed"
	}
}

func compactExtractionDetail(detail string) string {
	trimmed := strings.TrimSpace(detail)
	if idx := strings.Index(trimmed, ": "); idx != -1 {
		prefix := trimmed[:idx]
		if strings.Contains(prefix, " extraction failed") {
			trimmed = strings.TrimSpace(trimmed[idx+2:])
		}
	}
	return trimmed
}
