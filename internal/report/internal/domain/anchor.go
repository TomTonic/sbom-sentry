package domain

import "strings"

// OccurrenceAnchorID converts a component object ID to a deterministic anchor ID.
//
// This keeps cross-renderer anchor generation consistent between Markdown and
// JSON projection layers.
func OccurrenceAnchorID(objectID string) string {
	if objectID == "" {
		return "component-occurrence"
	}

	var b strings.Builder
	b.WriteString("component-")
	for _, r := range strings.ToLower(objectID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.TrimRight(b.String(), "-")
}
