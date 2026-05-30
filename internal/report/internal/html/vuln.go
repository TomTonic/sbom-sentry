package html

import (
	"sort"
	"strings"
)

// collectVulns flattens the Grype match map into a deterministically sorted,
// deduplicated slice of HTML vulnerability rows.
func collectVulns(data ReportData) []htmlVuln {
	if data.Vulnerabilities == nil || len(data.Vulnerabilities.MatchesByBOMRef) == 0 {
		return nil
	}

	bomRefName := make(map[string]string)
	bomRefVersion := make(map[string]string)
	if data.BOM != nil && data.BOM.Components != nil {
		comps := *data.BOM.Components
		for i := range comps {
			bomRefName[comps[i].BOMRef] = comps[i].Name
			bomRefVersion[comps[i].BOMRef] = comps[i].Version
		}
	}

	type vulnKey struct{ id, bomRef string }
	seen := make(map[vulnKey]bool)
	var keys []vulnKey
	for bomRef, matches := range data.Vulnerabilities.MatchesByBOMRef {
		for i := range matches {
			key := vulnKey{id: matches[i].VulnerabilityID, bomRef: bomRef}
			if seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		return keys[i].bomRef < keys[j].bomRef
	})

	vulns := make([]htmlVuln, 0, len(keys))
	for _, key := range keys {
		matches := data.Vulnerabilities.MatchesByBOMRef[key.bomRef]
		for i := range matches {
			if matches[i].VulnerabilityID != key.id {
				continue
			}
			desc := matches[i].Description
			if len([]rune(desc)) > 120 {
				desc = string([]rune(desc)[:120]) + "…"
			}
			vulns = append(vulns, htmlVuln{
				ID:          matches[i].VulnerabilityID,
				Severity:    matches[i].Severity,
				SeverityCSS: severityCSSClass(strings.ToLower(matches[i].Severity)),
				Package:     bomRefName[key.bomRef],
				Version:     bomRefVersion[key.bomRef],
				Description: desc,
			})
			break
		}
	}

	return vulns
}

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
