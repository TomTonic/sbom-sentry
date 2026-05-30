package json

import (
	"github.com/TomTonic/extract-sbom/internal/extract"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// buildProjectionsV2 prepares renderer-facing views from entities and raw data.
func buildProjectionsV2(data ReportData, entities entitiesV2, index entityIndexV2) projectionsV2 {
	occurrences, occurrenceStats := domain.CollectComponentOccurrences(data.BOM)
	packageGroups := domain.BuildPackageOccurrenceGroups(occurrences)

	extractionRows := buildExtractionProjectionRows(data.Tree, index)
	vulnerabilityRows := buildVulnerabilityProjectionRows(entities)
	issueRows := buildIssueProjectionRows(entities)
	componentIndexRows := buildComponentIndexProjectionRows(packageGroups, index)
	if len(componentIndexRows) == 0 {
		componentIndexRows = buildComponentFallbackProjectionRows(entities.Components)
	}
	markdownSections, markdownTOC, markdownAnchors := buildMarkdownProjectionRows(entities, extractionRows, vulnerabilityRows, componentIndexRows)
	htmlSummaryCards, htmlTableModels := buildHTMLProjectionRows(data, entities, extractionRows, vulnerabilityRows, issueRows)

	return projectionsV2{
		Generic: genericProjectionV2{
			Summary: map[string]any{
				"nodes":                        len(entities.Nodes),
				"scanTasks":                    len(entities.ScanTasks),
				"components":                   len(entities.Components),
				"packageGroups":                len(entities.PackageGroups),
				"vulnerabilities":              len(entities.Vulnerabilities),
				"suppressions":                 len(entities.Suppressions),
				"policyDecisions":              len(entities.PolicyDecisions),
				"issues":                       len(entities.Issues),
				"componentIndexStats":          occurrenceStats,
				"vulnerabilityEnrichmentState": vulnerabilityStateValue(data.Vulnerabilities),
				"vulnerabilityRequested":       vulnerabilityRequestedValue(data.Vulnerabilities),
			},
			ExtractionRows:    extractionRows,
			VulnerabilityRows: vulnerabilityRows,
			IssueRows:         issueRows,
			ComponentIndex:    componentIndexRows,
		},
		Markdown: markdownProjectionV2{
			Sections: markdownSections,
			TOC:      markdownTOC,
			Anchors:  markdownAnchors,
		},
		HTML: htmlProjectionV2{
			SummaryCards: htmlSummaryCards,
			TableModels:  htmlTableModels,
		},
	}
}

// buildExtractionProjectionRows flattens extraction tree data into ordered rows.
func buildExtractionProjectionRows(tree *extract.ExtractionNode, index entityIndexV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0)
	var walk func(node *extract.ExtractionNode, depth int)
	walk = func(node *extract.ExtractionNode, depth int) {
		if node == nil {
			return
		}
		row := projectionRowV2{
			SourceRefs: sourceRefsOrNil(index.nodeByPath[node.Path]),
			Data: map[string]any{
				"kind":   "extraction-node",
				"path":   node.Path,
				"status": node.Status.String(),
				"format": node.Format.Format.String(),
				"tool":   node.Tool,
				"detail": node.StatusDetail,
				"depth":  depth,
			},
		}
		rows = append(rows, row)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(tree, 0)
	return rows
}

// buildVulnerabilityProjectionRows builds vulnerability rows including package hints.
func buildVulnerabilityProjectionRows(entities entitiesV2) []projectionRowV2 {
	componentByID := make(map[string]componentEntityV2, len(entities.Components))
	for i := range entities.Components {
		componentByID[entities.Components[i].ID] = entities.Components[i]
	}

	rows := make([]projectionRowV2, 0, len(entities.Vulnerabilities))
	for i := range entities.Vulnerabilities {
		refs := []string{entities.Vulnerabilities[i].ID}
		component := componentEntityV2{}
		if entities.Vulnerabilities[i].ComponentID != "" {
			refs = append(refs, entities.Vulnerabilities[i].ComponentID)
			component = componentByID[entities.Vulnerabilities[i].ComponentID]
		}
		row := projectionRowV2{
			SourceRefs: refs,
			Data: map[string]any{
				"kind":            "vulnerability",
				"vulnerabilityId": entities.Vulnerabilities[i].VulnerabilityID,
				"severity":        entities.Vulnerabilities[i].Severity,
				"packageName":     component.Name,
				"installed":       component.Version,
				"bomRef":          entities.Vulnerabilities[i].BOMRef,
			},
		}
		if entities.Vulnerabilities[i].ComponentID == "" {
			row.ResolutionStatus = "missing"
			row.ResolutionReason = "component reference missing in vulnerability entity"
		}
		rows = append(rows, row)
	}
	return rows
}

// buildIssueProjectionRows emits issue rows for generic and HTML tables.
func buildIssueProjectionRows(entities entitiesV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0, len(entities.Issues))
	for i := range entities.Issues {
		rows = append(rows, projectionRowV2{
			SourceRefs: []string{entities.Issues[i].ID},
			Data: map[string]any{
				"kind":    "issue",
				"stage":   entities.Issues[i].Stage,
				"message": entities.Issues[i].Message,
			},
		})
	}
	return rows
}

// buildComponentIndexProjectionRows maps domain occurrence grouping into rows.
func buildComponentIndexProjectionRows(groups []domain.PackageOccurrenceGroup, index entityIndexV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0)
	for i := range groups {
		groupRefs := make([]string, 0, len(groups[i].Occurrences))
		for j := range groups[i].Occurrences {
			if componentID := index.componentByRef[groups[i].Occurrences[j].ObjectID]; componentID != "" {
				groupRefs = append(groupRefs, componentID)
			}
		}
		groupRefs = domain.SortedUniqueStrings(groupRefs)
		rows = append(rows, projectionRowV2{
			SourceRefs: domain.NormalizeProjectionRefs(groupRefs),
			Data: map[string]any{
				"kind":            "package-group",
				"anchorId":        groups[i].AnchorID,
				"packageName":     groups[i].PackageName,
				"version":         groups[i].Version,
				"purls":           groups[i].PURLs,
				"occurrenceCount": len(groups[i].Occurrences),
			},
		})
		for j := range groups[i].Occurrences {
			componentID := index.componentByRef[groups[i].Occurrences[j].ObjectID]
			if componentID == "" {
				continue
			}
			rows = append(rows, projectionRowV2{
				SourceRefs: []string{componentID},
				Data: map[string]any{
					"kind":            "occurrence",
					"packageAnchorId": groups[i].AnchorID,
					"anchorId":        domain.OccurrenceAnchorID(groups[i].Occurrences[j].ObjectID),
					"objectId":        groups[i].Occurrences[j].ObjectID,
					"deliveryPaths":   groups[i].Occurrences[j].DeliveryPaths,
					"evidencePaths":   groups[i].Occurrences[j].EvidencePaths,
					"evidenceSource":  groups[i].Occurrences[j].EvidenceSource,
					"foundBy":         groups[i].Occurrences[j].FoundBy,
				},
			})
		}
	}
	return rows
}

// buildComponentFallbackProjectionRows provides a projection when occurrence data is unavailable.
func buildComponentFallbackProjectionRows(components []componentEntityV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0, len(components))
	for i := range components {
		rows = append(rows, projectionRowV2{
			SourceRefs: []string{components[i].ID},
			Data: map[string]any{
				"kind":        "component-fallback",
				"packageName": components[i].Name,
				"version":     components[i].Version,
				"purl":        components[i].PURL,
				"bomRef":      components[i].BOMRef,
			},
		})
	}
	return rows
}

// buildMarkdownProjectionRows emits markdown section, toc, and anchor rows.
func buildMarkdownProjectionRows(entities entitiesV2, extractionRows, vulnerabilityRows, componentIndexRows []projectionRowV2) ([]projectionRowV2, []projectionRowV2, []projectionRowV2) {
	fallback := firstProjectionSourceRef(entities)
	sections := []struct {
		key    string
		anchor string
		level  int
		refs   []string
	}{
		{key: "summary", anchor: "summary", level: 0, refs: collectComponentIDs(entities.Components)},
		{key: "processing-issues", anchor: "processing-errors", level: 0, refs: collectIssueIDs(entities.Issues)},
		{key: "component-index", anchor: "component-occurrence-index", level: 1, refs: collectComponentIDs(entities.Components)},
		{key: "policy", anchor: "policy-decisions", level: 1, refs: collectPolicyDecisionIDs(entities.PolicyDecisions)},
		{key: "scan", anchor: "scan-results", level: 1, refs: collectScanTaskIDs(entities.ScanTasks)},
		{key: "extraction", anchor: "extraction-log", level: 1, refs: collectNodeIDs(entities.Nodes)},
		{key: "vulnerabilities", anchor: "vulnerability-summary", level: 1, refs: collectVulnerabilityIDs(entities.Vulnerabilities)},
	}

	sectionRows := make([]projectionRowV2, 0, len(sections))
	tocRows := make([]projectionRowV2, 0, len(sections))
	anchorRows := make([]projectionRowV2, 0)

	for _, section := range sections {
		refs := domain.PreferredRefs(section.refs, fallback)
		if len(refs) == 0 {
			continue
		}
		data := map[string]any{"kind": "section", "key": section.key, "anchor": section.anchor, "level": section.level}
		sectionRows = append(sectionRows, projectionRowV2{SourceRefs: refs, Data: data})
		tocRows = append(tocRows, projectionRowV2{SourceRefs: refs, Data: map[string]any{"kind": "toc-entry", "key": section.key, "anchor": section.anchor, "level": section.level}})
	}

	for i := range componentIndexRows {
		if componentIndexRows[i].Data == nil {
			continue
		}
		anchor, _ := componentIndexRows[i].Data["anchorId"].(string)
		if anchor == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: componentIndexRows[i].SourceRefs, Data: map[string]any{"kind": "anchor", "anchor": anchor}})
	}
	for i := range extractionRows {
		if extractionRows[i].Data == nil {
			continue
		}
		path, _ := extractionRows[i].Data["path"].(string)
		if path == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: extractionRows[i].SourceRefs, Data: map[string]any{"kind": "extraction-anchor", "path": path}})
	}
	for i := range vulnerabilityRows {
		if vulnerabilityRows[i].Data == nil {
			continue
		}
		vulnID, _ := vulnerabilityRows[i].Data["vulnerabilityId"].(string)
		if vulnID == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: vulnerabilityRows[i].SourceRefs, Data: map[string]any{"kind": "vulnerability-anchor", "vulnerabilityId": vulnID}})
	}

	return sectionRows, tocRows, anchorRows
}

// buildHTMLProjectionRows emits summary cards and table metadata for HTML consumers.
func buildHTMLProjectionRows(data ReportData, entities entitiesV2, extractionRows, vulnerabilityRows, issueRows []projectionRowV2) ([]projectionRowV2, []projectionRowV2) {
	summaryCards := make([]projectionRowV2, 0, 4)
	tableModels := make([]projectionRowV2, 0, 3)

	summaryCards = append(summaryCards,
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectComponentIDs(entities.Components), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "components", "count": len(entities.Components)}},
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectVulnerabilityIDs(entities.Vulnerabilities), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "vulnerabilities", "count": len(entities.Vulnerabilities), "state": vulnerabilityStateValue(data.Vulnerabilities)}},
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectIssueIDs(entities.Issues), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "issues", "count": len(entities.Issues)}},
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectNodeIDs(entities.Nodes), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "extraction", "count": len(extractionRows)}},
	)

	tableModels = append(tableModels,
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectVulnerabilityIDs(entities.Vulnerabilities), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "vulnerabilities", "rowCount": len(vulnerabilityRows), "columns": []string{"vulnerabilityId", "severity", "packageName", "installed"}}},
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectIssueIDs(entities.Issues), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "issues", "rowCount": len(issueRows), "columns": []string{"stage", "message"}}},
		projectionRowV2{SourceRefs: domain.PreferredRefs(collectNodeIDs(entities.Nodes), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "extraction-log", "rowCount": len(extractionRows), "columns": []string{"path", "format", "status", "tool", "detail"}}},
	)

	return summaryCards, tableModels
}

// vulnerabilityStateValue normalizes nil/empty vulnerability state to not-requested.
func vulnerabilityStateValue(v *vulnscan.Result) string {
	if v == nil {
		return string(vulnscan.StateNotRequested)
	}
	if v.State == "" {
		return string(vulnscan.StateNotRequested)
	}
	return string(v.State)
}

// vulnerabilityRequestedValue reports whether enrichment was requested.
func vulnerabilityRequestedValue(v *vulnscan.Result) bool {
	return v != nil && v.Requested
}

// sourceRefsOrNil returns a singleton source-ref list when the ID is non-empty.
func sourceRefsOrNil(ref string) []string {
	if ref == "" {
		return nil
	}
	return []string{ref}
}

// firstProjectionSourceRef picks a stable fallback ID for projection rows.
func firstProjectionSourceRef(entities entitiesV2) []string {
	return domain.FirstNonEmptyRefs(
		collectNodeIDs(entities.Nodes),
		collectComponentIDs(entities.Components),
		collectIssueIDs(entities.Issues),
		collectScanTaskIDs(entities.ScanTasks),
	)
}

// collectNodeIDs extracts node entity IDs in order.
func collectNodeIDs(in []nodeEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

// collectScanTaskIDs extracts scan-task entity IDs in order.
func collectScanTaskIDs(in []scanTaskEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

// collectComponentIDs extracts component entity IDs in order.
func collectComponentIDs(in []componentEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

// collectVulnerabilityIDs extracts vulnerability entity IDs in order.
func collectVulnerabilityIDs(in []vulnerabilityEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

// collectPolicyDecisionIDs extracts policy decision entity IDs in order.
func collectPolicyDecisionIDs(in []policyDecisionEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

// collectIssueIDs extracts issue entity IDs in order.
func collectIssueIDs(in []issueEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}
