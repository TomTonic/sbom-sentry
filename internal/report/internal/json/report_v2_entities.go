package json

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// entityIndexV2 stores lookup maps used while building cross-referenced entities.
// bomRefConflicts accumulates diagnostic messages when multiple components share the same BOMRef.
type entityIndexV2 struct {
	nodeByPath      map[string]string
	componentByRef  map[string]string
	componentByName map[string]string
	bomRefConflicts []string
}

// buildEntitiesV2 normalizes raw ReportData into canonical entity collections.
func buildEntitiesV2(data ReportData) (entitiesV2, entityIndexV2) {
	entities := entitiesV2{
		Nodes:           make([]nodeEntityV2, 0),
		ScanTasks:       make([]scanTaskEntityV2, 0),
		Components:      make([]componentEntityV2, 0),
		PackageGroups:   make([]packageGroupEntityV2, 0),
		Vulnerabilities: make([]vulnerabilityEntityV2, 0),
		Suppressions:    make([]suppressionEntityV2, 0),
		PolicyDecisions: make([]policyDecisionEntityV2, 0),
		Issues:          make([]issueEntityV2, 0),
	}

	index := entityIndexV2{
		nodeByPath:      map[string]string{},
		componentByRef:  map[string]string{},
		componentByName: map[string]string{},
	}

	buildNodeEntities(data.Tree, "", &entities.Nodes, index.nodeByPath)
	buildComponentEntities(data.BOM, &entities.Components, index)
	buildPackageGroupEntities(entities.Components, &entities.PackageGroups)
	buildScanTaskEntities(data.Scans, index, &entities.ScanTasks)
	buildVulnerabilityEntities(data.Vulnerabilities, index, &entities.Vulnerabilities)
	buildSuppressionEntities(data.Suppressions, index, &entities.Suppressions)
	buildPolicyDecisionEntities(data.PolicyDecisions, index, &entities.PolicyDecisions)
	buildIssueEntities(data.ProcessingIssues, &entities.Issues)

	return entities, index
}

// buildNodeEntities flattens the extraction tree into node entities and hierarchy links.
func buildNodeEntities(node *extract.ExtractionNode, parentID string, out *[]nodeEntityV2, nodeByPath map[string]string) string {
	if node == nil {
		return ""
	}

	id := stableID("node", node.Path, parentID)
	idx := len(*out)
	*out = append(*out, nodeEntityV2{
		ID:       id,
		Path:     node.Path,
		Status:   node.Status.String(),
		ParentID: parentID,
		ChildIDs: []string{},
	})
	if node.Path != "" {
		if _, exists := nodeByPath[node.Path]; !exists {
			nodeByPath[node.Path] = id
		}
	}

	childIDs := make([]string, 0, len(node.Children))
	for i := range node.Children {
		childID := buildNodeEntities(node.Children[i], id, out, nodeByPath)
		if childID != "" {
			childIDs = append(childIDs, childID)
		}
	}
	(*out)[idx].ChildIDs = childIDs
	return id
}

// buildComponentEntities adds all canonical BOM components as component entities.
func buildComponentEntities(bom *cdx.BOM, out *[]componentEntityV2, index entityIndexV2) {
	if bom == nil || bom.Components == nil {
		return
	}

	for i := range *bom.Components {
		appendComponentEntity((*bom.Components)[i], out, index, i)
	}
}

// appendComponentEntity appends one component and updates reverse lookup indexes.
func appendComponentEntity(component cdx.Component, out *[]componentEntityV2, index entityIndexV2, order int) {
	id := stableID("comp", component.BOMRef, component.PackageURL, component.Name, component.Version, string(component.Type), fmt.Sprintf("%d", order))
	entity := componentEntityV2{
		ID:      id,
		BOMRef:  component.BOMRef,
		Name:    component.Name,
		Version: component.Version,
		PURL:    component.PackageURL,
		Type:    string(component.Type),
	}
	*out = append(*out, entity)

	if component.BOMRef != "" {
		if _, exists := index.componentByRef[component.BOMRef]; exists {
			index.bomRefConflicts = append(index.bomRefConflicts,
				fmt.Sprintf("duplicate BOMRef %q: component %q@%q overwrites index entry", component.BOMRef, component.Name, component.Version))
		}
		index.componentByRef[component.BOMRef] = id
	}
	nameKey := componentNameKey(component.Name, component.Version)
	if nameKey != "" {
		if _, exists := index.componentByName[nameKey]; !exists {
			index.componentByName[nameKey] = id
		}
	}
}

// buildPackageGroupEntities groups components by PURL for package-level views.
func buildPackageGroupEntities(components []componentEntityV2, out *[]packageGroupEntityV2) {
	byPURL := map[string][]string{}
	for i := range components {
		if components[i].PURL == "" {
			continue
		}
		byPURL[components[i].PURL] = append(byPURL[components[i].PURL], components[i].ID)
	}

	purls := make([]string, 0, len(byPURL))
	for purl := range byPURL {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	for i := range purls {
		componentIDs := byPURL[purls[i]]
		sort.Strings(componentIDs)
		*out = append(*out, packageGroupEntityV2{
			ID:           stableID("pkg", purls[i]),
			PURL:         purls[i],
			ComponentIDs: componentIDs,
		})
	}
}

// buildScanTaskEntities maps scan tasks and links them to node/component entities.
func buildScanTaskEntities(scans []scan.ScanResult, index entityIndexV2, out *[]scanTaskEntityV2) {
	for i := range scans {
		componentIDs := make([]string, 0)
		if scans[i].BOM != nil && scans[i].BOM.Components != nil {
			for j := range *scans[i].BOM.Components {
				ref := strings.TrimSpace((*scans[i].BOM.Components)[j].BOMRef)
				if ref == "" {
					continue
				}
				if componentID, exists := index.componentByRef[ref]; exists {
					componentIDs = append(componentIDs, componentID)
				}
			}
		}
		sort.Strings(componentIDs)

		item := scanTaskEntityV2{
			ID:           stableID("scan", scans[i].NodePath, fmt.Sprintf("%d", i)),
			NodePath:     scans[i].NodePath,
			NodeID:       index.nodeByPath[scans[i].NodePath],
			ComponentIDs: domain.SortedUniqueStrings(componentIDs),
		}
		if scans[i].Error != nil {
			item.Error = scans[i].Error.Error()
		}
		*out = append(*out, item)
	}
}

// buildVulnerabilityEntities converts vulnerability matches into stable entities.
func buildVulnerabilityEntities(vulns *vulnscan.Result, index entityIndexV2, out *[]vulnerabilityEntityV2) {
	if vulns == nil {
		return
	}

	bomRefs := make([]string, 0, len(vulns.MatchesByBOMRef))
	for ref := range vulns.MatchesByBOMRef {
		bomRefs = append(bomRefs, ref)
	}
	sort.Strings(bomRefs)

	for _, ref := range bomRefs {
		componentID := index.componentByRef[ref]
		matches := vulns.MatchesByBOMRef[ref]
		for i := range matches {
			vulnID := strings.TrimSpace(matches[i].VulnerabilityID)
			if vulnID == "" {
				vulnID = "unknown"
			}
			*out = append(*out, vulnerabilityEntityV2{
				ID:              stableID("vuln", vulnID, componentID, ref, fmt.Sprintf("%d", i)),
				VulnerabilityID: vulnID,
				ComponentID:     componentID,
				Severity:        matches[i].Severity,
				BOMRef:          ref,
			})
		}
	}
}

// buildSuppressionEntities converts assembly suppression records into entities.
func buildSuppressionEntities(records []assembly.SuppressionRecord, index entityIndexV2, out *[]suppressionEntityV2) {
	for i := range records {
		suppressedRef := strings.TrimSpace(records[i].Component.BOMRef)
		suppressedID := ""
		if suppressedRef != "" {
			suppressedID = index.componentByRef[suppressedRef]
		}
		if suppressedID == "" {
			suppressedID = index.componentByName[componentNameKey(records[i].Component.Name, records[i].Component.Version)]
		}

		keptID := index.componentByName[componentNameKey(records[i].KeptName, "")]

		item := suppressionEntityV2{
			ID:                     stableID("sup", records[i].Reason, records[i].Component.BOMRef, records[i].Component.Name, records[i].KeptName, fmt.Sprintf("%d", i)),
			Reason:                 records[i].Reason,
			SuppressedComponentRef: suppressedRef,
			SuppressedComponentID:  suppressedID,
			KeptComponentName:      records[i].KeptName,
			KeptComponentFoundBy:   records[i].KeptFoundBy,
			KeptComponentID:        keptID,
			ResolutionStatus:       "resolved",
		}
		if item.SuppressedComponentID == "" {
			item.ResolutionStatus = "missing"
			item.ResolutionReason = "suppressed component not present in canonical component set"
		}
		*out = append(*out, item)
	}
}

// buildPolicyDecisionEntities maps policy decisions with node relations.
func buildPolicyDecisionEntities(decisions []policy.Decision, index entityIndexV2, out *[]policyDecisionEntityV2) {
	for i := range decisions {
		*out = append(*out, policyDecisionEntityV2{
			ID:       fmt.Sprintf("pol:%06d", i+1),
			Trigger:  decisions[i].Trigger,
			NodePath: decisions[i].NodePath,
			NodeID:   index.nodeByPath[decisions[i].NodePath],
			Action:   decisions[i].Action.String(),
			Detail:   decisions[i].Detail,
		})
	}
}

// buildIssueEntities maps processing issues into ordered entities.
func buildIssueEntities(issues []ProcessingIssue, out *[]issueEntityV2) {
	for i := range issues {
		*out = append(*out, issueEntityV2{
			ID:      fmt.Sprintf("issue:%06d", i+1),
			Stage:   issues[i].Stage,
			Message: issues[i].Message,
		})
	}
}

// componentNameKey creates a deterministic lookup key for name/version matching.
func componentNameKey(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" && version == "" {
		return ""
	}
	return name + "\x00" + version
}
