package markdown

import (
	"fmt"
	"io"
	"sort"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// writeScanNoPackageIdentitiesSubsection writes scan targets where Syft
// returned no component identities, which is a key coverage signal.
func writeScanNoPackageIdentitiesSubsection(w io.Writer, scn scanStats, t translations) {
	writeAnchoredHeading(w, 3, t.scanNoPackageIDsSection, anchorScanNoPackageIDs)
	if scn.NoComponentTasks == 0 {
		fmt.Fprintf(w, "- %s\n", t.noScanNoPackageIDs)
		return
	}

	paths := uniqueSortedPaths(scn.NoComponentPaths)
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.scanNoPackageIDsLead, len(paths)))
	const maxRows = 300
	for i, p := range paths {
		if i >= maxRows {
			fmt.Fprintf(w, "- ... (%s)\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, len(paths)-maxRows))
			break
		}
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// uniqueSortedPaths removes empty/duplicate paths and returns a sorted copy.
func uniqueSortedPaths(paths []string) []string {
	return reportjson.SortedUniqueNonEmptyStrings(paths)
}

// writeExtensionFilterSection documents which file extensions were configured
// to be skipped and which logical paths were affected.
func writeExtensionFilterSection(w io.Writer, data ReportData, ext extractionStats, t translations) {
	fmt.Fprintln(w, t.extensionFilterLead)
	fmt.Fprintln(w)

	if len(data.Config.SkipExtensions) > 0 {
		extensions := make([]string, len(data.Config.SkipExtensions))
		copy(extensions, data.Config.SkipExtensions)
		sort.Strings(extensions)
		quoted := make([]string, len(extensions))
		for i, e := range extensions {
			quoted[i] = "`" + e + "`"
		}
		fmt.Fprintf(w, "**%s:** %s\n\n", t.extensionFilterExtensionsLabel, strings.Join(quoted, ", "))
	} else {
		fmt.Fprintln(w, t.noExtensionFilteredFiles)
		return
	}

	fmt.Fprintf(w, "**%s (%d):**\n\n", t.extensionFilterSkippedLabel, ext.ExtensionFiltered)
	if ext.ExtensionFiltered == 0 {
		fmt.Fprintf(w, "- %s\n", t.noExtensionFilteredFiles)
		return
	}

	paths := make([]string, len(ext.ExtensionFilteredPaths))
	copy(paths, ext.ExtensionFilteredPaths)
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// writeComponentOccurrenceIndex renders the appendix index grouped by package
// (name+version) and lists concrete component occurrences underneath.
func writeComponentOccurrenceIndex(w io.Writer, occurrences []componentOccurrence, idx componentIndexStats, v *vulnscan.Result, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentIndexLead)

	if len(occurrences) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noIndexedComponents)
		return
	}
	groups := reportjson.BuildPackageOccurrenceGroups(occurrences)

	// Split package groups into with-PURL and without-PURL sections.
	var withPURL, withoutPURL []packageOccurrenceGroup
	for i := range groups {
		if len(groups[i].PURLs) > 0 {
			withPURL = append(withPURL, groups[i])
		} else {
			withoutPURL = append(withoutPURL, groups[i])
		}
	}

	// Write with-PURL subsection.
	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithPURLSubsection, idx.IndexedWithPURL), anchorComponentsWithPURL)
	if len(withPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withPURL {
			writePackageGroupEntry(w, withPURL[i], v, t)
		}
	}

	// Write without-PURL subsection.
	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithoutPURLSubsection, idx.IndexedWithoutPURL), anchorComponentsWithoutPURL)
	if len(withoutPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withoutPURL {
			writePackageGroupEntry(w, withoutPURL[i], v, t)
		}
	}
}

// writePackageGroupEntry renders one package group and its nested occurrences.
func writePackageGroupEntry(w io.Writer, group packageOccurrenceGroup, v *vulnscan.Result, t translations) {
	title := strings.TrimSpace(group.PackageName)
	if title == "" {
		title = t.noneValue
	}
	if strings.TrimSpace(group.Version) != "" {
		title += " " + group.Version
	}
	writeAnchoredHeading(w, 4, title, group.AnchorID)
	fmt.Fprintf(w, "- %s: `%s`\n", t.packageName, valueOrDash(group.PackageName))
	fmt.Fprintf(w, "- %s: `%s`\n", t.version, valueOrDash(group.Version))
	if len(group.PURLs) == 1 {
		fmt.Fprintf(w, "- %s: `%s`\n", t.purl, group.PURLs[0])
	} else if len(group.PURLs) > 1 {
		for _, p := range group.PURLs {
			fmt.Fprintf(w, "- %s: `%s`\n", t.purlsLabel, p)
		}
	}

	sharedVulnLines, perOccurrenceVulnLines := resolvePackageVulnerabilityBlocks(group, v, t)

	for i := range group.Occurrences {
		writeOccurrenceListEntry(w, group.Occurrences[i], t, perOccurrenceVulnLines[group.Occurrences[i].ObjectID])
	}
	writeVulnerabilityLines(w, sharedVulnLines, "")
	fmt.Fprintln(w)
}

// writeOccurrenceListEntry renders one normalized occurrence as nested list
// item inside a package-group entry.
func writeOccurrenceListEntry(w io.Writer, occ componentOccurrence, t translations, vulnLines []string) {
	fmt.Fprintf(w, "- %s: <a id=\"%s\"></a>`%s`\n", t.componentIDLabel, reportjson.OccurrenceAnchorID(occ.ObjectID), occ.ObjectID)
	for _, dp := range occ.DeliveryPaths {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.deliveryPath, dp)
	}
	switch {
	case len(occ.EvidencePaths) > 0:
		for _, evidencePath := range occ.EvidencePaths {
			fmt.Fprintf(w, "  - %s: `%s`\n", t.evidencePath, evidencePath)
		}
	case occ.EvidenceSource != "":
		fmt.Fprintf(w, "  - %s: `%s`\n", t.evidencePath, occ.EvidenceSource)
	default:
		fmt.Fprintf(w, "  - %s: %s\n", t.evidencePath, t.noEvidenceRecorded)
	}
	if occ.FoundBy != "" {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.foundBy, occ.FoundBy)
	}
	writeVulnerabilityLines(w, vulnLines, "  ")
}

func writeVulnerabilityLines(w io.Writer, lines []string, indent string) {
	for _, line := range lines {
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
