package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
)

// writeSuppressionReport renders normalization/suppression evidence grouped by
// reason so deduplication remains auditable.
func writeSuppressionReport(w io.Writer, suppressions []assembly.SuppressionRecord, bom *cdx.BOM, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentNormalizationLead)

	if len(suppressions) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noSuppressions)
	}

	// Group by reason for a structured overview.
	var fsArtifacts, lowValue, weakDups, purlDups []assembly.SuppressionRecord
	for i := range suppressions {
		switch suppressions[i].Reason {
		case assembly.SuppressionFSArtifact:
			fsArtifacts = append(fsArtifacts, suppressions[i])
		case assembly.SuppressionLowValueFile:
			lowValue = append(lowValue, suppressions[i])
		case assembly.SuppressionWeakDuplicate:
			weakDups = append(weakDups, suppressions[i])
		case assembly.SuppressionPURLDuplicate:
			purlDups = append(purlDups, suppressions[i])
		}
	}
	sortSuppressionRecords(fsArtifacts)
	sortSuppressionRecords(lowValue)
	sortSuppressionRecords(weakDups)
	sortSuppressionRecords(purlDups)

	resolver := newSuppressionLinkResolver(bom)

	// Summary counts.
	fmt.Fprintf(w, "| %s | %s |\n", t.reasonLabel, t.countLabel)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonFSArtifact, len(fsArtifacts))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonLowValueFile, len(lowValue))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonWeakDuplicate, len(weakDups))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonPURLDuplicate, len(purlDups))
	fmt.Fprintln(w)

	// FS-cataloger artifacts.
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchorSuppressionFSArtifacts)
	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonFSArtifact, len(fsArtifacts))
	fmt.Fprintln(w, t.suppressionOperationalFS)
	fmt.Fprintln(w)
	fmt.Fprintln(w, t.suppressionOperationalFSFollowUp)
	fmt.Fprintln(w)
	writeSuppressionReasonTable(w, fsArtifacts, resolver, t)

	// Low-value file artifacts.
	fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchorSuppressionLowValue)
	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonLowValueFile, len(lowValue))
	fmt.Fprintln(w, t.suppressionOperationalLowValue)
	fmt.Fprintln(w)
	writeSuppressionReasonTable(w, lowValue, resolver, t)

	// Weak duplicates.
	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonWeakDuplicate, len(weakDups))
	fmt.Fprintln(w, t.suppressionOperationalWeakDup)
	fmt.Fprintln(w)
	writeSuppressionReasonTable(w, weakDups, resolver, t)

	// PURL duplicates across scan nodes or evidence variants.
	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonPURLDuplicate, len(purlDups))
	fmt.Fprintln(w, t.suppressionOperationalPURLDup)
	fmt.Fprintln(w)
	writeSuppressionReasonTable(w, purlDups, resolver, t)
}

// writeSuppressionReasonTable prints a bounded, deterministic table for one
// suppression reason group.
func writeSuppressionReasonTable(w io.Writer, records []assembly.SuppressionRecord, resolver suppressionLinkResolver, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.suppressionTableDeliveryPath, t.suppressionTableComponentName, t.suppressionTableSuppressedBy)
	fmt.Fprintln(w, "|---|---|---|")
	if len(records) == 0 {
		fmt.Fprintln(w, "| - | - | - |")
		fmt.Fprintln(w)
		return
	}

	const maxRows = 30
	for i := range records {
		if i >= maxRows {
			fmt.Fprintf(w, "| ... | ... | %s |\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, len(records)-maxRows))
			break
		}
		r := records[i]
		suppressedName := r.Component.Name
		if suppressedName == "" {
			suppressedName = "-"
		}
		fmt.Fprintf(w, "| `%s` | `%s` | %s |\n",
			escapeMarkdownCell(r.DeliveryPath),
			escapeMarkdownCell(suppressedName),
			suppressedByCell(r, resolver, t),
		)
	}
	fmt.Fprintln(w)
}

// suppressionLinkCandidate is one surviving indexed component considered as a
// replacement link target for suppressed records.
type suppressionLinkCandidate struct {
	BOMRef  string
	Name    string
	FoundBy string
	Score   int
}

// suppressionLinkResolver provides delivery-path-based lookup from suppressed
// records to surviving indexed components.
type suppressionLinkResolver struct {
	byDeliveryPath map[string][]suppressionLinkCandidate
}

// newSuppressionLinkResolver builds the lookup index used by suppression
// reporting to link removed records to retained components.
func newSuppressionLinkResolver(bom *cdx.BOM) suppressionLinkResolver {
	resolver := suppressionLinkResolver{byDeliveryPath: map[string][]suppressionLinkCandidate{}}
	if bom == nil || bom.Components == nil {
		return resolver
	}

	for i := range *bom.Components {
		comp := (*bom.Components)[i]
		if comp.BOMRef == "" {
			continue
		}
		candidate := suppressionLinkCandidate{
			BOMRef:  comp.BOMRef,
			Name:    comp.Name,
			FoundBy: firstComponentPropertyValue(comp, "syft:package:foundBy"),
			Score:   suppressionLinkCandidateScore(comp),
		}
		for _, deliveryPath := range componentPropertyValues(comp, "extract-sbom:delivery-path") {
			resolver.byDeliveryPath[deliveryPath] = append(resolver.byDeliveryPath[deliveryPath], candidate)
		}
	}

	for deliveryPath := range resolver.byDeliveryPath {
		sort.Slice(resolver.byDeliveryPath[deliveryPath], func(i, j int) bool {
			a := resolver.byDeliveryPath[deliveryPath][i]
			b := resolver.byDeliveryPath[deliveryPath][j]
			if a.Score != b.Score {
				return a.Score > b.Score
			}
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.FoundBy != b.FoundBy {
				return a.FoundBy < b.FoundBy
			}
			return a.BOMRef < b.BOMRef
		})
	}

	return resolver
}

// suppressionLinkCandidateScore ranks candidate replacement components by
// package-identity strength; keep aligned with occurrenceQualityScore.
func suppressionLinkCandidateScore(comp cdx.Component) int {
	score := 0
	if comp.PackageURL != "" {
		score += 4
	}
	if comp.Version != "" {
		score += 2
	}
	if firstComponentPropertyValue(comp, "syft:package:foundBy") != "" {
		score += 2
	}
	if comp.Type != cdx.ComponentTypeFile {
		score++
	}
	return score
}

// resolve chooses the best indexed replacement BOMRef for one suppression
// record, or returns a localized explanation when no unambiguous match exists.
func (r suppressionLinkResolver) resolve(record assembly.SuppressionRecord, t translations) (string, string) {
	candidates := r.byDeliveryPath[record.DeliveryPath]
	if len(candidates) == 0 {
		return "", t.suppressedByNoIndexedMatch
	}

	if record.KeptName != "" {
		for i := range candidates {
			candidate := candidates[i]
			if candidate.Name != record.KeptName {
				continue
			}
			if record.KeptFoundBy != "" && candidate.FoundBy != record.KeptFoundBy {
				continue
			}
			return candidate.BOMRef, ""
		}
		return "", t.suppressedByReplacementNotIndexed
	}

	if len(candidates) == 1 {
		return candidates[0].BOMRef, ""
	}

	return "", t.suppressedByAmbiguousIndexedMatch
}

// suppressedByCell formats the "suppressed by" table cell with either a link
// to the retained component or an explanatory fallback message.
func suppressedByCell(record assembly.SuppressionRecord, resolver suppressionLinkResolver, t translations) string {
	bomRef, reason := resolver.resolve(record, t)
	if bomRef == "" {
		if reason == "" {
			reason = t.suppressedByNoIndexedMatch
		}
		return fmt.Sprintf("*%s*", escapeMarkdownCell(reason))
	}
	return fmt.Sprintf("[%s](#%s)", escapeMarkdownCell(bomRef), occurrenceAnchorID(bomRef))
}

// sortSuppressionRecords enforces deterministic ordering in suppression tables.
func sortSuppressionRecords(records []assembly.SuppressionRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].DeliveryPath != records[j].DeliveryPath {
			return records[i].DeliveryPath < records[j].DeliveryPath
		}
		if records[i].Component.Name != records[j].Component.Name {
			return records[i].Component.Name < records[j].Component.Name
		}
		if records[i].KeptName != records[j].KeptName {
			return records[i].KeptName < records[j].KeptName
		}
		return records[i].Component.BOMRef < records[j].Component.BOMRef
	})
}

// occurrenceAnchorID converts a BOMRef to a stable Markdown anchor id.
func occurrenceAnchorID(objectID string) string {
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
