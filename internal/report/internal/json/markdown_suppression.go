package json

import (
	"sort"

	"github.com/TomTonic/extract-sbom/internal/assembly"
)

const (
	// SuppressionResolveNoIndexedMatch indicates no indexed component exists for delivery path.
	SuppressionResolveNoIndexedMatch = "no-indexed-match"
	// SuppressionResolveReplacementNotIndexed indicates kept component could not be found.
	SuppressionResolveReplacementNotIndexed = "replacement-not-indexed"
	// SuppressionResolveAmbiguousIndexedMatch indicates multiple candidates without kept-name disambiguation.
	SuppressionResolveAmbiguousIndexedMatch = "ambiguous-indexed-match"
)

// MarkdownSuppressionCandidate is one indexed replacement candidate.
type MarkdownSuppressionCandidate struct {
	BOMRef  string
	Name    string
	FoundBy string
	Score   int
}

// MarkdownSuppressionResolver resolves suppression records to surviving component references.
type MarkdownSuppressionResolver struct {
	byDeliveryPath map[string][]MarkdownSuppressionCandidate
}

// BuildMarkdownSuppressionResolver builds a ranked lookup from occurrence data.
func BuildMarkdownSuppressionResolver(occurrences []ComponentOccurrence) MarkdownSuppressionResolver {
	resolver := MarkdownSuppressionResolver{byDeliveryPath: map[string][]MarkdownSuppressionCandidate{}}
	if len(occurrences) == 0 {
		return resolver
	}

	for i := range occurrences {
		occ := occurrences[i]
		if occ.ObjectID == "" {
			continue
		}
		candidate := MarkdownSuppressionCandidate{
			BOMRef:  occ.ObjectID,
			Name:    occ.PackageName,
			FoundBy: occ.FoundBy,
			Score:   OccurrenceQualityScore(occ),
		}
		for j := range occ.DeliveryPaths {
			resolver.byDeliveryPath[occ.DeliveryPaths[j]] = append(resolver.byDeliveryPath[occ.DeliveryPaths[j]], candidate)
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

// Resolve maps one suppression record to a bom-ref link target, or a reason code.
func (r MarkdownSuppressionResolver) Resolve(record assembly.SuppressionRecord) (string, string) {
	candidates := r.byDeliveryPath[record.DeliveryPath]
	if len(candidates) == 0 {
		return "", SuppressionResolveNoIndexedMatch
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
		return "", SuppressionResolveReplacementNotIndexed
	}

	if len(candidates) == 1 {
		return candidates[0].BOMRef, ""
	}

	return "", SuppressionResolveAmbiguousIndexedMatch
}
