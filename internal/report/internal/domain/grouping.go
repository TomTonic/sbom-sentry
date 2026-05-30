package domain

import (
	"fmt"
	"sort"
	"strings"
)

// BuildPackageOccurrenceGroups groups occurrences by package name/version and
// assigns deterministic package-level anchors.
func BuildPackageOccurrenceGroups(occurrences []ComponentOccurrence) []PackageOccurrenceGroup {
	if len(occurrences) == 0 {
		return nil
	}

	type groupKey struct {
		name    string
		version string
	}

	byKey := make(map[groupKey][]ComponentOccurrence)
	order := make([]groupKey, 0)
	for i := range occurrences {
		key := groupKey{name: occurrences[i].PackageName, version: occurrences[i].Version}
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], occurrences[i])
	}

	groups := make([]PackageOccurrenceGroup, 0, len(order))
	for _, key := range order {
		groupOccurrences := append([]ComponentOccurrence(nil), byKey[key]...)
		sort.Slice(groupOccurrences, func(i, j int) bool {
			return compareOccurrence(groupOccurrences[i], groupOccurrences[j]) < 0
		})
		groups = append(groups, PackageOccurrenceGroup{
			PackageName: key.name,
			Version:     key.version,
			PURLs:       collectDistinctPURLs(groupOccurrences),
			Occurrences: groupOccurrences,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		leftPrimary := ComponentOccurrence{}
		if len(groups[i].Occurrences) > 0 {
			leftPrimary = groups[i].Occurrences[0]
		}
		rightPrimary := ComponentOccurrence{}
		if len(groups[j].Occurrences) > 0 {
			rightPrimary = groups[j].Occurrences[0]
		}
		if cmp := compareOccurrence(leftPrimary, rightPrimary); cmp != 0 {
			return cmp < 0
		}
		if groups[i].PackageName != groups[j].PackageName {
			return groups[i].PackageName < groups[j].PackageName
		}
		if groups[i].Version != groups[j].Version {
			return groups[i].Version < groups[j].Version
		}
		return strings.Join(groups[i].PURLs, "|") < strings.Join(groups[j].PURLs, "|")
	})

	usedAnchors := make(map[string]int)
	for i := range groups {
		base := packageAnchorBase(groups[i].PackageName, groups[i].Version)
		count := usedAnchors[base]
		usedAnchors[base] = count + 1
		if count == 0 {
			groups[i].AnchorID = base
			continue
		}
		groups[i].AnchorID = fmt.Sprintf("%s-%d", base, count+1)
	}

	return groups
}

func compareOccurrence(a, b ComponentOccurrence) int {
	aPrimary := firstString(a.DeliveryPaths)
	bPrimary := firstString(b.DeliveryPaths)
	if aPrimary != bPrimary {
		if aPrimary < bPrimary {
			return -1
		}
		return 1
	}
	aEvidence := firstString(a.EvidencePaths)
	bEvidence := firstString(b.EvidencePaths)
	if aEvidence != bEvidence {
		if aEvidence < bEvidence {
			return -1
		}
		return 1
	}
	if a.PackageName != b.PackageName {
		if a.PackageName < b.PackageName {
			return -1
		}
		return 1
	}
	if a.Version != b.Version {
		if a.Version < b.Version {
			return -1
		}
		return 1
	}
	if a.PURL != b.PURL {
		if a.PURL < b.PURL {
			return -1
		}
		return 1
	}
	if a.FoundBy != b.FoundBy {
		if a.FoundBy < b.FoundBy {
			return -1
		}
		return 1
	}
	if a.ObjectID < b.ObjectID {
		return -1
	}
	if a.ObjectID > b.ObjectID {
		return 1
	}
	return 0
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func collectDistinctPURLs(occurrences []ComponentOccurrence) []string {
	if len(occurrences) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(occurrences))
	purls := make([]string, 0, len(occurrences))
	for i := range occurrences {
		if occurrences[i].PURL == "" {
			continue
		}
		if _, ok := seen[occurrences[i].PURL]; ok {
			continue
		}
		seen[occurrences[i].PURL] = struct{}{}
		purls = append(purls, occurrences[i].PURL)
	}
	sort.Strings(purls)
	return purls
}

func packageAnchorBase(name string, version string) string {
	base := "package"
	if slug := anchorSlugPart(name); slug != "" {
		base += "-" + slug
	}
	if slug := anchorSlugPart(version); slug != "" {
		base += "-" + slug
	}
	return strings.TrimRight(base, "-")
}

func anchorSlugPart(value string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
