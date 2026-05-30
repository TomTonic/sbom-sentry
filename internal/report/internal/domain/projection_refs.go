package domain

import "sort"

// PreferredRefs returns primary refs if present; otherwise fallback refs.
func PreferredRefs(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// NormalizeProjectionRefs keeps schema-valid projection refs when none are available.
func NormalizeProjectionRefs(refs []string) []string {
	if len(refs) > 0 {
		return refs
	}
	return []string{}
}

// FirstNonEmptyRefs returns the first non-empty ref set as a stable fallback.
func FirstNonEmptyRefs(refSets ...[]string) []string {
	for i := range refSets {
		if len(refSets[i]) == 0 {
			continue
		}
		return refSets[i][:1]
	}
	return nil
}

// SortedUniqueStrings returns a sorted copy with duplicates removed.
func SortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	out := append([]string(nil), in...)
	sort.Strings(out)
	if len(out) < 2 {
		return out
	}

	writeIdx := 1
	for i := 1; i < len(out); i++ {
		if out[i] == out[writeIdx-1] {
			continue
		}
		out[writeIdx] = out[i]
		writeIdx++
	}
	return out[:writeIdx]
}

// SortedUniqueNonEmptyStrings returns sorted unique values while skipping empty strings.
func SortedUniqueNonEmptyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	filtered := make([]string, 0, len(in))
	for i := range in {
		if in[i] == "" {
			continue
		}
		filtered = append(filtered, in[i])
	}

	return SortedUniqueStrings(filtered)
}
