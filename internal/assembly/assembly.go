// Package assembly merges per-node CycloneDX BOMs into a single consolidated
// SBOM. It adds container-as-module components, the dependency graph,
// composition annotations, and root metadata. The result is a complete
// CycloneDX JSON BOM suitable for downstream vulnerability assessment.
package assembly

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

var shortBOMRefEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// Suppression reason constants used in SuppressionRecord.
const (
	// SuppressionFSArtifact identifies Syft file-cataloger entries that carry
	// an absolute temp-directory path as the component Name. These represent
	// the physical file record and are always superseded by a dedicated
	// package cataloger (e.g. java-archive-cataloger) when one is present.
	// When no package cataloger identifies the file, the entry is dropped to
	// prevent temp-path leakage and SBOM noise.
	SuppressionFSArtifact = "fs-cataloger-artifact"

	// SuppressionLowValueFile identifies type=file entries that carry no
	// PURL, version, or foundBy metadata. They convey no identification
	// value and cannot be matched to a vulnerability database.
	SuppressionLowValueFile = "low-value-file"

	// SuppressionWeakDuplicate identifies entries at the same
	// (delivery-path, evidence-path) locus whose quality score is lower than
	// the best entry in that group. Only dropped when the best entry is
	// clearly superior (score ≥ 4, i.e. has a PURL).
	SuppressionWeakDuplicate = "weak-duplicate"

	// SuppressionPURLDuplicate identifies entries that carry the same PURL as
	// another component and are therefore collapsed into a single surviving
	// representative. The survivor inherits all unique leaf-most delivery and
	// evidence paths from the whole group.
	SuppressionPURLDuplicate = "purl-duplicate"
)

// SuppressionRecord documents a component that was removed from the SBOM
// during normalization or deduplication. Every record that appears here must
// also appear in the audit report so that the suppression decision is traceable.
type SuppressionRecord struct {
	// Reason is one of the Suppression* constants.
	Reason string
	// Component is the suppressed entry exactly as emitted by Syft.
	Component cdx.Component
	// FoundBy is the syft:package:foundBy value of the suppressed entry.
	FoundBy string
	// DeliveryPath is the delivery-path context at the time of suppression.
	DeliveryPath string
	// KeptName is the name of the component that replaced this one.
	// Only set for duplicate suppressions.
	KeptName string
	// KeptFoundBy is the foundBy of the replacement component.
	// Only set for duplicate suppressions.
	KeptFoundBy string
}

type bomRefAssigner struct {
	byKey   map[string]string
	byRef   map[string]string
	makeRef func(string, int) string
}

type scanComponentCandidate struct {
	component    cdx.Component
	deliveryPath string
	evidence     []string
	foundBy      string
	order        int
}

func newBOMRefAssigner(tree *extract.ExtractionNode, scanMap map[string]*scan.ScanResult) *bomRefAssigner {
	return newBOMRefAssignerWithKeys(collectBOMRefKeys(tree, scanMap), makeBOMRefWithSalt)
}

func newBOMRefAssignerWithKeys(keys []string, factory func(string, int) string) *bomRefAssigner {
	assigner := &bomRefAssigner{
		byKey:   make(map[string]string, len(keys)),
		byRef:   make(map[string]string, len(keys)),
		makeRef: factory,
	}

	sortedKeys := append([]string(nil), keys...)
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		assigner.assign(key)
	}

	return assigner
}

func (a *bomRefAssigner) RefForNode(deliveryPath string) string {
	return a.assign(deliveryPath)
}

func (a *bomRefAssigner) RefForComponent(nodePath string, component cdx.Component, index int) string {
	return a.assign(componentRefKey(nodePath, component, index))
}

func (a *bomRefAssigner) assign(key string) string {
	if ref, ok := a.byKey[key]; ok {
		return ref
	}

	for salt := 0; ; salt++ {
		ref := a.makeRef(key, salt)
		existingKey, exists := a.byRef[ref]
		if !exists || existingKey == key {
			a.byKey[key] = ref
			a.byRef[ref] = key
			return ref
		}
	}
}

func collectBOMRefKeys(tree *extract.ExtractionNode, scanMap map[string]*scan.ScanResult) []string {
	if tree == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var visit func(node *extract.ExtractionNode)
	visit = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}

		seen[node.Path] = struct{}{}
		if sr, ok := scanMap[node.Path]; ok && sr != nil && sr.Error == nil && sr.BOM != nil && sr.BOM.Components != nil {
			candidates, _ := normalizeScanComponents(node, sr)
			for i := range candidates {
				seen[componentRefKey(node.Path, candidates[i].component, i)] = struct{}{}
			}
		}

		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(tree)

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys
}

func componentRefKey(nodePath string, component cdx.Component, index int) string {
	if component.BOMRef != "" {
		return "component\x00" + nodePath + "\x00" + component.BOMRef
	}

	return fmt.Sprintf(
		"component\x00%s\x00%d\x00%s\x00%s\x00%s",
		nodePath,
		index,
		component.Type,
		component.Name,
		component.Version,
	)
}

// isFileCatalogerArtifact returns true for Syft file-cataloger entries that
// represent the file itself rather than an identified package. These have
// type=file and an absolute filesystem path (the temp extraction directory)
// as the component name. Filtering them out avoids temp-path leaks and
// duplicates with the properly-identified library-type entry.
func isFileCatalogerArtifact(comp cdx.Component) bool {
	return comp.Type == cdx.ComponentTypeFile && strings.HasPrefix(comp.Name, "/")
}

// syftLocationPath extracts the syft:location:0:path property from a
// component. This path indicates where Syft found the file within the
// scanned directory and can be used to refine the delivery-path.
func syftLocationPath(comp cdx.Component) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == "syft:location:0:path" {
			return prop.Value
		}
	}
	return ""
}

func normalizeScanComponents(node *extract.ExtractionNode, sr *scan.ScanResult) ([]scanComponentCandidate, []SuppressionRecord) {
	if node == nil || sr == nil || sr.BOM == nil || sr.BOM.Components == nil {
		return nil, nil
	}

	var suppressions []SuppressionRecord
	candidates := make([]scanComponentCandidate, 0, len(*sr.BOM.Components))
	for i := range *sr.BOM.Components {
		comp := (*sr.BOM.Components)[i]
		if isFileCatalogerArtifact(comp) {
			foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionFSArtifact,
				Component:    comp,
				FoundBy:      foundBy,
				DeliveryPath: node.Path,
			})
			continue
		}

		foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
		if isLowValueFileArtifact(comp, foundBy) {
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionLowValueFile,
				Component:    comp,
				FoundBy:      foundBy,
				DeliveryPath: node.Path,
			})
			continue
		}

		deliveryPath := node.Path
		if node.Status == extract.StatusExtracted {
			if loc := syftLocationPath(comp); loc != "" {
				deliveryPath = node.Path + "/" + strings.TrimPrefix(loc, "/")
			}
		}

		rawEvidence := sr.EvidencePaths[comp.BOMRef]
		evidence := make([]string, 0, len(rawEvidence))
		for _, ep := range rawEvidence {
			// Skip evidence that equals the delivery path — it adds no information.
			if ep != deliveryPath {
				evidence = append(evidence, ep)
			}
		}
		sort.Strings(evidence)

		candidates = append(candidates, scanComponentCandidate{
			component:    comp,
			deliveryPath: deliveryPath,
			evidence:     evidence,
			foundBy:      foundBy,
			order:        i,
		})
	}

	merged, mergeSuppressed := mergeDuplicateScanCandidates(candidates)
	suppressions = append(suppressions, mergeSuppressed...)

	merged, purlSuppressed := mergePURLDuplicateScanCandidates(merged)
	suppressions = append(suppressions, purlSuppressed...)

	sort.Slice(merged, func(i, j int) bool {
		return compareScanCandidates(merged[i], merged[j]) < 0
	})

	return merged, suppressions
}

func mergeDuplicateScanCandidates(candidates []scanComponentCandidate) ([]scanComponentCandidate, []SuppressionRecord) {
	if len(candidates) < 2 {
		return candidates, nil
	}

	groups := make(map[string][]scanComponentCandidate)
	keys := make([]string, 0)
	for i := range candidates {
		key := scanCandidateLocusKey(candidates[i])
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], candidates[i])
	}
	sort.Strings(keys)

	var suppressions []SuppressionRecord
	merged := make([]scanComponentCandidate, 0, len(candidates))
	for _, key := range keys {
		group := groups[key]
		if len(group) == 1 {
			merged = append(merged, group[0])
			continue
		}

		best := pickBestScanCandidate(group)
		if shouldCollapseScanCandidateGroup(group, best) {
			merged = append(merged, best)
			for i := range group {
				if group[i].component.BOMRef == best.component.BOMRef && group[i].order == best.order {
					continue
				}
				suppressions = append(suppressions, SuppressionRecord{
					Reason:       SuppressionWeakDuplicate,
					Component:    group[i].component,
					FoundBy:      group[i].foundBy,
					DeliveryPath: group[i].deliveryPath,
					KeptName:     best.component.Name,
					KeptFoundBy:  best.foundBy,
				})
			}
			continue
		}

		merged = append(merged, group...)
	}

	return merged, suppressions
}

func scanCandidateLocusKey(candidate scanComponentCandidate) string {
	return candidate.deliveryPath + "\x00" + strings.Join(candidate.evidence, "\x1f")
}

// mergePURLDuplicateScanCandidates performs a second-pass deduplication that
// collapses candidates with the same PURL and delivery path regardless of
// evidence differences. Syft occasionally emits two entries for the same
// physical JAR — one cataloged from the filename pattern (no evidence) and
// one from its MANIFEST.MF (with evidence). Both carry the same PURL and
// delivery path but different evidence sets; the first pass cannot catch them
// because its locus key includes evidence. This pass groups by (PURL,
// deliveryPath) and keeps the candidate with the most evidence.
func mergePURLDuplicateScanCandidates(candidates []scanComponentCandidate) ([]scanComponentCandidate, []SuppressionRecord) {
	if len(candidates) < 2 {
		return candidates, nil
	}

	type purlLocusKey struct{ purl, deliveryPath string }
	groups := make(map[purlLocusKey][]int) // key → indices into candidates
	var keyOrder []purlLocusKey

	for i := range candidates {
		if candidates[i].component.PackageURL == "" {
			continue
		}
		k := purlLocusKey{candidates[i].component.PackageURL, candidates[i].deliveryPath}
		if _, exists := groups[k]; !exists {
			keyOrder = append(keyOrder, k)
		}
		groups[k] = append(groups[k], i)
	}

	suppress := make(map[int]struct{})
	var suppressions []SuppressionRecord

	for _, k := range keyOrder {
		idxs := groups[k]
		if len(idxs) < 2 {
			continue
		}

		// Pick the candidate with the most evidence; break ties by quality
		// score then order.
		bestIdx := idxs[0]
		for _, idx := range idxs[1:] {
			c := candidates[idx]
			b := candidates[bestIdx]
			if len(c.evidence) > len(b.evidence) {
				bestIdx = idx
			} else if len(c.evidence) == len(b.evidence) {
				cs := scanCandidateQualityScore(c)
				bs := scanCandidateQualityScore(b)
				if cs > bs || (cs == bs && c.order < b.order) {
					bestIdx = idx
				}
			}
		}

		best := candidates[bestIdx]
		for _, idx := range idxs {
			if idx == bestIdx {
				continue
			}
			suppress[idx] = struct{}{}
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionPURLDuplicate,
				Component:    candidates[idx].component,
				FoundBy:      candidates[idx].foundBy,
				DeliveryPath: candidates[idx].deliveryPath,
				KeptName:     best.component.Name,
				KeptFoundBy:  best.foundBy,
			})
		}
	}

	if len(suppress) == 0 {
		return candidates, suppressions
	}

	merged := make([]scanComponentCandidate, 0, len(candidates)-len(suppress))
	for i := range candidates {
		if _, ok := suppress[i]; !ok {
			merged = append(merged, candidates[i])
		}
	}
	return merged, suppressions
}

func pickBestScanCandidate(group []scanComponentCandidate) scanComponentCandidate {
	best := group[0]
	bestScore := scanCandidateQualityScore(best)
	for i := 1; i < len(group); i++ {
		score := scanCandidateQualityScore(group[i])
		if score > bestScore || (score == bestScore && compareScanCandidates(group[i], best) < 0) {
			best = group[i]
			bestScore = score
		}
	}
	return best
}

func compareScanCandidates(a, b scanComponentCandidate) int {
	if a.deliveryPath != b.deliveryPath {
		if a.deliveryPath < b.deliveryPath {
			return -1
		}
		return 1
	}
	aEvidence := ""
	if len(a.evidence) > 0 {
		aEvidence = a.evidence[0]
	}
	bEvidence := ""
	if len(b.evidence) > 0 {
		bEvidence = b.evidence[0]
	}
	if aEvidence != bEvidence {
		if aEvidence < bEvidence {
			return -1
		}
		return 1
	}
	if a.component.Name != b.component.Name {
		if a.component.Name < b.component.Name {
			return -1
		}
		return 1
	}
	if a.component.Version != b.component.Version {
		if a.component.Version < b.component.Version {
			return -1
		}
		return 1
	}
	if a.component.PackageURL != b.component.PackageURL {
		if a.component.PackageURL < b.component.PackageURL {
			return -1
		}
		return 1
	}
	if a.foundBy != b.foundBy {
		if a.foundBy < b.foundBy {
			return -1
		}
		return 1
	}
	if a.component.BOMRef != b.component.BOMRef {
		if a.component.BOMRef < b.component.BOMRef {
			return -1
		}
		return 1
	}
	if a.order < b.order {
		return -1
	}
	if a.order > b.order {
		return 1
	}
	return 0
}

func scanCandidateQualityScore(candidate scanComponentCandidate) int {
	score := 0
	if candidate.component.PackageURL != "" {
		score += 4
	}
	if candidate.foundBy != "" {
		score += 3
	}
	if candidate.component.Version != "" {
		score += 2
	}
	if candidate.component.Name != "" && !strings.Contains(candidate.component.Name, "/") {
		score++
	}
	return score
}

func shouldCollapseScanCandidateGroup(group []scanComponentCandidate, best scanComponentCandidate) bool {
	if scanCandidateQualityScore(best) < 4 {
		return false
	}

	for i := range group {
		candidate := group[i]
		if candidate.component.BOMRef == best.component.BOMRef && candidate.order == best.order {
			continue
		}
		if !isWeakScanCandidate(candidate) {
			return false
		}
	}

	return true
}

func isWeakScanCandidate(candidate scanComponentCandidate) bool {
	if candidate.component.PackageURL != "" || candidate.foundBy != "" || candidate.component.Version != "" {
		return false
	}
	name := candidate.component.Name
	if name == "" {
		return true
	}
	if strings.Contains(name, "/") {
		return true
	}

	base := path.Base(candidate.deliveryPath)
	baseNoExt := strings.TrimSuffix(base, path.Ext(base))
	return strings.EqualFold(name, base) || strings.EqualFold(name, baseNoExt)
}

func isLowValueFileArtifact(comp cdx.Component, foundBy string) bool {
	if comp.Type != cdx.ComponentTypeFile {
		return false
	}
	return comp.PackageURL == "" && comp.Version == "" && foundBy == ""
}

func firstComponentPropertyValue(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == name && prop.Value != "" {
			return prop.Value
		}
	}
	return ""
}

// deduplicateGlobalComponents performs cross-node deduplication on the final
// assembled component list. Components with the same PURL are collapsed into
// a single entry regardless of delivery path. The surviving component
// inherits all unique leaf-most delivery-path and evidence-path properties
// from the suppressed entries, and redundant ancestor container paths are
// dropped. Dependency graph references are rewritten so no dangling BOMRefs
// remain.
func deduplicateGlobalComponents(components []cdx.Component, dependencies []cdx.Dependency) ([]cdx.Component, []SuppressionRecord) {
	// Index: PURL → list of component indices.
	groups := make(map[string][]int)
	var keyOrder []string
	for i := range components {
		comp := components[i]
		purl := comp.PackageURL
		if purl == "" {
			continue // only dedup components with PURL
		}
		// Container-as-module nodes (type=file) are structural; skip them.
		if comp.Type == cdx.ComponentTypeFile {
			continue
		}
		if _, exists := groups[purl]; !exists {
			keyOrder = append(keyOrder, purl)
		}
		groups[purl] = append(groups[purl], i)
	}

	// For each group with >1 entries, pick the best and suppress the rest.
	suppress := make(map[int]struct{})
	// refRewrite maps suppressed BOMRef → surviving BOMRef for dependency fixup.
	refRewrite := make(map[string]string)
	var suppressions []SuppressionRecord

	for _, purl := range keyOrder {
		idxs := groups[purl]
		if len(idxs) < 2 {
			continue
		}

		// Pick the entry with the most evidence; break ties by quality/order.
		bestIdx := idxs[0]
		for _, idx := range idxs[1:] {
			if globalComponentBetter(components[idx], components[bestIdx]) {
				bestIdx = idx
			}
		}

		// Collect all delivery-path, evidence-path, evidence-source values
		// from every entry in the group so nothing is lost.
		mergedProps := collectMergedProperties(components, idxs)

		best := &components[bestIdx]
		replaceMultiValueProperties(best, mergedProps)

		for _, idx := range idxs {
			if idx == bestIdx {
				continue
			}
			suppress[idx] = struct{}{}
			refRewrite[components[idx].BOMRef] = best.BOMRef
			dp := componentPropertyValue(components[idx], "extract-sbom:delivery-path")
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionPURLDuplicate,
				Component:    components[idx],
				FoundBy:      firstComponentPropertyValue(components[idx], "syft:package:foundBy"),
				DeliveryPath: dp,
				KeptName:     best.Name,
				KeptFoundBy:  firstComponentPropertyValue(*best, "syft:package:foundBy"),
			})
		}
	}

	if len(suppress) == 0 {
		return components, nil
	}

	// Build filtered component list.
	filtered := make([]cdx.Component, 0, len(components)-len(suppress))
	for i := range components {
		if _, ok := suppress[i]; !ok {
			filtered = append(filtered, components[i])
		}
	}

	// Rewrite dependency references so no dangling refs remain.
	for i := range dependencies {
		if newRef, ok := refRewrite[dependencies[i].Ref]; ok {
			dependencies[i].Ref = newRef
		}
		if dependencies[i].Dependencies != nil {
			rewritten := make([]string, 0, len(*dependencies[i].Dependencies))
			seen := make(map[string]struct{})
			for _, ref := range *dependencies[i].Dependencies {
				if newRef, ok := refRewrite[ref]; ok {
					ref = newRef
				}
				if _, dup := seen[ref]; !dup {
					seen[ref] = struct{}{}
					rewritten = append(rewritten, ref)
				}
			}
			*dependencies[i].Dependencies = rewritten
		}
	}

	return filtered, suppressions
}

// mergedPropertyNames lists the property names that are collected across all
// entries in a PURL group and merged into the surviving component.
var mergedPropertyNames = []string{
	"extract-sbom:delivery-path",
	"extract-sbom:evidence-path",
	"extract-sbom:evidence-source",
}

// collectMergedProperties gathers all unique values for the merged property
// names across the given component indices. For logical path properties it
// keeps only leaf-most values so an enclosing archive path does not survive
// alongside a more specific nested artifact path.
func collectMergedProperties(components []cdx.Component, idxs []int) map[string][]string {
	sets := make(map[string]map[string]struct{}, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		sets[name] = make(map[string]struct{})
	}

	for _, idx := range idxs {
		comp := components[idx]
		if comp.Properties == nil {
			continue
		}
		for _, prop := range *comp.Properties {
			if s, ok := sets[prop.Name]; ok && prop.Value != "" {
				s[prop.Value] = struct{}{}
			}
		}
	}

	result := make(map[string][]string, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		vals := make([]string, 0, len(sets[name]))
		for v := range sets[name] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		vals = pruneMergedPathValues(name, vals)
		if len(vals) > 0 {
			result[name] = vals
		}
	}
	return result
}

func pruneMergedPathValues(name string, values []string) []string {
	switch name {
	case "extract-sbom:delivery-path", "extract-sbom:evidence-path":
		return leafMostLogicalPaths(values)
	default:
		return values
	}
}

func leafMostLogicalPaths(values []string) []string {
	if len(values) < 2 {
		return values
	}

	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		cleaned = append(cleaned, path.Clean(value))
	}
	if len(cleaned) < 2 {
		return cleaned
	}

	kept := make([]string, 0, len(cleaned))
	for i, candidate := range cleaned {
		redundant := false
		for j, other := range cleaned {
			if i == j {
				continue
			}
			if isAncestorLogicalPath(candidate, other) {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func isAncestorLogicalPath(ancestor, descendant string) bool {
	ancestor = strings.TrimSuffix(path.Clean(ancestor), "/")
	descendant = path.Clean(descendant)
	if ancestor == "" || ancestor == "." || ancestor == descendant {
		return false
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

// replaceMultiValueProperties replaces the merged property names on comp with
// the union of values from the whole PURL group, preserving all other props.
func replaceMultiValueProperties(comp *cdx.Component, merged map[string][]string) {
	isReplaced := make(map[string]struct{}, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		isReplaced[name] = struct{}{}
	}

	var kept []cdx.Property
	if comp.Properties != nil {
		kept = make([]cdx.Property, 0, len(*comp.Properties))
		for _, prop := range *comp.Properties {
			if _, ok := isReplaced[prop.Name]; !ok {
				kept = append(kept, prop)
			}
		}
	}
	for _, name := range mergedPropertyNames {
		for _, val := range merged[name] {
			kept = append(kept, cdx.Property{Name: name, Value: val})
		}
	}
	kept = uniqueSortedProperties(kept)
	comp.Properties = &kept
}

// globalComponentBetter returns true if a is a better representative than b
// for a global PURL group. Prefers more evidence, then higher quality score,
// then earlier BOMRef for determinism.
func globalComponentBetter(a, b cdx.Component) bool {
	aEvidence := countPropertyValues(a, "extract-sbom:evidence-path")
	bEvidence := countPropertyValues(b, "extract-sbom:evidence-path")
	if aEvidence != bEvidence {
		return aEvidence > bEvidence
	}
	aScore := globalQualityScore(a)
	bScore := globalQualityScore(b)
	if aScore != bScore {
		return aScore > bScore
	}
	return a.BOMRef < b.BOMRef
}

func globalQualityScore(comp cdx.Component) int {
	score := 0
	if comp.PackageURL != "" {
		score += 4
	}
	foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
	if foundBy != "" {
		score += 3
	}
	if comp.Version != "" {
		score += 2
	}
	if comp.Name != "" {
		score++
	}
	return score
}

func componentPropertyValue(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == name {
			return prop.Value
		}
	}
	return ""
}

func countPropertyValues(comp cdx.Component, name string) int {
	if comp.Properties == nil {
		return 0
	}
	count := 0
	for _, prop := range *comp.Properties {
		if prop.Name == name && prop.Value != "" {
			count++
		}
	}
	return count
}

// evidenceSourceFromCataloger maps a Syft cataloger name (foundBy) to a
// human-readable description of the evidence source for the identification.
func evidenceSourceFromCataloger(foundBy string) string {
	switch {
	case strings.Contains(foundBy, "java-archive"):
		return "Java archive metadata (MANIFEST.MF / pom.properties)"
	case strings.Contains(foundBy, "java-pom"):
		return "Maven POM metadata"
	case strings.Contains(foundBy, "pe-binary"):
		return "PE version resource"
	case strings.Contains(foundBy, "dotnet-portable-executable"):
		return ".NET PE assembly metadata"
	case strings.Contains(foundBy, "dotnet-deps"):
		return ".NET deps.json"
	case strings.Contains(foundBy, "rpm"):
		return "RPM package header"
	case strings.Contains(foundBy, "dpkg"):
		return "Debian dpkg metadata"
	case strings.Contains(foundBy, "apk-db"):
		return "Alpine APK metadata"
	case strings.Contains(foundBy, "npm"):
		return "npm package.json"
	case strings.Contains(foundBy, "python"):
		return "Python package metadata"
	case strings.Contains(foundBy, "go-module"):
		return "Go module metadata"
	case strings.Contains(foundBy, "rust"):
		return "Rust Cargo metadata"
	case strings.Contains(foundBy, "conan"):
		return "Conan package metadata"
	case strings.Contains(foundBy, "linux-kernel"):
		return "Linux kernel metadata"
	case foundBy != "":
		return foundBy
	default:
		return ""
	}
}

// Assemble builds the final, unified CycloneDX BOM from the extraction tree
// and per-node scan results. It creates container-as-module components,
// merges discovered packages, builds the dependency graph, and annotates
// composition completeness.
//
// Parameters:
//   - tree: the root ExtractionNode from extract.Extract
//   - scans: the per-node scan results from scan.ScanAll
//   - cfg: the run configuration (for root metadata and formatting)
//
// Returns the consolidated CycloneDX BOM or an error if assembly fails.
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cdx.BOM, []SuppressionRecord, error) {
	generatorInfo := buildinfo.Read()

	bom := cdx.NewBOM()
	bom.BOMFormat = "CycloneDX"
	bom.SpecVersion = cdx.SpecVersion1_6

	// Use input file's modification time for determinism.
	var serialTimestamp string
	if info, err := os.Stat(cfg.InputPath); err == nil {
		serialTimestamp = info.ModTime().UTC().Format(time.RFC3339)
	}

	// Set metadata.
	bom.Metadata = &cdx.Metadata{
		Timestamp: serialTimestamp,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "extract-sbom",
					Version: generatorInfo.Version,
					Properties: &[]cdx.Property{
						{Name: "extract-sbom:build", Value: generatorInfo.String()},
						{Name: "extract-sbom:vcs-revision", Value: generatorInfo.Revision},
						{Name: "extract-sbom:vcs-time", Value: generatorInfo.Time},
						{Name: "extract-sbom:vcs-modified", Value: fmt.Sprintf("%t", generatorInfo.Modified)},
					},
				},
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "syft",
					Version: scan.Version,
				},
			},
		},
	}

	// Build scan results map for quick lookup.
	scanMap := make(map[string]*scan.ScanResult)
	for i := range scans {
		scanMap[scans[i].NodePath] = &scans[i]
	}
	refAssigner := newBOMRefAssigner(tree, scanMap)

	// Create the root component.
	rootRef := refAssigner.RefForNode(tree.Path)
	rootComponent := cdx.Component{
		BOMRef: rootRef,
		Type:   cdx.ComponentTypeApplication,
		Name:   deriveRootName(cfg),
	}

	if cfg.RootMetadata.Version != "" {
		rootComponent.Version = cfg.RootMetadata.Version
	}

	if cfg.RootMetadata.Manufacturer != "" {
		rootComponent.Supplier = &cdx.OrganizationalEntity{
			Name: cfg.RootMetadata.Manufacturer,
		}
	}

	// Add root properties.
	rootProps := []cdx.Property{
		{Name: "extract-sbom:delivery-path", Value: tree.Path},
		{Name: "extract-sbom:interpret-mode", Value: cfg.InterpretMode.String()},
		{Name: "extract-sbom:generator-version", Value: generatorInfo.Version},
		{Name: "extract-sbom:generator-build", Value: generatorInfo.String()},
	}

	if cfg.RootMetadata.DeliveryDate != "" {
		rootProps = append(rootProps, cdx.Property{
			Name: "extract-sbom:delivery-date", Value: cfg.RootMetadata.DeliveryDate,
		})
	}

	for k, v := range cfg.RootMetadata.Properties {
		rootProps = append(rootProps, cdx.Property{Name: k, Value: v})
	}

	// Add file hash.
	if hash, err := computeSHA256(cfg.InputPath); err == nil {
		rootComponent.Hashes = &[]cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: hash},
		}
	}

	// Sort properties for determinism.
	sort.Slice(rootProps, func(i, j int) bool {
		if rootProps[i].Name == rootProps[j].Name {
			return rootProps[i].Value < rootProps[j].Value
		}
		return rootProps[i].Name < rootProps[j].Name
	})
	rootComponent.Properties = &rootProps

	bom.Metadata.Component = &rootComponent

	// Collect all components and dependencies.
	var components []cdx.Component
	var dependencies []cdx.Dependency
	var compositions []cdx.Composition

	// Root dependency.
	rootDep := cdx.Dependency{Ref: rootRef}

	// Process the tree, collecting suppression records for the audit report.
	var suppressions []SuppressionRecord
	processNode(tree, &components, &dependencies, &rootDep, &compositions, scanMap, refAssigner, true, &suppressions)

	dependencies = append(dependencies, rootDep)

	// Global cross-node deduplication: components from different scan nodes
	// can describe the same physical file (same PURL + same delivery path).
	// For example, a JAR found by scanning an extracted directory AND by a
	// direct SyftNative scan of the same JAR. Per-node dedup cannot catch
	// these; they must be deduplicated after all nodes have been processed.
	components, globalSuppressions := deduplicateGlobalComponents(components, dependencies)
	suppressions = append(suppressions, globalSuppressions...)

	// Sort components by BOMRef for determinism.
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	// Sort dependencies by Ref.
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Ref < dependencies[j].Ref
	})
	for i := range dependencies {
		sortDependencyRefs(&dependencies[i])
	}

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}
	if len(compositions) > 0 {
		bom.Compositions = &compositions
	}

	return bom, suppressions, nil
}

// processNode recursively processes the extraction tree, creating components,
// dependencies, and composition annotations.
func processNode(node *extract.ExtractionNode, components *[]cdx.Component, dependencies *[]cdx.Dependency,
	parentDep *cdx.Dependency, compositions *[]cdx.Composition, scanMap map[string]*scan.ScanResult,
	refAssigner *bomRefAssigner, isRoot bool, suppressions *[]SuppressionRecord) {
	nodeRef := refAssigner.RefForNode(node.Path)

	// Add container component for non-root nodes.
	if !isRoot {
		comp := cdx.Component{
			BOMRef: nodeRef,
			Type:   cdx.ComponentTypeFile,
			Name:   filepath.Base(node.Path),
		}

		props := []cdx.Property{
			{Name: "extract-sbom:delivery-path", Value: node.Path},
		}

		if node.Status != extract.StatusPending {
			props = append(props, cdx.Property{
				Name: "extract-sbom:extraction-status", Value: node.Status.String(),
			})
		}

		// Add MSI metadata if available.
		if node.Metadata != nil {
			if node.Metadata.ProductName != "" {
				comp.Name = node.Metadata.ProductName
			}
			if node.Metadata.ProductVersion != "" {
				comp.Version = node.Metadata.ProductVersion
			}
			if node.Metadata.Manufacturer != "" {
				comp.Supplier = &cdx.OrganizationalEntity{
					Name: node.Metadata.Manufacturer,
				}
				// Generate CPE from MSI metadata.
				cpe := generateCPE(node.Metadata.Manufacturer, comp.Name, comp.Version)
				if cpe != "" {
					comp.CPE = cpe
				}
			}
			if node.Metadata.ProductCode != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-product-code", Value: node.Metadata.ProductCode})
			}
			if node.Metadata.UpgradeCode != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-upgrade-code", Value: node.Metadata.UpgradeCode})
			}
			if node.Metadata.Language != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-language", Value: node.Metadata.Language})
			}
		}

		// Add hash if we can compute it.
		if node.OriginalPath != "" {
			if hash, err := computeSHA256(node.OriginalPath); err == nil {
				comp.Hashes = &[]cdx.Hash{
					{Algorithm: cdx.HashAlgoSHA256, Value: hash},
				}
			}
		}

		// Record installer-semantic hint when the extraction layer flagged it.
		if node.InstallerHint != "" {
			props = append(props, cdx.Property{
				Name: "extract-sbom:installer-hint", Value: node.InstallerHint,
			})
		}

		sort.Slice(props, func(i, j int) bool {
			if props[i].Name == props[j].Name {
				return props[i].Value < props[j].Value
			}
			return props[i].Name < props[j].Name
		})
		comp.Properties = &props

		*components = append(*components, comp)

		// Add to parent's dependency list.
		if parentDep.Dependencies == nil {
			deps := make([]string, 0)
			parentDep.Dependencies = &deps
		}
		*parentDep.Dependencies = append(*parentDep.Dependencies, nodeRef)
	}

	// Node dependency (its own children and discovered packages).
	nodeDep := cdx.Dependency{Ref: nodeRef}

	// Add composition annotation.
	var compositionAggregate cdx.CompositionAggregate
	switch node.Status {
	case extract.StatusExtracted:
		compositionAggregate = cdx.CompositionAggregateComplete
	case extract.StatusSkipped, extract.StatusFailed, extract.StatusToolMissing:
		compositionAggregate = cdx.CompositionAggregateIncomplete
	case extract.StatusSecurityBlocked:
		compositionAggregate = cdx.CompositionAggregateIncomplete
	case extract.StatusSyftNative:
		compositionAggregate = cdx.CompositionAggregateComplete
	default:
		compositionAggregate = cdx.CompositionAggregateUnknown
	}

	// Merge scan results.
	if sr, ok := scanMap[node.Path]; ok && sr.Error == nil && sr.BOM != nil {
		candidates, nodeSuppressed := normalizeScanComponents(node, sr)
		*suppressions = append(*suppressions, nodeSuppressed...)
		for i := range candidates {
			comp := candidates[i].component
			comp.BOMRef = refAssigner.RefForComponent(node.Path, comp, i)

			props := []cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: candidates[i].deliveryPath},
			}
			for _, evidencePath := range candidates[i].evidence {
				props = append(props, cdx.Property{Name: "extract-sbom:evidence-path", Value: evidencePath})
			}
			if src := evidenceSourceFromCataloger(candidates[i].foundBy); src != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:evidence-source", Value: src})
			}
			if comp.Properties != nil {
				props = append(props, *comp.Properties...)
			}
			props = uniqueSortedProperties(props)
			comp.Properties = &props

			*components = append(*components, comp)

			// Add to node's dependency list.
			if nodeDep.Dependencies == nil {
				deps := make([]string, 0)
				nodeDep.Dependencies = &deps
			}
			*nodeDep.Dependencies = append(*nodeDep.Dependencies, comp.BOMRef)
		}
	} else if sr, ok := scanMap[node.Path]; ok && sr.Error != nil {
		compositionAggregate = cdx.CompositionAggregateUnknown
	}

	*compositions = append(*compositions, cdx.Composition{
		Aggregate: compositionAggregate,
		Assemblies: &[]cdx.BOMReference{
			cdx.BOMReference(nodeRef),
		},
	})

	// Recurse into children.
	for _, child := range node.Children {
		processNode(child, components, dependencies, &nodeDep, compositions, scanMap, refAssigner, false, suppressions)
	}

	if !isRoot {
		*dependencies = append(*dependencies, nodeDep)
	} else if nodeDep.Dependencies != nil {
		// For root, merge nodeDep into parentDep.
		if parentDep.Dependencies == nil {
			parentDep.Dependencies = nodeDep.Dependencies
		} else {
			*parentDep.Dependencies = append(*parentDep.Dependencies, *nodeDep.Dependencies...)
		}
	}
}

func sortDependencyRefs(dep *cdx.Dependency) {
	if dep == nil || dep.Dependencies == nil {
		return
	}
	sort.Slice(*dep.Dependencies, func(i, j int) bool {
		return (*dep.Dependencies)[i] < (*dep.Dependencies)[j]
	})
}

func uniqueSortedProperties(props []cdx.Property) []cdx.Property {
	if len(props) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(props))
	unique := make([]cdx.Property, 0, len(props))
	for _, prop := range props {
		key := prop.Name + "\x00" + prop.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, prop)
	}

	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Name == unique[j].Name {
			return unique[i].Value < unique[j].Value
		}
		return unique[i].Name < unique[j].Name
	})

	return unique
}

// WriteSBOM writes the consolidated CycloneDX BOM to the specified file path.
//
// Parameters:
//   - bom: the CycloneDX BOM to write
//   - path: the output file path
//
// Returns an error if the file cannot be written or encoding fails.
func WriteSBOM(bom *cdx.BOM, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("assembly: create SBOM file %s: %w", path, err)
	}
	defer f.Close()

	encoder := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("assembly: encode SBOM: %w", err)
	}

	return nil
}

// deriveRootName produces the root component name from config or filename.
func deriveRootName(cfg config.Config) string {
	if cfg.RootMetadata.Name != "" {
		return cfg.RootMetadata.Name
	}
	return filepath.Base(cfg.InputPath)
}

// makeBOMRef creates a deterministic BOMRef from a delivery path.
func makeBOMRef(deliveryPath string) string {
	return makeBOMRefWithSalt(deliveryPath, 0)
}

func makeBOMRefWithSalt(key string, salt int) string {
	payload := key
	if salt > 0 {
		payload = fmt.Sprintf("%s\x00%d", key, salt)
	}

	h := sha256.Sum256([]byte(payload))
	token := shortBOMRefEncoding.EncodeToString(h[:5])
	return "extract-sbom:" + token[:4] + "_" + token[4:8]
}

// generateCPE creates a CPE 2.3 string from manufacturer, product, and version.
// It follows NVD normalization: lowercase, spaces replaced with underscores,
// special characters stripped.
func generateCPE(manufacturer, product, version string) string {
	vendor := normalizeCPEField(manufacturer)
	prod := normalizeCPEField(product)
	ver := normalizeCPEField(version)

	if vendor == "" || prod == "" {
		return ""
	}

	if ver == "" {
		ver = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, prod, ver)
}

// normalizeCPEField normalizes a string for CPE use.
func normalizeCPEField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	// Remove characters not allowed in CPE fields.
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// computeSHA256 computes the SHA-256 hash of a file.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
