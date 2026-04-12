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
			candidates := normalizeScanComponents(node, sr)
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

func normalizeScanComponents(node *extract.ExtractionNode, sr *scan.ScanResult) []scanComponentCandidate {
	if node == nil || sr == nil || sr.BOM == nil || sr.BOM.Components == nil {
		return nil
	}

	candidates := make([]scanComponentCandidate, 0, len(*sr.BOM.Components))
	for i := range *sr.BOM.Components {
		comp := (*sr.BOM.Components)[i]
		if isFileCatalogerArtifact(comp) {
			continue
		}

		foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
		if isLowValueFileArtifact(comp, foundBy) {
			continue
		}

		deliveryPath := node.Path
		if node.Status == extract.StatusExtracted {
			if loc := syftLocationPath(comp); loc != "" {
				deliveryPath = node.Path + "/" + strings.TrimPrefix(loc, "/")
			}
		}

		evidence := append([]string(nil), sr.EvidencePaths[comp.BOMRef]...)
		sort.Strings(evidence)

		candidates = append(candidates, scanComponentCandidate{
			component:    comp,
			deliveryPath: deliveryPath,
			evidence:     evidence,
			foundBy:      foundBy,
			order:        i,
		})
	}

	candidates = mergeDuplicateScanCandidates(candidates)

	sort.Slice(candidates, func(i, j int) bool {
		return compareScanCandidates(candidates[i], candidates[j]) < 0
	})

	return candidates
}

func mergeDuplicateScanCandidates(candidates []scanComponentCandidate) []scanComponentCandidate {
	if len(candidates) < 2 {
		return candidates
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
			continue
		}

		merged = append(merged, group...)
	}

	return merged
}

func scanCandidateLocusKey(candidate scanComponentCandidate) string {
	return candidate.deliveryPath + "\x00" + strings.Join(candidate.evidence, "\x1f")
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
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cdx.BOM, error) {
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

	// Process the tree.
	processNode(tree, &components, &dependencies, &rootDep, &compositions, scanMap, refAssigner, true)

	dependencies = append(dependencies, rootDep)

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

	return bom, nil
}

// processNode recursively processes the extraction tree, creating components,
// dependencies, and composition annotations.
func processNode(node *extract.ExtractionNode, components *[]cdx.Component, dependencies *[]cdx.Dependency,
	parentDep *cdx.Dependency, compositions *[]cdx.Composition, scanMap map[string]*scan.ScanResult,
	refAssigner *bomRefAssigner, isRoot bool) {
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
		candidates := normalizeScanComponents(node, sr)
		for i := range candidates {
			comp := candidates[i].component
			comp.BOMRef = refAssigner.RefForComponent(node.Path, comp, i)

			props := []cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: candidates[i].deliveryPath},
			}
			for _, evidencePath := range candidates[i].evidence {
				props = append(props, cdx.Property{Name: "extract-sbom:evidence-path", Value: evidencePath})
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
		processNode(child, components, dependencies, &nodeDep, compositions, scanMap, refAssigner, false)
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
