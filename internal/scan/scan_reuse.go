package scan

import (
	"fmt"
	"strings"

	syftfile "github.com/anchore/syft/syft/file"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

// reuseSyftNativeResultsFromExtractedScans reassigns packages discovered in
// extracted-directory scans to descendant syft-native nodes when Syft location
// evidence proves ownership.
//
// Returns:
// - reusedCount: number of native nodes fully resolved from extracted scans
// - unresolved: native indices that still require direct Syft scans
func reuseSyftNativeResultsFromExtractedScans(root *extract.ExtractionNode, results []ScanResult, extractedIndices []int, nativeIndices []int) (int, []int, error) {
	packagesByNativeNode := make(map[string][]syftpkg.Package)

	for _, idx := range extractedIndices {
		if results[idx].Error != nil || len(results[idx].syftPackages) == 0 {
			continue
		}

		node := findNode(root, results[idx].NodePath)
		if node == nil {
			continue
		}

		descendantNativeNodes := collectDescendantSyftNativeNodes(node)
		if len(descendantNativeNodes) == 0 {
			continue
		}

		assignedPackagesByNode := make(map[string][]syftpkg.Package)
		remainingPackages := make([]syftpkg.Package, 0, len(results[idx].syftPackages))
		for i := range results[idx].syftPackages {
			pkg := results[idx].syftPackages[i]
			ownerPath := matchPackageToSyftNativeNode(pkg, descendantNativeNodes)
			if ownerPath == "" {
				remainingPackages = append(remainingPackages, pkg)
				continue
			}

			assignedPackagesByNode[ownerPath] = append(assignedPackagesByNode[ownerPath], pkg)
		}

		if len(assignedPackagesByNode) == 0 {
			continue
		}

		filteredBOM, err := buildBOMFromPackages(remainingPackages)
		if err != nil {
			return 0, nativeIndices, fmt.Errorf("filter extracted scan %s: %w", node.Path, err)
		}

		results[idx].BOM = filteredBOM
		results[idx].syftPackages = remainingPackages

		for ownerPath, pkgs := range assignedPackagesByNode {
			packagesByNativeNode[ownerPath] = append(packagesByNativeNode[ownerPath], pkgs...)
		}
	}

	reusedCount := 0
	unresolved := make([]int, 0, len(nativeIndices))
	for _, idx := range nativeIndices {
		node := findNode(root, results[idx].NodePath)
		if node == nil {
			unresolved = append(unresolved, idx)
			continue
		}

		pkgs := packagesByNativeNode[node.Path]
		if len(pkgs) == 0 {
			unresolved = append(unresolved, idx)
			continue
		}

		bom, err := buildBOMFromPackages(pkgs)
		if err != nil {
			unresolved = append(unresolved, idx)
			continue
		}

		results[idx].BOM = bom
		results[idx].Error = nil
		results[idx].EvidencePaths = collectEvidencePaths(node, node.OriginalPath, bom)
		results[idx].syftPackages = pkgs
		reusedCount++
	}

	return reusedCount, unresolved, nil
}

// collectDescendantSyftNativeNodes returns all syft-native descendants below a
// given node, depth-first.
func collectDescendantSyftNativeNodes(node *extract.ExtractionNode) []*extract.ExtractionNode {
	if node == nil {
		return nil
	}

	var descendants []*extract.ExtractionNode
	for _, child := range node.Children {
		if child.Status == extract.StatusSyftNative {
			descendants = append(descendants, child)
		}
		descendants = append(descendants, collectDescendantSyftNativeNodes(child)...)
	}

	return descendants
}

// matchPackageToSyftNativeNode maps one Syft package to the most specific
// syft-native descendant whose original file path matches package location
// evidence.
func matchPackageToSyftNativeNode(pkg syftpkg.Package, nodes []*extract.ExtractionNode) string {
	bestMatch := ""
	bestMatchLength := -1

	for _, location := range pkg.Locations.ToSlice() {
		for _, node := range nodes {
			if node == nil || node.OriginalPath == "" {
				continue
			}

			if !locationMatchesTarget(location, node.OriginalPath) {
				continue
			}

			if len(node.OriginalPath) > bestMatchLength {
				bestMatch = node.Path
				bestMatchLength = len(node.OriginalPath)
			}
		}
	}

	return bestMatch
}

// locationMatchesTarget compares both Syft location paths against one scan
// target path.
func locationMatchesTarget(location syftfile.Location, target string) bool {
	return pathMatchesScanTarget(location.RealPath, target) || pathMatchesScanTarget(location.AccessPath, target)
}

// pathMatchesScanTarget checks exact and nested archive/path encodings used by
// Syft locations.
func pathMatchesScanTarget(locationPath string, target string) bool {
	if locationPath == "" || target == "" {
		return false
	}

	if locationPath == target {
		return true
	}

	return strings.HasPrefix(locationPath, target+":") || strings.HasPrefix(locationPath, target+"!") || strings.HasPrefix(locationPath, target+"/")
}
