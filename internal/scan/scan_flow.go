package scan

import (
	"context"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
)

// ScanAll walks the extraction tree and invokes Syft on each scannable node.
// SyftNative leaves are scanned using the original file path; extracted
// directories are scanned at their extraction output path.
//
// To reduce redundant work, extracted directories are scanned first. Packages
// discovered inside Syft-native child files are then reassigned to those child
// nodes, allowing many per-file Syft invocations to be skipped entirely.
//
// Scanning is parallelized across multiple workers (cfg.ParallelScanners).
// Results are maintained in extraction-tree walk order.
func ScanAll(ctx context.Context, root *extract.ExtractionNode, cfg config.Config) ([]ScanResult, error) { //nolint:revive // stuttering is acceptable
	var results []ScanResult
	collectScanTargets(root, &results)
	if len(results) == 0 {
		cfg.EmitProgress(config.ProgressNormal, "[scan] no scan tasks discovered")
		return results, nil
	}

	numWorkers := cfg.ParallelScanners
	if numWorkers < 1 {
		numWorkers = 1
	}

	extractedIndices, nativeIndices := partitionScanTargets(root, results)
	cfg.EmitProgress(
		config.ProgressNormal,
		"[scan] starting %d scan workers for %d tasks (%d extracted, %d syft-native)",
		numWorkers,
		len(results),
		len(extractedIndices),
		len(nativeIndices),
	)

	if len(extractedIndices) > 0 {
		parallelScanIndices(ctx, root, results, extractedIndices, numWorkers, cfg, "scan-extracted")
	}

	directNativeIndices := nativeIndices
	if len(extractedIndices) > 0 && len(nativeIndices) > 0 {
		reusedCount, unresolvedNativeIndices, err := reuseSyftNativeResultsFromExtractedScans(root, results, extractedIndices, nativeIndices)
		if err != nil {
			cfg.EmitProgress(config.ProgressNormal, "[scan] reuse of extracted directory results disabled: %v", err)
		} else {
			directNativeIndices = unresolvedNativeIndices
			if reusedCount > 0 {
				cfg.EmitProgress(config.ProgressNormal, "[scan] reused %d syft-native tasks from extracted directory scans", reusedCount)
			}
		}
	}

	if len(directNativeIndices) > 0 {
		parallelScanIndices(ctx, root, results, directNativeIndices, numWorkers, cfg, "scan-native")
	}

	return results, nil
}

// partitionScanTargets classifies result indices by node status to enforce
// Phase-2 scan ordering: extracted directories first, native leaves second.
func partitionScanTargets(root *extract.ExtractionNode, results []ScanResult) (extractedIndices []int, nativeIndices []int) {
	for idx := range results {
		node := findNode(root, results[idx].NodePath)
		if node == nil {
			continue
		}

		switch node.Status {
		case extract.StatusExtracted:
			extractedIndices = append(extractedIndices, idx)
		case extract.StatusSyftNative:
			nativeIndices = append(nativeIndices, idx)
		}
	}

	return extractedIndices, nativeIndices
}

// collectScanTargets walks the extraction tree and identifies nodes that
// should be scanned by Syft.
func collectScanTargets(node *extract.ExtractionNode, results *[]ScanResult) {
	if node == nil {
		return
	}

	switch node.Status {
	case extract.StatusSyftNative, extract.StatusExtracted:
		*results = append(*results, ScanResult{NodePath: node.Path})
	}

	for _, child := range node.Children {
		collectScanTargets(child, results)
	}
}

// findNode locates a node in the tree by path.
func findNode(root *extract.ExtractionNode, path string) *extract.ExtractionNode {
	if root == nil {
		return nil
	}
	if root.Path == path {
		return root
	}
	for _, child := range root.Children {
		if n := findNode(child, path); n != nil {
			return n
		}
	}
	return nil
}
