// Package scan invokes Syft in library mode to catalog software components.
// It operates on two distinct node types from the extraction tree:
//   - SyftNative leaves: Syft scans the original file (e.g., JAR, RPM)
//   - Extracted directories: Syft scans the extraction output directory
//
// The scan module produces per-node CycloneDX BOMs that are later merged
// by the assembly module into a single consolidated SBOM.
package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	syftfile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"

	// Register a pure-Go SQLite driver required by Syft's RPM catalogers.
	_ "github.com/glebarez/go-sqlite"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
)

// ScanResult holds the CycloneDX BOM produced by scanning a single
// extraction node, along with metadata linking it back to the tree.
type ScanResult struct { //nolint:revive // stuttering is acceptable for clarity
	NodePath      string              // matches ExtractionNode.Path
	BOM           *cdx.BOM            // CycloneDX BOM for this subtree/file
	EvidencePaths map[string][]string // optional component BOMRef -> supporting internal paths
	Error         error               // non-nil if scanning failed
	syftPackages  []syftpkg.Package
}

// Version is the extract-sbom version string, set at build time.
var Version = "dev"

// ScanAll walks the extraction tree and invokes Syft on each scannable node.
// SyftNative leaves are scanned using the original file path; extracted
// directories are scanned at their extraction output path.
//
// To reduce redundant work, extracted directories are scanned first. Packages
// discovered inside Syft-native child files are then reassigned to those child
// nodes, allowing many per-file Syft invocations to be skipped entirely.
//
// Scanning is parallelized across multiple workers (controlled by cfg.ParallelScanners).
// Results are maintained in the same order as the extraction tree walk.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - root: the root of the extraction tree from extract.Extract
//   - cfg: the run configuration
//
// Returns a slice of ScanResults (one per scannable node) and an error
// only if the overall scan operation cannot proceed. Per-node failures
// are captured in individual ScanResult.Error fields.
func ScanAll(ctx context.Context, root *extract.ExtractionNode, cfg config.Config) ([]ScanResult, error) { //nolint:revive // stuttering is acceptable
	var results []ScanResult
	collectScanTargets(root, &results)
	if len(results) == 0 {
		cfg.EmitProgress(config.ProgressNormal, "[scan] no scan targets discovered")
		return results, nil
	}

	numWorkers := cfg.ParallelScanners
	if numWorkers < 1 {
		numWorkers = 1
	}

	extractedIndices, nativeIndices := partitionScanTargets(root, results)
	cfg.EmitProgress(
		config.ProgressNormal,
		"[scan] starting %d scan workers for %d targets (%d extracted, %d syft-native)",
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
				cfg.EmitProgress(config.ProgressNormal, "[scan] reused %d syft-native targets from extracted directory scans", reusedCount)
			}
		}
	}

	if len(directNativeIndices) > 0 {
		parallelScanIndices(ctx, root, results, directNativeIndices, numWorkers, cfg, "scan-native")
	}

	return results, nil
}

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

type scanTask struct {
	resultIndex int
	ordinal     int
}

const (
	scanNativeProgressInterval         = 2 * time.Second
	scanNativeVerboseCompletionMinimum = 2 * time.Second
)

type scanProgressTracker struct {
	mu         sync.Mutex
	completed  int
	nextUpdate time.Time
}

func newScanProgressTracker(label string) *scanProgressTracker {
	if label != "scan-native" {
		return nil
	}

	return &scanProgressTracker{nextUpdate: time.Now().Add(scanNativeProgressInterval)}
}

func (tracker *scanProgressTracker) markCompleted(cfg config.Config, total int) {
	if tracker == nil || total < 1 {
		return
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.completed++
	now := time.Now()
	if tracker.completed < total && now.Before(tracker.nextUpdate) {
		return
	}

	cfg.EmitProgress(config.ProgressNormal, "[scan-native] completed %d/%d targets", tracker.completed, total)
	tracker.nextUpdate = now.Add(scanNativeProgressInterval)
}

func shouldLogScanStart(label string) bool {
	return false // Suppress start logs for all scan types
}

func shouldLogScanCompletion(label string, duration time.Duration) bool {
	return label != "scan-native" || duration >= scanNativeVerboseCompletionMinimum
}

func parallelScanIndices(ctx context.Context, root *extract.ExtractionNode, results []ScanResult, indices []int, numWorkers int, cfg config.Config, label string) {
	workQueue := make(chan scanTask, len(indices))
	var wg sync.WaitGroup
	progressTracker := newScanProgressTracker(label)

	for worker := 0; worker < numWorkers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range workQueue {
				nodePath := results[task.resultIndex].NodePath
				if shouldLogScanStart(label) {
					cfg.EmitProgress(config.ProgressVerbose, "[%s %d/%d] start: %s", label, task.ordinal, len(indices), nodePath)
				}

				start := time.Now()
				done := make(chan struct{})
				if cfg.ProgressLevel >= config.ProgressNormal {
					go func(ordinal int, total int, currentNodePath string) {
						ticker := time.NewTicker(15 * time.Second)
						defer ticker.Stop()
						for {
							select {
							case <-done:
								return
							case <-ticker.C:
								cfg.EmitProgress(config.ProgressNormal, "[%s %d/%d] still running: %s", label, ordinal, total, currentNodePath)
							}
						}
					}(task.ordinal, len(indices), nodePath)
				}

				scanNode(ctx, &results[task.resultIndex], root)
				close(done)

				duration := time.Since(start).Round(time.Millisecond)
				progressTracker.markCompleted(cfg, len(indices))
				if results[task.resultIndex].Error != nil {
					cfg.EmitProgress(config.ProgressNormal, "[%s %d/%d] failed after %s: %s (%v)", label, task.ordinal, len(indices), duration, nodePath, results[task.resultIndex].Error)
					continue
				}

				componentCount := 0
				if results[task.resultIndex].BOM != nil && results[task.resultIndex].BOM.Components != nil {
					componentCount = len(*results[task.resultIndex].BOM.Components)
				}
				if shouldLogScanCompletion(label, duration) {
					cfg.EmitProgress(config.ProgressVerbose, "[%s %d/%d] done in %s: %s (%d components)", label, task.ordinal, len(indices), duration, nodePath, componentCount)
				}
			}
		}()
	}

	for ordinal, idx := range indices {
		workQueue <- scanTask{resultIndex: idx, ordinal: ordinal + 1}
	}
	close(workQueue)

	wg.Wait()
}

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

func locationMatchesTarget(location syftfile.Location, target string) bool {
	return pathMatchesScanTarget(location.RealPath, target) || pathMatchesScanTarget(location.AccessPath, target)
}

func pathMatchesScanTarget(locationPath string, target string) bool {
	if locationPath == "" || target == "" {
		return false
	}

	if locationPath == target {
		return true
	}

	return strings.HasPrefix(locationPath, target+":") || strings.HasPrefix(locationPath, target+"!") || strings.HasPrefix(locationPath, target+"/")
}

// collectScanTargets walks the extraction tree and identifies nodes that
// should be scanned by Syft.
func collectScanTargets(node *extract.ExtractionNode, results *[]ScanResult) {
	if node == nil {
		return
	}

	switch node.Status {
	case extract.StatusSyftNative:
		*results = append(*results, ScanResult{NodePath: node.Path})
	case extract.StatusExtracted:
		*results = append(*results, ScanResult{NodePath: node.Path})
	}

	for _, child := range node.Children {
		collectScanTargets(child, results)
	}
}

// findNode locates a node in the tree by path.
func findNode(root *extract.ExtractionNode, path string) *extract.ExtractionNode {
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

// scanNode performs the actual Syft scan for a single node.
func scanNode(ctx context.Context, result *ScanResult, root *extract.ExtractionNode) {
	node := findNode(root, result.NodePath)
	if node == nil {
		result.Error = fmt.Errorf("scan: node %s not found in tree", result.NodePath)
		return
	}

	// Determine the target path for Syft.
	var target string
	switch node.Status {
	case extract.StatusSyftNative:
		target = node.OriginalPath
	case extract.StatusExtracted:
		target = node.ExtractedDir
	default:
		result.Error = fmt.Errorf("scan: node %s has unexpected status %s", node.Path, node.Status)
		return
	}

	// Verify target exists.
	if _, err := os.Stat(target); err != nil {
		result.Error = fmt.Errorf("scan: target %s does not exist: %w", target, err)
		return
	}

	result.BOM = nil
	result.EvidencePaths = nil
	result.Error = nil
	result.syftPackages = nil

	// Create Syft source.
	src, err := syft.GetSource(ctx, target, nil)
	if err != nil {
		result.Error = fmt.Errorf("scan: get source for %s: %w", target, err)
		return
	}
	defer src.Close()

	// Create SBOM using Syft.
	syftSBOM, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		result.Error = fmt.Errorf("scan: syft SBOM creation for %s: %w", target, err)
		return
	}

	bom, err := convertSyftSBOMToCycloneDX(syftSBOM)
	if err != nil {
		result.Error = fmt.Errorf("scan: convert Syft SBOM to CycloneDX for %s: %w", target, err)
		return
	}

	if syftSBOM.Artifacts.Packages != nil {
		result.syftPackages = syftSBOM.Artifacts.Packages.Sorted()
	}

	result.BOM = bom
	result.EvidencePaths = collectEvidencePaths(node, target, bom)
}

func buildBOMFromPackages(packages []syftpkg.Package) (*cdx.BOM, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	syftBOM := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(packages...),
		},
	}

	return convertSyftSBOMToCycloneDX(syftBOM)
}

func convertSyftSBOMToCycloneDX(syftBOM *syftsbom.SBOM) (*cdx.BOM, error) {
	if syftBOM == nil {
		return nil, nil
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("create CycloneDX encoder: %w", err)
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *syftBOM); err != nil {
		return nil, fmt.Errorf("encode SBOM to CycloneDX JSON: %w", err)
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		bom = new(cdx.BOM)
		if jerr := json.Unmarshal(buf.Bytes(), bom); jerr != nil {
			return nil, fmt.Errorf("decode CycloneDX BOM: %w (json fallback: %v)", err, jerr)
		}
	}

	return bom, nil
}

// collectEvidencePaths derives optional, deterministic evidence pointers for
// scan results where extract-sbom can name the specific internal file that
// materially supports component identification.
func collectEvidencePaths(node *extract.ExtractionNode, target string, bom *cdx.BOM) map[string][]string {
	if node == nil || bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return nil
	}

	// SyftNative path: for JAR-type archives, find the MANIFEST.MF file and
	// record it as evidence for every component in the scan result.
	if node.Status == extract.StatusSyftNative {
		evidencePath := findManifestEvidencePath(node, target)
		if evidencePath == "" {
			return nil
		}
		evidence := make(map[string][]string, len(*bom.Components))
		for i := range *bom.Components {
			component := (*bom.Components)[i]
			if component.BOMRef == "" {
				continue
			}
			evidence[component.BOMRef] = []string{evidencePath}
		}
		if len(evidence) == 0 {
			return nil
		}
		return evidence
	}

	// Extracted-directory path: for each component, derive per-component
	// evidence from syft:location:0:path. The source file is the evidence —
	// whether it is a binary (PE, dotnet) whose version resource was read,
	// or a JAR whose MANIFEST.MF / pom.properties was inspected by Syft.
	if node.Status == extract.StatusExtracted {
		evidence := make(map[string][]string)
		for i := range *bom.Components {
			comp := (*bom.Components)[i]
			if comp.BOMRef == "" {
				continue
			}
			loc := firstPropertyValue(comp, "syft:location:0:path")
			if loc == "" {
				continue
			}
			evidencePath := path.Clean(node.Path + "/" + strings.TrimPrefix(loc, "/"))
			// Skip self-referencing evidence where evidence = delivery path.
			if evidencePath == node.Path {
				continue
			}
			evidence[comp.BOMRef] = []string{evidencePath}
		}
		if len(evidence) == 0 {
			return nil
		}
		return evidence
	}

	return nil
}

// findManifestEvidencePath returns a delivery-relative pointer to a JAR-style
// manifest when the scanned artifact is a Syft-native ZIP-based package that
// actually contains such a manifest.
func findManifestEvidencePath(node *extract.ExtractionNode, target string) string {
	if node == nil || node.Status != extract.StatusSyftNative || !isManifestEvidenceCandidate(target) {
		return ""
	}

	r, err := zip.OpenReader(target)
	if err != nil {
		return ""
	}
	defer r.Close()

	for _, file := range r.File {
		if strings.EqualFold(file.Name, "META-INF/MANIFEST.MF") {
			return path.Clean(node.Path + "/" + file.Name)
		}
	}

	return ""
}

func isManifestEvidenceCandidate(target string) bool {
	switch strings.ToLower(filepath.Ext(target)) {
	case ".jar", ".war", ".ear", ".jpi", ".hpi":
		return true
	default:
		return false
	}
}

// firstPropertyValue returns the value of the first CycloneDX property with
// the given name, or "" if not found.
func firstPropertyValue(comp cdx.Component, name string) string {
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

// FlattenEvidencePaths returns the unique, sorted evidence paths associated
// with a scan result across all discovered components.
func FlattenEvidencePaths(result ScanResult) []string {
	if len(result.EvidencePaths) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	for _, paths := range result.EvidencePaths {
		for _, evidencePath := range paths {
			if evidencePath == "" {
				continue
			}
			seen[evidencePath] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	flattened := make([]string, 0, len(seen))
	for evidencePath := range seen {
		flattened = append(flattened, evidencePath)
	}
	sort.Strings(flattened)
	return flattened
}
