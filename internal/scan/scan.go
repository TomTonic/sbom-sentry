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
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"

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
}

// Version is the extract-sbom version string, set at build time.
var Version = "dev"

// ScanAll walks the extraction tree and invokes Syft on each scannable node.
// SyftNative leaves are scanned using the original file path; extracted
// directories are scanned at their extraction output path.
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

	for i := range results {
		cfg.EmitProgress(config.ProgressVerbose, "[scan %d/%d] start: %s", i+1, len(results), results[i].NodePath)
		start := time.Now()
		done := make(chan struct{})
		if cfg.ProgressLevel >= config.ProgressNormal {
			go func(idx int, total int, nodePath string) {
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						cfg.EmitProgress(config.ProgressNormal, "[scan %d/%d] still running: %s", idx, total, nodePath)
					}
				}
			}(i+1, len(results), results[i].NodePath)
		}
		scanNode(ctx, &results[i], root)
		close(done)

		duration := time.Since(start).Round(time.Millisecond)
		if results[i].Error != nil {
			cfg.EmitProgress(config.ProgressNormal, "[scan %d/%d] failed after %s: %s (%v)", i+1, len(results), duration, results[i].NodePath, results[i].Error)
			continue
		}

		componentCount := 0
		if results[i].BOM != nil && results[i].BOM.Components != nil {
			componentCount = len(*results[i].BOM.Components)
		}
		cfg.EmitProgress(config.ProgressVerbose, "[scan %d/%d] done in %s: %s (%d components)", i+1, len(results), duration, results[i].NodePath, componentCount)
	}

	return results, nil
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

	// Encode Syft's internal SBOM to CycloneDX JSON.
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		result.Error = fmt.Errorf("scan: create CycloneDX encoder: %w", err)
		return
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *syftSBOM); err != nil {
		result.Error = fmt.Errorf("scan: encode SBOM to CycloneDX JSON for %s: %w", target, err)
		return
	}

	// Decode CycloneDX JSON into cyclonedx-go types.
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		// Try plain JSON decode as fallback.
		bom = new(cdx.BOM)
		if jerr := json.Unmarshal(buf.Bytes(), bom); jerr != nil {
			result.Error = fmt.Errorf("scan: decode CycloneDX BOM for %s: %w (json fallback: %v)", target, err, jerr)
			return
		}
	}

	result.BOM = bom
	result.EvidencePaths = collectEvidencePaths(node, target, bom)
}

// collectEvidencePaths derives optional, deterministic evidence pointers for
// scan results where extract-sbom can name the specific internal file that
// materially supports component identification.
func collectEvidencePaths(node *extract.ExtractionNode, target string, bom *cdx.BOM) map[string][]string {
	if node == nil || bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return nil
	}

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
