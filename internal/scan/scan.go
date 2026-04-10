package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"sbom-sentry/internal/extract"
)

// ScanResult stores the per-node scan outcome and a CycloneDX BOM fragment.
type ScanResult struct {
	NodePath string
	SBOM     *cyclonedx.BOM
	Error    error
}

// ScanAll walks the extraction tree and scans each scannable node.
// SyftNative leaves scan the original file; extracted nodes scan their output directory.
func ScanAll(root *extract.ExtractionNode) ([]ScanResult, error) {
	nodes := collectScannable(root)
	results := make([]ScanResult, 0, len(nodes))
	for _, n := range nodes {
		bom, err := scanNode(n)
		results = append(results, ScanResult{
			NodePath: n.Path,
			SBOM:     bom,
			Error:    err,
		})
	}
	return results, nil
}

func collectScannable(root *extract.ExtractionNode) []*extract.ExtractionNode {
	out := make([]*extract.ExtractionNode, 0, 16)
	var walk func(*extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}
		if n.Status == extract.SyftNative || n.Status == extract.Extracted {
			out = append(out, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(root)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func scanNode(node *extract.ExtractionNode) (*cyclonedx.BOM, error) {
	target := node.ExtractedDir
	if node.Status == extract.SyftNative {
		target = node.OriginalPath
	}
	if target == "" {
		return nil, fmt.Errorf("empty scan target for node %s", node.Path)
	}

	components, err := componentsFromTarget(node, target)
	if err != nil {
		return nil, err
	}

	bom := cyclonedx.NewBOM()
	bom.Version = 1
	bom.BOMFormat = cyclonedx.BOMFormat
	bom.SpecVersion = cyclonedx.SpecVersion1_6
	bom.Metadata = &cyclonedx.Metadata{Timestamp: time.Now().UTC().Format(time.RFC3339)}
	bom.Components = &components

	return bom, nil
}

func componentsFromTarget(node *extract.ExtractionNode, target string) ([]cyclonedx.Component, error) {
	if node.Status == extract.SyftNative {
		h, err := sha256File(target)
		if err != nil {
			return nil, err
		}
		hashes := []cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: h}}
		props := []cyclonedx.Property{{Name: "sbom-sentry:delivery-path", Value: node.Path}}
		return []cyclonedx.Component{{
			BOMRef:      "scan:" + sanitizeBOMRef(node.Path),
			Type:        cyclonedx.ComponentTypeFile,
			Name:        filepath.Base(target),
			Hashes:      &hashes,
			Properties:  &props,
			Description: "scanned as Syft-native artifact",
		}}, nil
	}

	components := make([]cyclonedx.Component, 0, 64)
	err := filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(target, path)
		if err != nil {
			return err
		}
		deliveryPath := toSlash(filepath.Join(node.Path, rel))
		h, err := sha256File(path)
		if err != nil {
			return err
		}

		hashes := []cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: h}}
		props := []cyclonedx.Property{{Name: "sbom-sentry:delivery-path", Value: deliveryPath}}

		components = append(components, cyclonedx.Component{
			BOMRef:     "scan:" + sanitizeBOMRef(deliveryPath),
			Type:       cyclonedx.ComponentTypeFile,
			Name:       filepath.Base(path),
			Hashes:     &hashes,
			Properties: &props,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk scan target %s: %w", target, err)
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	return components, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hash: %w", err)
	}
	defer f.Close()

	h := sha256.New() //nolint:gosec // SHA-256 chosen intentionally for SBOM hashing.
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func toSlash(path string) string {
	return strings.ReplaceAll(path, string(filepath.Separator), "/")
}

func sanitizeBOMRef(v string) string {
	clean := strings.ReplaceAll(v, " ", "_")
	clean = strings.ReplaceAll(clean, "\\", "/")
	return clean
}
