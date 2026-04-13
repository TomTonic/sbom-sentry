package scan

import (
	"archive/zip"
	"path"
	"path/filepath"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

// collectEvidencePaths derives optional, deterministic evidence pointers for
// scan results where extract-sbom can name the specific internal file that
// materially supports component identification.
func collectEvidencePaths(node *extract.ExtractionNode, target string, bom *cdx.BOM) map[string][]string {
	if node == nil || bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return nil
	}

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

// isManifestEvidenceCandidate checks whether file extension indicates a
// ZIP-based Java archive where a MANIFEST.MF is expected.
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

// FlattenEvidencePaths returns unique, sorted evidence paths associated with a
// scan result across all discovered components.
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
