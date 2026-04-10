// Package assembly merges per-node CycloneDX BOMs into a single consolidated
// SBOM. It adds container-as-module components, the dependency graph,
// composition annotations, and root metadata. The result is a complete
// CycloneDX JSON BOM suitable for downstream vulnerability assessment.
package assembly

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

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/extract"
	"github.com/sbom-sentry/internal/scan"
)

// ToolVersion is the sbom-sentry version string, set at build time.
var ToolVersion = "dev"

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
					Name:    "sbom-sentry",
					Version: ToolVersion,
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

	// Create the root component.
	rootRef := makeBOMRef(tree.Path)
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
		{Name: "sbom-sentry:delivery-path", Value: tree.Path},
		{Name: "sbom-sentry:interpret-mode", Value: cfg.InterpretMode.String()},
	}

	if cfg.RootMetadata.DeliveryDate != "" {
		rootProps = append(rootProps, cdx.Property{
			Name: "sbom-sentry:delivery-date", Value: cfg.RootMetadata.DeliveryDate,
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
	processNode(tree, &components, &dependencies, &rootDep, &compositions, scanMap, "", true)

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
	_ string, isRoot bool) {
	nodeRef := makeBOMRef(node.Path)

	// Add container component for non-root nodes.
	if !isRoot {
		comp := cdx.Component{
			BOMRef: nodeRef,
			Type:   cdx.ComponentTypeFile,
			Name:   filepath.Base(node.Path),
		}

		props := []cdx.Property{
			{Name: "sbom-sentry:delivery-path", Value: node.Path},
		}

		if node.Status != extract.StatusPending {
			props = append(props, cdx.Property{
				Name: "sbom-sentry:extraction-status", Value: node.Status.String(),
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
				props = append(props, cdx.Property{Name: "sbom-sentry:msi-product-code", Value: node.Metadata.ProductCode})
			}
			if node.Metadata.UpgradeCode != "" {
				props = append(props, cdx.Property{Name: "sbom-sentry:msi-upgrade-code", Value: node.Metadata.UpgradeCode})
			}
			if node.Metadata.Language != "" {
				props = append(props, cdx.Property{Name: "sbom-sentry:msi-language", Value: node.Metadata.Language})
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
				Name: "sbom-sentry:installer-hint", Value: node.InstallerHint,
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
		if sr.BOM.Components != nil {
			for i := range *sr.BOM.Components {
				comp := (*sr.BOM.Components)[i]
				originalRef := comp.BOMRef
				// Namespace BOMRef to avoid collisions.
				comp.BOMRef = nodeRef + "/" + comp.BOMRef

				// Add delivery-path property.
				deliveryPath := node.Path
				props := []cdx.Property{
					{Name: "sbom-sentry:delivery-path", Value: deliveryPath},
				}
				for _, evidencePath := range sr.EvidencePaths[originalRef] {
					props = append(props, cdx.Property{Name: "sbom-sentry:evidence-path", Value: evidencePath})
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
		processNode(child, components, dependencies, &nodeDep, compositions, scanMap, nodeRef, false)
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
	h := sha256.Sum256([]byte(deliveryPath))
	return "sbom-sentry:" + hex.EncodeToString(h[:8])
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
