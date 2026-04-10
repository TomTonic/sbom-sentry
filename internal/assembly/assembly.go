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

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"sbom-sentry/internal/config"
	"sbom-sentry/internal/extract"
	"sbom-sentry/internal/scan"
)

// Assemble merges extraction-tree context and per-node scan BOM fragments into
// a single consolidated CycloneDX BOM for output generation.
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cyclonedx.BOM, error) {
	if tree == nil {
		return nil, fmt.Errorf("nil extraction tree")
	}

	rootRef := "root:" + sanitizeBOMRef(tree.Path)
	rootName := cfg.RootMetadata.Name
	if rootName == "" {
		rootName = filepath.Base(tree.Path)
	}

	rootProps := []cyclonedx.Property{{Name: "sbom-sentry:delivery-path", Value: tree.Path}}
	if cfg.RootMetadata.DeliveryDate != "" {
		rootProps = append(rootProps, cyclonedx.Property{Name: "sbom-sentry:delivery-date", Value: cfg.RootMetadata.DeliveryDate})
	}
	for k, v := range cfg.RootMetadata.Properties {
		rootProps = append(rootProps, cyclonedx.Property{Name: k, Value: v})
	}
	sort.Slice(rootProps, func(i, j int) bool { return rootProps[i].Name < rootProps[j].Name })

	rootComponent := cyclonedx.Component{
		BOMRef:      rootRef,
		Type:        cyclonedx.ComponentTypeApplication,
		Name:        rootName,
		Version:     cfg.RootMetadata.Version,
		Properties:  &rootProps,
		Description: "delivery root component",
	}
	if cfg.RootMetadata.Manufacturer != "" {
		o := &cyclonedx.OrganizationalEntity{Name: cfg.RootMetadata.Manufacturer}
		rootComponent.Supplier = o
		rootComponent.Manufacturer = o
	}

	components := []cyclonedx.Component{rootComponent}
	dependencies := make(map[string]map[string]struct{})
	containerRefByPath := map[string]string{tree.Path: rootRef}
	scanRefsByNode := map[string][]string{}
	compositions := make([]cyclonedx.Composition, 0, 32)

	var walk func(parent *extract.ExtractionNode, node *extract.ExtractionNode)
	walk = func(parent *extract.ExtractionNode, node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if parent != nil {
			ref := "container:" + sanitizeBOMRef(node.Path)
			containerRefByPath[node.Path] = ref

			comp := makeContainerComponent(node, ref)
			components = append(components, comp)
			addDep(dependencies, containerRefByPath[parent.Path], ref)

			aggregate := cyclonedx.CompositionAggregateComplete
			if node.Status == extract.Skipped || node.Status == extract.Failed || node.Status == extract.SecurityBlocked {
				aggregate = cyclonedx.CompositionAggregateIncomplete
			}
			refs := []cyclonedx.BOMReference{cyclonedx.BOMReference(ref)}
			compositions = append(compositions, cyclonedx.Composition{Aggregate: aggregate, Assemblies: &refs})
		}

		for _, child := range node.Children {
			walk(node, child)
		}
	}
	walk(nil, tree)

	for _, sr := range scans {
		if sr.Error != nil || sr.SBOM == nil || sr.SBOM.Components == nil {
			if ref, ok := containerRefByPath[sr.NodePath]; ok {
				agg := cyclonedx.CompositionAggregateUnknown
				refs := []cyclonedx.BOMReference{cyclonedx.BOMReference(ref)}
				compositions = append(compositions, cyclonedx.Composition{Aggregate: agg, Assemblies: &refs})
			}
			continue
		}

		for _, c := range *sr.SBOM.Components {
			prefixed := c
			prefixed.BOMRef = "scan:" + sanitizeBOMRef(sr.NodePath) + ":" + sanitizeBOMRef(c.BOMRef)
			ensureDeliveryPathProperty(&prefixed, sr.NodePath)
			components = append(components, prefixed)
			scanRefsByNode[sr.NodePath] = append(scanRefsByNode[sr.NodePath], prefixed.BOMRef)
		}
	}

	for nodePath, refs := range scanRefsByNode {
		containerRef := containerRefByPath[nodePath]
		if containerRef == "" {
			containerRef = rootRef
		}
		for _, dep := range refs {
			addDep(dependencies, containerRef, dep)
		}
	}

	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	depList := flattenDeps(dependencies)
	sort.Slice(depList, func(i, j int) bool { return depList[i].Ref < depList[j].Ref })

	sort.Slice(compositions, func(i, j int) bool {
		lhs := ""
		rhs := ""
		if compositions[i].Assemblies != nil && len(*compositions[i].Assemblies) > 0 {
			lhs = string((*compositions[i].Assemblies)[0])
		}
		if compositions[j].Assemblies != nil && len(*compositions[j].Assemblies) > 0 {
			rhs = string((*compositions[j].Assemblies)[0])
		}
		return lhs < rhs
	})

	tools := []cyclonedx.Tool{{
		Vendor:  "sbom-sentry",
		Name:    "sbom-sentry",
		Version: "dev",
	}}

	bom := cyclonedx.NewBOM()
	bom.Version = 1
	bom.BOMFormat = cyclonedx.BOMFormat
	bom.SpecVersion = cyclonedx.SpecVersion1_6
	bom.Components = &components
	bom.Dependencies = &depList
	bom.Compositions = &compositions
	bom.Metadata = &cyclonedx.Metadata{
		Component: &rootComponent,
		Tools: &cyclonedx.ToolsChoice{
			Tools: &tools,
		},
	}

	return bom, nil
}

func makeContainerComponent(node *extract.ExtractionNode, ref string) cyclonedx.Component {
	name := filepath.Base(node.Path)
	props := []cyclonedx.Property{
		{Name: "sbom-sentry:delivery-path", Value: node.Path},
		{Name: "sbom-sentry:status", Value: string(node.Status)},
	}
	if node.Tool != "" {
		props = append(props, cyclonedx.Property{Name: "sbom-sentry:tool", Value: node.Tool})
	}
	if node.SandboxUsed != "" {
		props = append(props, cyclonedx.Property{Name: "sbom-sentry:sandbox", Value: node.SandboxUsed})
	}

	comp := cyclonedx.Component{
		BOMRef:      ref,
		Type:        cyclonedx.ComponentTypeFile,
		Name:        name,
		Properties:  &props,
		Description: "container artifact",
	}

	if h, err := sha256File(node.OriginalPath); err == nil {
		hashes := []cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: h}}
		comp.Hashes = &hashes
	}

	if node.Metadata != nil {
		if node.Metadata.ProductName != "" {
			comp.Name = node.Metadata.ProductName
		}
		comp.Version = node.Metadata.ProductVersion
		if cpe := cpeFromMSIMetadata(node.Metadata); cpe != "" {
			comp.CPE = cpe
		}
		*comp.Properties = append(*comp.Properties,
			cyclonedx.Property{Name: "sbom-sentry:msi-product-code", Value: node.Metadata.ProductCode},
			cyclonedx.Property{Name: "sbom-sentry:msi-upgrade-code", Value: node.Metadata.UpgradeCode},
			cyclonedx.Property{Name: "sbom-sentry:msi-language", Value: node.Metadata.Language},
		)
	}

	return comp
}

func cpeFromMSIMetadata(md *extract.ContainerMetadata) string {
	if md == nil || md.Manufacturer == "" || md.ProductName == "" || md.ProductVersion == "" {
		return ""
	}
	vendor := cpeToken(md.Manufacturer)
	product := cpeToken(md.ProductName)
	version := cpeToken(md.ProductVersion)
	if vendor == "" || product == "" || version == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

func cpeToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, " ", "_")
	b := strings.Builder{}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ensureDeliveryPathProperty(c *cyclonedx.Component, deliveryPath string) {
	if c.Properties == nil {
		props := []cyclonedx.Property{{Name: "sbom-sentry:delivery-path", Value: deliveryPath}}
		c.Properties = &props
		return
	}
	for _, p := range *c.Properties {
		if p.Name == "sbom-sentry:delivery-path" {
			return
		}
	}
	*c.Properties = append(*c.Properties, cyclonedx.Property{Name: "sbom-sentry:delivery-path", Value: deliveryPath})
}

func addDep(deps map[string]map[string]struct{}, from string, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	if _, ok := deps[from]; !ok {
		deps[from] = map[string]struct{}{}
	}
	deps[from][to] = struct{}{}
}

func flattenDeps(depMap map[string]map[string]struct{}) []cyclonedx.Dependency {
	out := make([]cyclonedx.Dependency, 0, len(depMap))
	for ref, children := range depMap {
		list := make([]string, 0, len(children))
		for d := range children {
			list = append(list, d)
		}
		sort.Strings(list)
		out = append(out, cyclonedx.Dependency{Ref: ref, Dependencies: &list})
	}
	return out
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New() //nolint:gosec // SHA-256 is required SBOM hash algorithm.
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sanitizeBOMRef(v string) string {
	v = strings.ReplaceAll(v, "\\", "/")
	v = strings.ReplaceAll(v, " ", "_")
	return v
}
