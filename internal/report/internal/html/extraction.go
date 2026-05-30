package html

import "github.com/TomTonic/extract-sbom/internal/extract"

// flattenExtractionNodes recursively collects extraction nodes for display.
func flattenExtractionNodes(node *extract.ExtractionNode, depth int, out *[]htmlNode) {
	if node == nil {
		return
	}
	d := depth
	if d > 5 {
		d = 5
	}
	*out = append(*out, htmlNode{
		Depth:  d,
		Path:   node.Path,
		Status: node.Status.String(),
		Format: node.Format.Format.String(),
		Tool:   node.Tool,
		Detail: node.StatusDetail,
	})
	for _, child := range node.Children {
		flattenExtractionNodes(child, depth+1, out)
	}
}
