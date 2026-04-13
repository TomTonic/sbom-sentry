package scan

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	syftpkg "github.com/anchore/syft/syft/pkg"
)

// ScanResult holds the CycloneDX BOM produced by scanning a single
// extraction node, along with metadata linking it back to the tree.
type ScanResult struct { //nolint:revive // stuttering is acceptable for clarity
	NodePath      string              // matches ExtractionNode.Path
	BOM           *cdx.BOM            // CycloneDX BOM for this subtree/file
	EvidencePaths map[string][]string // optional component BOMRef -> supporting internal paths
	Error         error               // non-nil if scanning failed
	syftPackages  []syftpkg.Package   // internal sorted package cache used for extracted/native reuse and BOM rebuilds
}
