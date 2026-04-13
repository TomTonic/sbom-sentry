package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"

	// Register a pure-Go SQLite driver required by Syft's RPM catalogers.
	_ "github.com/glebarez/go-sqlite"

	"github.com/TomTonic/extract-sbom/internal/extract"
)

// scanNode performs the actual Syft scan for a single node.
func scanNode(ctx context.Context, result *ScanResult, root *extract.ExtractionNode) {
	node := findNode(root, result.NodePath)
	if node == nil {
		result.Error = fmt.Errorf("scan: node %s not found in tree", result.NodePath)
		return
	}

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

	if _, err := os.Stat(target); err != nil {
		result.Error = fmt.Errorf("scan: target %s does not exist: %w", target, err)
		return
	}

	result.BOM = nil
	result.EvidencePaths = nil
	result.Error = nil
	result.syftPackages = nil

	// NOTE: syft.GetSource() currently touches shared global state in an
	// upstream dependency, so concurrent calls can race under -race.
	syftGetSourceMu.Lock()
	src, err := syft.GetSource(ctx, target, nil)
	syftGetSourceMu.Unlock()
	if err != nil {
		result.Error = fmt.Errorf("scan: get source for %s: %w", target, err)
		return
	}
	defer src.Close()

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

// buildBOMFromPackages creates a minimal Syft SBOM from a package set and
// converts it to CycloneDX.
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

// convertSyftSBOMToCycloneDX serializes Syft's internal SBOM through Syft's
// own CycloneDX encoder and then decodes it with cyclonedx-go.
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
