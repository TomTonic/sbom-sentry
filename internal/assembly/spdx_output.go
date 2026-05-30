package assembly

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// spdxFallbackCreated is the SPDX CreationInfo.Created value used when the
// source BOM carries no metadata timestamp. A fixed epoch value is used in
// preference to the wall clock so that SPDX output stays reproducible even in
// the degraded case where the input file's modification time was unavailable.
const spdxFallbackCreated = "1970-01-01T00:00:00Z"

// nonAlphaNumHyphen matches characters that are not alphanumeric or hyphen.
var nonAlphaNumHyphen = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// sanitizeSPDXID converts a BOMRef string into a valid SPDX ElementID suffix
// (alphanumeric and hyphens only). Non-conforming characters are replaced with
// hyphens; consecutive hyphens are collapsed.
func sanitizeSPDXID(bomRef string) string {
	s := nonAlphaNumHyphen.ReplaceAllString(bomRef, "-")
	// Collapse consecutive hyphens.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		s = "component"
	}
	return s
}

// spdxLicense returns the first usable SPDX license expression from a
// CycloneDX component, or "NOASSERTION" if none is available.
func spdxLicense(c cdx.Component) string {
	if c.Licenses == nil {
		return "NOASSERTION"
	}
	for _, lic := range *c.Licenses {
		if lic.License != nil && lic.License.ID != "" {
			return lic.License.ID
		}
		if lic.Expression != "" {
			return lic.Expression
		}
	}
	return "NOASSERTION"
}

// downloadLocation returns a PURL or "NOASSERTION" for a CycloneDX component.
func downloadLocation(c cdx.Component) string {
	if c.PackageURL != "" {
		return c.PackageURL
	}
	return "NOASSERTION"
}

// spdxCreated returns the SPDX CreationInfo.Created timestamp for the document.
//
// SPDX requires a creation timestamp, but emitting the wall-clock time would
// make every run produce a different document for identical input. To keep the
// SPDX output reproducible — and consistent with the CycloneDX writer, which
// already derives its metadata timestamp from the input file's modification
// time — the timestamp is taken from the source BOM's metadata. When the BOM
// carries no timestamp the fixed sentinel spdxFallbackCreated is used instead.
func spdxCreated(bom *cdx.BOM) string {
	if bom != nil && bom.Metadata != nil && strings.TrimSpace(bom.Metadata.Timestamp) != "" {
		return bom.Metadata.Timestamp
	}
	return spdxFallbackCreated
}

// spdxDocumentNamespace builds the SPDX DocumentNamespace URI.
//
// The SPDX specification requires the namespace to uniquely identify the
// document. Generating a fresh random UUID per run would break reproducibility:
// otherwise-identical SBOMs would receive a different namespace on every
// invocation. Instead the UUID is derived deterministically (RFC 4122 v5) from
// the document name, creation timestamp, and the sorted component identity
// list, so identical inputs yield an identical namespace while distinct SBOMs
// still receive distinct namespaces.
func spdxDocumentNamespace(bom *cdx.BOM, docName, created string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, docName)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, created)
	if bom != nil && bom.Components != nil {
		idents := make([]string, 0, len(*bom.Components))
		for i := range *bom.Components {
			c := &(*bom.Components)[i]
			idents = append(idents, c.BOMRef+"\x00"+c.Name+"\x00"+c.Version)
		}
		sort.Strings(idents)
		for _, id := range idents {
			_, _ = io.WriteString(h, "\x00")
			_, _ = io.WriteString(h, id)
		}
	}
	return "https://extract-sbom/spdx/" + uuid.NewSHA1(uuid.NameSpaceURL, h.Sum(nil)).String()
}

// WriteSBOMSPDX converts the CycloneDX BOM to an SPDX 2.3 JSON document and
// writes it to path. If bom is nil or has no components, a minimal valid SPDX
// document is written.
//
// Parameters:
// - bom: CycloneDX BOM to convert (may be nil)
// - path: target file path to create or truncate
//
// Returns an error when file creation or encoding fails.
func WriteSBOMSPDX(bom *cdx.BOM, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("assembly: create SPDX file %s: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if err := writeSPDXTo(bom, f); err != nil {
		return fmt.Errorf("assembly: encode SPDX: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("assembly: close SPDX file %s: %w", path, err)
	}

	return nil
}

// writeSPDXTo is the testable core: converts a CycloneDX BOM to SPDX 2.3 JSON
// and writes to the given writer.
//
// The document namespace and creation timestamp are derived deterministically
// from the source BOM (see spdxDocumentNamespace and spdxCreated) so that two
// runs over the same input produce byte-for-byte identical SPDX output.
func writeSPDXTo(bom *cdx.BOM, w io.Writer) error {
	docName := "SBOM"
	if bom != nil && bom.Metadata != nil && bom.Metadata.Component != nil &&
		bom.Metadata.Component.Name != "" {
		docName = bom.Metadata.Component.Name
	}

	created := spdxCreated(bom)

	doc := &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    spdxcommon.ElementID("DOCUMENT"),
		DocumentName:      docName,
		DocumentNamespace: spdxDocumentNamespace(bom, docName, created),
		CreationInfo: &spdx.CreationInfo{
			Created: created,
			Creators: []spdxcommon.Creator{
				{CreatorType: "Tool", Creator: "extract-sbom"},
			},
		},
	}

	if bom == nil {
		return spdxjson.Write(doc, w, spdxjson.Indent("  "))
	}

	// Add root package from metadata component.
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		root := bom.Metadata.Component
		rootPkg := &spdx.Package{
			PackageName:             root.Name,
			PackageSPDXIdentifier:   spdxcommon.ElementID("DOCUMENT"),
			PackageVersion:          root.Version,
			PackageDownloadLocation: downloadLocation(*root),
			FilesAnalyzed:           false,
			PackageLicenseConcluded: spdxLicense(*root),
			PackageLicenseDeclared:  spdxLicense(*root),
		}
		doc.Packages = append(doc.Packages, rootPkg)
	}

	// Map BOMRef → SPDX ElementID for dependency relationship building.
	bomRefToElementID := make(map[string]spdxcommon.ElementID)

	if bom.Components != nil {
		for i := range *bom.Components {
			c := (*bom.Components)[i]
			eid := spdxcommon.ElementID("SPDXRef-" + sanitizeSPDXID(c.BOMRef))
			bomRefToElementID[c.BOMRef] = eid

			pkg := &spdx.Package{
				PackageName:             c.Name,
				PackageSPDXIdentifier:   eid,
				PackageVersion:          c.Version,
				PackageDownloadLocation: downloadLocation(c),
				FilesAnalyzed:           false,
				PackageLicenseConcluded: spdxLicense(c),
				PackageLicenseDeclared:  spdxLicense(c),
			}
			doc.Packages = append(doc.Packages, pkg)
		}
	}

	// DESCRIBES relationship from document to root package.
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{
			RefA:         spdxcommon.MakeDocElementID("", "DOCUMENT"),
			RefB:         spdxcommon.MakeDocElementID("", "DOCUMENT"),
			Relationship: "DESCRIBES",
		})
	}

	// DEPENDS_ON relationships from dependency graph.
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil || len(*dep.Dependencies) == 0 {
				continue
			}
			refAID, ok := bomRefToElementID[dep.Ref]
			if !ok {
				// Try document root.
				if bom.Metadata != nil && bom.Metadata.Component != nil &&
					dep.Ref == bom.Metadata.Component.BOMRef {
					refAID = spdxcommon.ElementID("DOCUMENT")
				} else {
					continue
				}
			}
			for _, depRef := range *dep.Dependencies {
				refBID, ok2 := bomRefToElementID[depRef]
				if !ok2 {
					continue
				}
				doc.Relationships = append(doc.Relationships, &spdx.Relationship{
					RefA:         spdxcommon.MakeDocElementID("", string(refAID)),
					RefB:         spdxcommon.MakeDocElementID("", string(refBID)),
					Relationship: "DEPENDS_ON",
				})
			}
		}
	}

	return spdxjson.Write(doc, w, spdxjson.Indent("  "))
}
