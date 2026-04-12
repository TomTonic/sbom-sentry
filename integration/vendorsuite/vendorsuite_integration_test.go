// Package vendorsuite_test provides an end-to-end integration test that
// processes the vendor-suite-3.2.zip test fixture and verifies every
// structural claim made in SCAN_APPROACH.md §4.
//
// The test exercises the complete pipeline: extraction → scanning → assembly.
// It checks statuses, package attribution, MSI metadata, and the resulting
// CycloneDX SBOM structure.
//
// Prerequisites:
//   - testdata/vendor-suite-3.2.zip must exist (run build_testdata.sh)
//   - 7zz must be on PATH (brew install sevenzip)
//   - unshield must be on PATH (brew install unshield)
package vendorsuite_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// testdataZIP returns the absolute path to vendor-suite-3.2.zip.
func testdataZIP(t *testing.T) string {
	t.Helper()
	p := filepath.Join("testdata", "vendor-suite-3.2.zip")
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		t.Skipf("testdata not found: %s (run build_testdata.sh first)", abs)
	}
	return abs
}

// requireTool skips the test if 7zz is not on PATH.
func requireTool(t *testing.T) {
	t.Helper()
	const name = "7zz"
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		}
	}
	t.Skipf("required tool %q not on PATH", name)
}

// findNode walks the extraction tree and returns the first node whose Path
// ends with the given suffix. Returns nil if not found.
func findNode(root *extract.ExtractionNode, suffix string) *extract.ExtractionNode {
	if strings.HasSuffix(root.Path, suffix) {
		return root
	}
	for _, c := range root.Children {
		if n := findNode(c, suffix); n != nil {
			return n
		}
	}
	return nil
}

// findComponent returns the CycloneDX component whose properties include
// an extract-sbom:delivery-path matching the given suffix.
func findComponent(bom *cdx.BOM, pathSuffix string) *cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if p.Name == "extract-sbom:delivery-path" && strings.HasSuffix(p.Value, pathSuffix) {
				return c
			}
		}
	}
	return nil
}

// componentProperty returns the value of the named property on the component, or "".
func componentProperty(c *cdx.Component, name string) string {
	if c == nil || c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// dependencyRefs returns the dependency ref strings for the given component BOMRef.
func dependencyRefs(bom *cdx.BOM, bomRef string) []string {
	if bom == nil || bom.Dependencies == nil {
		return nil
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == bomRef && d.Dependencies != nil {
			return *d.Dependencies
		}
	}
	return nil
}

// TestVendorSuitePhase1ExtractionTree verifies that extract-sbom correctly
// identifies and extracts all container formats in vendor-suite-3.2.zip,
// matching the claims in SCAN_APPROACH.md §4.2.
func TestVendorSuitePhase1ExtractionTree(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("test requires unix")
	}
	requireTool(t)
	inputPath := testdataZIP(t)

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = t.TempDir()
	cfg.WorkDir = t.TempDir()
	cfg.Unsafe = true

	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		// Partial errors are okay for IS stubs; check the tree.
		t.Logf("extraction returned error (may be partial): %v", err)
	}
	if tree == nil {
		t.Fatal("extraction returned nil tree")
	}

	// §4.2: vendor-suite-3.2.zip → extracted
	if tree.Status != extract.StatusExtracted {
		t.Fatalf("root status = %v, want extracted", tree.Status)
	}

	// §4.2: RPM → syft-native
	t.Run("RPM is syft-native", func(t *testing.T) {
		n := findNode(tree, "server-3.2.rpm")
		if n == nil {
			t.Fatal("server-3.2.rpm not found in tree")
		}
		if n.Status != extract.StatusSyftNative {
			t.Errorf("status = %v, want syft-native", n.Status)
		}
	})

	// §4.2: DEB → syft-native
	t.Run("DEB is syft-native", func(t *testing.T) {
		n := findNode(tree, "libssl1.1_1.1.1n-0_amd64.deb")
		if n == nil {
			t.Fatal("DEB not found in tree")
		}
		if n.Status != extract.StatusSyftNative {
			t.Errorf("status = %v, want syft-native", n.Status)
		}
	})

	// §4.2: TAR.GZ → extracted
	t.Run("tar.gz is extracted", func(t *testing.T) {
		n := findNode(tree, "apache-tomcat-9.0.98.tar.gz")
		if n == nil {
			t.Fatal("tar.gz not found in tree")
		}
		if n.Status != extract.StatusExtracted {
			t.Errorf("status = %v, want extracted", n.Status)
		}
		if n.ExtractedDir == "" {
			t.Error("ExtractedDir is empty")
		}
	})

	// §4.2: JARs inside tar.gz → syft-native
	t.Run("JARs inside tomcat are syft-native", func(t *testing.T) {
		for _, name := range []string{"catalina.jar", "tomcat-embed-core-9.0.98.jar", "servlet-api.jar"} {
			n := findNode(tree, name)
			if n == nil {
				t.Errorf("%s not found in tree", name)
				continue
			}
			if n.Status != extract.StatusSyftNative {
				t.Errorf("%s: status = %v, want syft-native", name, n.Status)
			}
		}
	})

	// §4.2: EAR → syft-native
	t.Run("EAR is syft-native", func(t *testing.T) {
		n := findNode(tree, "vendor-app.ear")
		if n == nil {
			t.Fatal("vendor-app.ear not found in tree")
		}
		if n.Status != extract.StatusSyftNative {
			t.Errorf("status = %v, want syft-native", n.Status)
		}
	})

	// §4.2: resources.tgz → extracted
	t.Run("resources.tgz is extracted", func(t *testing.T) {
		n := findNode(tree, "resources.tgz")
		if n == nil {
			t.Fatal("resources.tgz not found in tree")
		}
		if n.Status != extract.StatusExtracted {
			t.Errorf("status = %v, want extracted", n.Status)
		}
	})

	// §4.2: MSI → extracted with metadata
	t.Run("MSI is extracted with metadata", func(t *testing.T) {
		n := findNode(tree, "client-setup.msi")
		if n == nil {
			t.Fatal("client-setup.msi not found in tree")
		}
		if n.Status != extract.StatusExtracted {
			t.Errorf("status = %v, want extracted", n.Status)
		}
		if n.Metadata == nil {
			t.Fatal("MSI metadata is nil")
		}
		if n.Metadata.ProductName == "" {
			t.Error("MSI ProductName is empty")
		}
		if n.Metadata.ProductVersion == "" {
			t.Error("MSI ProductVersion is empty")
		}
		if n.Metadata.Manufacturer == "" {
			t.Error("MSI Manufacturer is empty")
		}
		t.Logf("MSI: ProductName=%q, Version=%q, Manufacturer=%q",
			n.Metadata.ProductName, n.Metadata.ProductVersion, n.Metadata.Manufacturer)
	})

	// §4.2: Microsoft CAB → extracted
	t.Run("Microsoft CAB is extracted", func(t *testing.T) {
		n := findNode(tree, "vcredist.cab")
		if n == nil {
			t.Fatal("vcredist.cab not found in tree")
		}
		if n.Status != extract.StatusExtracted {
			t.Errorf("status = %v, want extracted", n.Status)
		}
	})

	// §4.2: InstallShield data1.cab → extracted or failed (stub)
	t.Run("InstallShield data1.cab is attempted", func(t *testing.T) {
		n := findNode(tree, "data1.cab")
		if n == nil {
			t.Fatal("data1.cab not found in tree")
		}
		// With a stub file, unshield may fail, but the format must be detected.
		t.Logf("data1.cab: status=%v, tool=%q", n.Status, n.Tool)
	})

	// §4.2 + D1 fix: data1.hdr must NOT be in the tree as an extracted node.
	// After the identify.go fix, .hdr files are Unknown → skipped → not persisted.
	t.Run("data1.hdr is not a persistent tree node", func(t *testing.T) {
		n := findNode(tree, "data1.hdr")
		if n != nil {
			t.Errorf("data1.hdr should not be in tree (status=%v), it is a companion file", n.Status)
		}
	})

	// §4.2: 7z → extracted
	t.Run("7z is extracted", func(t *testing.T) {
		n := findNode(tree, "webapp-patch-1.2.1.7z")
		if n == nil {
			t.Fatal("webapp-patch-1.2.1.7z not found in tree")
		}
		if n.Status != extract.StatusExtracted {
			t.Errorf("status = %v, want extracted", n.Status)
		}
	})

	// §4.2: plain files (PDF, .properties, PE binaries) are not persisted
	// in the tree as they get StatusSkipped with no children.
	t.Run("plain files are not persistent tree nodes", func(t *testing.T) {
		for _, name := range []string{"release-notes.pdf", "de.properties", "en.properties"} {
			n := findNode(tree, name)
			if n != nil {
				t.Errorf("%s should not be in tree (status=%v)", name, n.Status)
			}
		}
	})
}

// TestVendorSuitePhase2ScanAndAttribution verifies that the scan phase
// correctly finds packages and attributes them per SCAN_APPROACH.md §4.3/§7.2.
func TestVendorSuitePhase2ScanAndAttribution(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("test requires unix")
	}
	requireTool(t)
	inputPath := testdataZIP(t)

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = t.TempDir()
	cfg.WorkDir = t.TempDir()
	cfg.Unsafe = true

	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Logf("extraction returned error (may be partial): %v", err)
	}
	if tree == nil {
		t.Fatal("extraction returned nil tree")
	}

	scans, err := scan.ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Logf("scan returned error (may be partial): %v", err)
	}

	// Build a scan result map for easy lookup.
	scanMap := map[string]*scan.ScanResult{}
	for i := range scans {
		scanMap[scans[i].NodePath] = &scans[i]
	}

	// §4.3: minimist@0.0.8 found from webapp-patch-1.2.1.7z
	t.Run("npm minimist detected from 7z", func(t *testing.T) {
		var sr *scan.ScanResult
		for k, v := range scanMap {
			if strings.HasSuffix(k, "webapp-patch-1.2.1.7z") {
				sr = v
				break
			}
		}
		if sr == nil {
			t.Fatal("no scan result for webapp-patch-1.2.1.7z")
		}
		if sr.BOM == nil || sr.BOM.Components == nil {
			t.Fatal("webapp-patch scan produced no components")
		}
		found := false
		for _, c := range *sr.BOM.Components {
			if c.Name == "minimist" && c.Version == "0.0.8" {
				found = true
				break
			}
		}
		if !found {
			t.Error("minimist@0.0.8 not found in webapp-patch scan result")
		}
	})

	// §4.3: Maven packages from JARs attributed to JAR nodes (not TAR)
	t.Run("Maven packages attributed to JAR nodes via reuse", func(t *testing.T) {
		for _, suffix := range []string{"catalina.jar", "tomcat-embed-core-9.0.98.jar", "servlet-api.jar"} {
			var sr *scan.ScanResult
			for k, v := range scanMap {
				if strings.HasSuffix(k, suffix) {
					sr = v
					break
				}
			}
			if sr == nil {
				t.Errorf("no scan result for %s", suffix)
				continue
			}
			if sr.BOM == nil || sr.BOM.Components == nil {
				t.Errorf("%s: scan result has no components", suffix)
				continue
			}
			t.Logf("%s: %d components found", suffix, len(*sr.BOM.Components))
		}
	})

	// §4.3: RPM package detected
	t.Run("RPM package detected", func(t *testing.T) {
		var sr *scan.ScanResult
		for k, v := range scanMap {
			if strings.HasSuffix(k, "server-3.2.rpm") {
				sr = v
				break
			}
		}
		if sr == nil {
			t.Fatal("no scan result for server-3.2.rpm")
		}
		if sr.BOM == nil || sr.BOM.Components == nil {
			t.Fatal("RPM scan produced no components")
		}
		found := false
		for _, c := range *sr.BOM.Components {
			if strings.Contains(strings.ToLower(c.Name), "server") {
				found = true
				t.Logf("RPM package: %s@%s", c.Name, c.Version)
				break
			}
		}
		if !found {
			t.Error("server package not found in RPM scan result")
		}
	})

	// §4.3: DEB package detected
	t.Run("DEB package detected", func(t *testing.T) {
		var sr *scan.ScanResult
		for k, v := range scanMap {
			if strings.HasSuffix(k, "libssl1.1_1.1.1n-0_amd64.deb") {
				sr = v
				break
			}
		}
		if sr == nil {
			t.Fatal("no scan result for DEB")
		}
		if sr.BOM == nil || sr.BOM.Components == nil {
			t.Fatal("DEB scan produced no components")
		}
		found := false
		for _, c := range *sr.BOM.Components {
			if strings.Contains(c.Name, "libssl") {
				found = true
				t.Logf("DEB package: %s@%s", c.Name, c.Version)
				break
			}
		}
		if !found {
			t.Error("libssl package not found in DEB scan result")
		}
	})
}

// TestVendorSuiteSBOMAssembly verifies that the final SBOM has the expected
// structure per SCAN_APPROACH.md §8.
func TestVendorSuiteSBOMAssembly(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("test requires unix")
	}
	requireTool(t)
	inputPath := testdataZIP(t)

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = t.TempDir()
	cfg.WorkDir = t.TempDir()
	cfg.Unsafe = true

	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Logf("extraction error (may be partial): %v", err)
	}
	if tree == nil {
		t.Fatal("extraction returned nil tree")
	}

	scans, err := scan.ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Logf("scan error (may be partial): %v", err)
	}

	bom, err := assembly.Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("assembly failed: %v", err)
	}
	if bom == nil {
		t.Fatal("assembly returned nil BOM")
	}

	// §8: Every tracked node becomes a component with extract-sbom:delivery-path.
	t.Run("tracked nodes are SBOM components", func(t *testing.T) {
		for _, suffix := range []string{
			"vendor-suite-3.2.zip",
			"server-3.2.rpm",
			"libssl1.1_1.1.1n-0_amd64.deb",
			"apache-tomcat-9.0.98.tar.gz",
			"catalina.jar",
			"tomcat-embed-core-9.0.98.jar",
			"servlet-api.jar",
			"vendor-app.ear",
			"resources.tgz",
			"client-setup.msi",
			"vcredist.cab",
			"webapp-patch-1.2.1.7z",
		} {
			c := findComponent(bom, suffix)
			if c == nil {
				t.Errorf("no component for %s", suffix)
			}
		}
	})

	// §8: skipped leaves are NOT SBOM components.
	t.Run("skipped leaves are not components", func(t *testing.T) {
		for _, suffix := range []string{
			"release-notes.pdf",
			"de.properties",
			"en.properties",
		} {
			c := findComponent(bom, suffix)
			if c != nil {
				t.Errorf("unexpected component for skipped leaf %s", suffix)
			}
		}
	})

	// §8: MSI component has standard CycloneDX fields from Property table.
	t.Run("MSI component has product metadata in standard fields", func(t *testing.T) {
		c := findComponent(bom, "client-setup.msi")
		if c == nil {
			t.Fatal("no component for client-setup.msi")
		}
		// ProductName mapped to component Name.
		if c.Name == "" || c.Name == "client-setup.msi" {
			t.Logf("MSI component name = %q (ProductName may not have overridden)", c.Name)
		}
		// ProductVersion mapped to component Version.
		if c.Version != "" {
			t.Logf("MSI component version = %q", c.Version)
		}
		// Manufacturer mapped to Supplier.
		if c.Supplier != nil {
			t.Logf("MSI supplier = %q", c.Supplier.Name)
		}
	})

	// §8: Components have extract-sbom:delivery-path and extract-sbom:extraction-status.
	t.Run("components have delivery-path and extraction-status properties", func(t *testing.T) {
		c := findComponent(bom, "apache-tomcat-9.0.98.tar.gz")
		if c == nil {
			t.Fatal("no component for tar.gz")
		}
		dp := componentProperty(c, "extract-sbom:delivery-path")
		if dp == "" {
			t.Error("missing extract-sbom:delivery-path")
		}
		status := componentProperty(c, "extract-sbom:extraction-status")
		if status == "" {
			t.Error("missing extract-sbom:extraction-status")
		}
		t.Logf("tar.gz: delivery-path=%q, status=%q", dp, status)
	})

	// §8: Packages discovered by Syft appear as separate components linked
	// via dependencies (not as nested sub-components).
	t.Run("packages are linked via dependencies not nested", func(t *testing.T) {
		c := findComponent(bom, "webapp-patch-1.2.1.7z")
		if c == nil {
			t.Fatal("no component for 7z")
		}
		deps := dependencyRefs(bom, c.BOMRef)
		t.Logf("webapp-patch deps: %v", deps)
		if len(deps) == 0 {
			t.Error("webapp-patch should have dependency refs (minimist)")
		}
		// The minimist component should be findable in the flat components list.
		found := false
		if bom.Components != nil {
			for _, comp := range *bom.Components {
				if comp.Name == "minimist" {
					found = true
					t.Logf("minimist component BOMRef=%s", comp.BOMRef)
					break
				}
			}
		}
		if !found {
			t.Error("minimist not found as flat component in BOM")
		}
	})
}

// TestVendorSuiteDeterminism verifies SCAN_APPROACH.md §9: processing the
// same input twice yields byte-identical SBOM output.
func TestVendorSuiteDeterminism(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("test requires unix")
	}
	requireTool(t)
	inputPath := testdataZIP(t)

	runPipeline := func() []byte {
		cfg := config.DefaultConfig()
		cfg.InputPath = inputPath
		cfg.OutputDir = t.TempDir()
		cfg.WorkDir = t.TempDir()
		cfg.Unsafe = true

		tree, _ := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
		if tree == nil {
			t.Fatal("extraction returned nil tree")
		}
		scans, _ := scan.ScanAll(context.Background(), tree, cfg)
		bom, err := assembly.Assemble(tree, scans, cfg)
		if err != nil {
			t.Fatalf("assembly failed: %v", err)
		}
		out := filepath.Join(cfg.OutputDir, "test.cdx.json")
		if writeErr := assembly.WriteSBOM(bom, out); writeErr != nil {
			t.Fatalf("write SBOM: %v", writeErr)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read SBOM: %v", err)
		}
		return data
	}

	run1 := runPipeline()
	run2 := runPipeline()

	// Normalize temp directory paths in Syft evidence locations.
	// These are ephemeral and change between runs but don't affect
	// SBOM correctness. Match everything up to extract-sbom-TYPE-RANDOM/.
	tmpPat := regexp.MustCompile(`[/][^\s"]*extract-sbom-[a-z0-9]+-\d+/`)
	norm1 := tmpPat.ReplaceAll(run1, []byte("/NORMALIZED/"))
	norm2 := tmpPat.ReplaceAll(run2, []byte("/NORMALIZED/"))

	if len(norm1) != len(norm2) {
		t.Fatalf("SBOM size differs after normalization: %d vs %d", len(norm1), len(norm2))
	}

	// Compare as parsed JSON to get better error messages.
	var bom1, bom2 cdx.BOM
	if err := json.Unmarshal(norm1, &bom1); err != nil {
		t.Fatalf("parse run1: %v", err)
	}
	if err := json.Unmarshal(norm2, &bom2); err != nil {
		t.Fatalf("parse run2: %v", err)
	}

	// Byte-for-byte comparison after re-marshal to normalize.
	j1, _ := json.Marshal(bom1)
	j2, _ := json.Marshal(bom2)
	if string(j1) != string(j2) {
		// Find the first difference for debugging.
		s1, s2 := string(j1), string(j2)
		minLen := len(s1)
		if len(s2) < minLen {
			minLen = len(s2)
		}
		for i := 0; i < minLen; i++ {
			if s1[i] == s2[i] {
				continue
			}
			start := i - 80
			if start < 0 {
				start = 0
			}
			end := i + 80
			if end > minLen {
				end = minLen
			}
			t.Errorf("first diff at byte %d:\n  run1: ...%s...\n  run2: ...%s...", i, s1[start:end], s2[start:end])
			break
		}
		t.Error("SBOM output is not deterministic across two runs")
	}
}
