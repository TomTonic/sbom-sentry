// Package vendorsuite_test — integration tests for cross-node deduplication
// and evidence-path correctness. These tests exercise the full pipeline
// (extraction → scanning → assembly) on synthetic test fixtures and verify
// that the final SBOM contains no duplicates.
package vendorsuite_test

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// makeTestJAR creates a minimal JAR file with META-INF/MANIFEST.MF and
// pom.properties so that Syft's java-archive-cataloger can identify it.
func makeTestJAR(t *testing.T, path, groupID, artifactID, version string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	manifest, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = manifest.Write([]byte(
		"Manifest-Version: 1.0\r\n" +
			"Implementation-Title: " + artifactID + "\r\n" +
			"Implementation-Version: " + version + "\r\n\r\n"))

	pomPropsPath := "META-INF/maven/" + groupID + "/" + artifactID + "/pom.properties"
	pom, err := w.Create(pomPropsPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pom.Write([]byte(
		"groupId=" + groupID + "\n" +
			"artifactId=" + artifactID + "\n" +
			"version=" + version + "\n"))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// makeTestZIPContainingJAR creates a ZIP file that contains a single JAR
// at the given inner path. This simulates a delivery ZIP containing a JAR.
func makeTestZIPContainingJAR(t *testing.T, zipPath, innerJARName, groupID, artifactID, version string) {
	t.Helper()

	// First create the JAR in a temp location.
	jarPath := filepath.Join(t.TempDir(), innerJARName)
	makeTestJAR(t, jarPath, groupID, artifactID, version)

	jarData, err := os.ReadFile(jarPath)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, err := w.Create(innerJARName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(jarData); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDedupJARInsideZIP_NoDuplicatesInSBOM creates a ZIP containing a JAR,
// runs the full pipeline, and verifies that the resulting SBOM contains exactly
// one component for that JAR — not two (one from the extracted directory scan
// and one from the SyftNative scan).
func TestDedupJARInsideZIP_NoDuplicatesInSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	t.Parallel()

	const (
		groupID    = "org.example.dedup"
		artifactID = "dedup-lib"
		version    = "7.42.1"
		jarName    = "dedup-lib-7.42.1.jar"
		purl       = "pkg:maven/org.example.dedup/dedup-lib@7.42.1"
	)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	makeTestZIPContainingJAR(t, inputPath, jarName, groupID, artifactID, version)

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.WorkDir = filepath.Join(dir, "work")
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Unsafe = true // no sandbox needed for this test

	// Phase 1: Extract
	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Logf("extraction returned error (may be partial): %v", err)
	}
	if tree == nil {
		t.Fatal("extraction returned nil tree")
	}

	// Debug: print the tree structure.
	var printTree func(node *extract.ExtractionNode, depth int)
	printTree = func(node *extract.ExtractionNode, depth int) {
		t.Logf("%s%s (status=%v, format=%v)", strings.Repeat("  ", depth), node.Path, node.Status, node.Format)
		for _, child := range node.Children {
			printTree(child, depth+1)
		}
	}
	printTree(tree, 0)

	// Verify the JAR is a SyftNative child of the extracted ZIP.
	jarNode := findNode(tree, "dedup-lib-7.42.1.jar")
	if jarNode == nil {
		t.Fatal("JAR node not found in extraction tree")
	}
	if jarNode.Status != extract.StatusSyftNative {
		t.Fatalf("JAR status = %v, want syft-native", jarNode.Status)
	}

	// Phase 2: Scan (Syft integration)
	scanResults, err := scan.ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll error: %v", err)
	}

	// Log scan results for debugging.
	for _, sr := range scanResults {
		if sr.Error != nil {
			t.Logf("scan %s: error=%v", sr.NodePath, sr.Error)
			continue
		}
		if sr.BOM != nil && sr.BOM.Components != nil {
			for _, c := range *sr.BOM.Components {
				t.Logf("scan %s: component name=%q version=%q purl=%q", sr.NodePath, c.Name, c.Version, c.PackageURL)
			}
		}
	}

	// Phase 3: Assemble
	bom, suppressions, err := assembly.Assemble(tree, scanResults, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("BOM has no components")
	}

	// Count components matching the expected PURL.
	var matches []cdx.Component
	for _, comp := range *bom.Components {
		if comp.PackageURL == purl {
			matches = append(matches, comp)
		}
	}

	if len(matches) == 0 {
		// Syft might identify it with a slightly different PURL; search by name.
		for _, comp := range *bom.Components {
			if comp.Name == artifactID && comp.Version == version {
				matches = append(matches, comp)
			}
		}
	}

	if len(matches) == 0 {
		t.Fatal("no matching component found in SBOM — Syft did not identify the JAR")
	}

	if len(matches) > 1 {
		t.Errorf("expected exactly 1 component for %s, got %d:", purl, len(matches))
		for i, m := range matches {
			dp := ""
			ep := ""
			if m.Properties != nil {
				for _, p := range *m.Properties {
					if p.Name == "extract-sbom:delivery-path" {
						dp = p.Value
					}
					if p.Name == "extract-sbom:evidence-path" {
						ep = p.Value
					}
				}
			}
			t.Errorf("  [%d] BOMRef=%s deliveryPath=%s evidencePath=%s", i, m.BOMRef, dp, ep)
		}
	}

	// The surviving component must have an evidence path.
	if len(matches) >= 1 {
		comp := matches[0]
		var evidencePaths []string
		if comp.Properties != nil {
			for _, p := range *comp.Properties {
				if p.Name == "extract-sbom:evidence-path" && p.Value != "" {
					evidencePaths = append(evidencePaths, p.Value)
				}
			}
		}
		if len(evidencePaths) == 0 {
			t.Errorf("surviving component has no evidence-path")
		}
		// Evidence must NOT be self-referencing (equal to delivery path).
		for _, ep := range evidencePaths {
			dp := componentProperty(&comp, "extract-sbom:delivery-path")
			if ep == dp {
				t.Errorf("evidence-path %q is self-referencing (equals delivery-path)", ep)
			}
		}
	}

	// Log suppressions for visibility.
	for _, s := range suppressions {
		if s.Component.PackageURL == purl || s.Component.Name == artifactID {
			t.Logf("suppression: reason=%s name=%q purl=%q deliveryPath=%s keptName=%q",
				s.Reason, s.Component.Name, s.Component.PackageURL, s.DeliveryPath, s.KeptName)
		}
	}

	// Verify no dangling BOMRefs in the dependency graph.
	if bom.Dependencies != nil {
		allRefs := make(map[string]bool)
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			allRefs[bom.Metadata.Component.BOMRef] = true
		}
		for _, c := range *bom.Components {
			allRefs[c.BOMRef] = true
		}
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil {
				continue
			}
			for _, ref := range *dep.Dependencies {
				if !allRefs[ref] {
					t.Errorf("dangling dependency ref %q in dep entry for %q", ref, dep.Ref)
				}
			}
		}
	}
}

// TestDedupMultipleJARsInsideZIP tests that multiple JARs inside a ZIP each
// appear exactly once in the final SBOM.
func TestDedupMultipleJARsInsideZIP(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	t.Parallel()

	type jarSpec struct {
		name       string
		groupID    string
		artifactID string
		version    string
	}
	jars := []jarSpec{
		{"alpha-1.0.0.jar", "org.example", "alpha", "1.0.0"},
		{"beta-2.3.1.jar", "org.example", "beta", "2.3.1"},
	}

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "multi.zip")

	// Build a ZIP containing multiple JARs.
	f, err := os.Create(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, j := range jars {
		jarPath := filepath.Join(t.TempDir(), filepath.Base(j.name))
		makeTestJAR(t, jarPath, j.groupID, j.artifactID, j.version)
		jarData, err := os.ReadFile(jarPath)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := zw.Create(j.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(jarData); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.WorkDir = filepath.Join(dir, "work")
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Unsafe = true

	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Logf("extraction error (may be partial): %v", err)
	}
	if tree == nil {
		t.Fatal("extraction returned nil tree")
	}

	scanResults, err := scan.ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll error: %v", err)
	}

	bom, _, err := assembly.Assemble(tree, scanResults, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("BOM has no components")
	}

	for _, j := range jars {
		purl := "pkg:maven/" + j.groupID + "/" + j.artifactID + "@" + j.version
		var count int
		for _, comp := range *bom.Components {
			if comp.PackageURL == purl {
				count++
			}
		}
		// Also check by name+version as fallback.
		if count == 0 {
			for _, comp := range *bom.Components {
				if comp.Name == j.artifactID && comp.Version == j.version {
					count++
				}
			}
		}

		if count == 0 {
			t.Errorf("%s not found in SBOM", purl)
		}
		if count > 1 {
			t.Errorf("%s appears %d times in SBOM, want 1", purl, count)
		}
	}
}

// TestEvidencePathNotSelfReferencing runs the full pipeline on a ZIP and
// verifies that no component has evidence-path equal to its delivery-path.
func TestEvidencePathNotSelfReferencing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "evidence-test.zip")
	makeTestZIPContainingJAR(t, inputPath, "app.jar",
		"org.example.evidence", "evidence-lib", "3.0.0")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.WorkDir = filepath.Join(dir, "work")
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Unsafe = true

	tree, err := extract.Extract(context.Background(), inputPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Logf("extraction error: %v", err)
	}
	if tree == nil {
		t.Fatal("nil tree")
	}

	scanResults, err := scan.ScanAll(context.Background(), tree, cfg)
	if err != nil {
		t.Fatalf("ScanAll error: %v", err)
	}

	bom, _, err := assembly.Assemble(tree, scanResults, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		return // nothing to check
	}

	for _, comp := range *bom.Components {
		if comp.Properties == nil {
			continue
		}
		var deliveryPath string
		var evidencePaths []string
		for _, p := range *comp.Properties {
			if p.Name == "extract-sbom:delivery-path" {
				deliveryPath = p.Value
			}
			if p.Name == "extract-sbom:evidence-path" {
				evidencePaths = append(evidencePaths, p.Value)
			}
		}
		for _, ep := range evidencePaths {
			if ep == deliveryPath {
				t.Errorf("component %q (PURL=%s): evidence-path %q is self-referencing",
					comp.Name, comp.PackageURL, ep)
			}
			// Evidence should be more specific than delivery path.
			if !strings.HasPrefix(ep, deliveryPath) && ep != "" {
				// Different path entirely — that's technically fine (e.g.
				// evidence from a different location). Just log it.
				t.Logf("component %q: evidence %q does not extend delivery %q", comp.Name, ep, deliveryPath)
			}
		}
	}
}
