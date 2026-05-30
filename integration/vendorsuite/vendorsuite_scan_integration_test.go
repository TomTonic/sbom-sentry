package vendorsuite_test

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

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
