package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	syftfile "github.com/anchore/syft/syft/file"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
)

func TestReuseSyftNativeResultsFromExtractedScansMovesPackagesToNativeNode(t *testing.T) {
	t.Parallel()

	extractedDir := t.TempDir()
	jarDir := filepath.Join(extractedDir, "lib")
	if err := os.MkdirAll(jarDir, 0o750); err != nil {
		t.Fatal(err)
	}
	jarPath := filepath.Join(jarDir, "app.jar")
	if err := os.WriteFile(jarPath, []byte("not-a-real-jar"), 0o600); err != nil {
		t.Fatal(err)
	}

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: "/input/delivery.zip",
		ExtractedDir: extractedDir,
		Status:       extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{
				Path:         "delivery.zip/lib/app.jar",
				OriginalPath: jarPath,
				Status:       extract.StatusSyftNative,
				Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
			},
		},
	}

	results := []ScanResult{
		{
			NodePath: "delivery.zip",
			syftPackages: []syftpkg.Package{
				newTestPackage("root-pkg", filepath.Join(extractedDir, "package.json")),
				newTestPackage("jar-pkg", jarPath),
			},
		},
		{
			NodePath: "delivery.zip/lib/app.jar",
		},
	}

	reusedCount, unresolved, err := reuseSyftNativeResultsFromExtractedScans(tree, results, []int{0}, []int{1})
	if err != nil {
		t.Fatalf("reuseSyftNativeResultsFromExtractedScans() error = %v", err)
	}
	if reusedCount != 1 {
		t.Fatalf("reusedCount = %d, want 1", reusedCount)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved = %v, want none", unresolved)
	}

	if got := componentNames(results[0].BOM); !reflect.DeepEqual(got, []string{"root-pkg"}) {
		t.Fatalf("root component names = %v, want [root-pkg]", got)
	}
	if got := componentNames(results[1].BOM); !reflect.DeepEqual(got, []string{"jar-pkg"}) {
		t.Fatalf("native component names = %v, want [jar-pkg]", got)
	}
}

func TestPathMatchesScanTargetMatchesNestedAccessPath(t *testing.T) {
	t.Parallel()

	target := "/tmp/example/app.jar"
	if !pathMatchesScanTarget(target+":META-INF/maven/pom.properties", target) {
		t.Fatal("expected access path with colon to match target")
	}
	if !pathMatchesScanTarget(target+"!/META-INF/MANIFEST.MF", target) {
		t.Fatal("expected access path with bang to match target")
	}
	if pathMatchesScanTarget("/tmp/example/app.jarx", target) {
		t.Fatal("unexpected fuzzy match for non-target path")
	}
}

func TestNativeScanLoggingKeepsOnlySlowVerboseDetails(t *testing.T) {
	t.Parallel()

	if shouldLogScanCompletion("scan-native", 1500*time.Millisecond) {
		t.Fatal("fast scan-native completion logs should be suppressed")
	}
	if !shouldLogScanCompletion("scan-native", 2*time.Second) {
		t.Fatal("slow scan-native completion logs should be kept")
	}
	if !shouldLogScanCompletion("scan-extracted", 500*time.Millisecond) {
		t.Fatal("scan-extracted completion logs should remain enabled")
	}
}

func newTestPackage(name string, locationPath string) syftpkg.Package {
	pkg := syftpkg.Package{
		Name:      name,
		Version:   "1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation(locationPath)),
	}
	pkg.SetID()
	return pkg
}

func componentNames(bom *cdx.BOM) []string {
	if bom == nil || bom.Components == nil {
		return nil
	}

	names := make([]string, 0, len(*bom.Components))
	for i := range *bom.Components {
		component := (*bom.Components)[i]
		names = append(names, component.Name)
	}
	sort.Strings(names)
	return names
}
