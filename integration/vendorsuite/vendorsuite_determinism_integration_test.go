package vendorsuite_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

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
		bom, _, err := assembly.Assemble(tree, scans, cfg)
		if err != nil {
			t.Fatalf("assembly failed: %v", err)
		}
		out := filepath.Join(cfg.OutputDir, "test.cdx.json")
		if writeErr := assembly.WriteSBOM(bom, out, "cyclonedx-json"); writeErr != nil {
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
