package markdown

import (
	"fmt"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestCollectProcessingEntriesFromTree(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.cab", Status: extract.StatusFailed, StatusDetail: "7zz exit 2"},
			{Path: "b.msi", Status: extract.StatusToolMissing},
			{Path: "c.zip", Status: extract.StatusSecurityBlocked, StatusDetail: "zip bomb"},
		},
	}
	data.ProcessingIssues = []ProcessingIssue{{Stage: "assembly", Message: "merge error"}}
	data.Scans = []scan.ScanResult{{NodePath: "root.zip", Error: fmt.Errorf("syft failed")}}

	entries := reportjson.CollectMarkdownProcessingEntries(data)
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5", len(entries))
	}

	sources := make(map[string]int)
	for _, e := range entries {
		sources[e.Source]++
	}
	if sources["pipeline"] != 1 {
		t.Errorf("pipeline entries = %d, want 1", sources["pipeline"])
	}
	if sources["extraction"] != 3 {
		t.Errorf("extraction entries = %d, want 3", sources["extraction"])
	}
	if sources["scan"] != 1 {
		t.Errorf("scan entries = %d, want 1", sources["scan"])
	}
}

func TestCollectProcessingEntriesToolMissingFallbackDetail(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:     "root.zip",
		Status:   extract.StatusExtracted,
		Children: []*extract.ExtractionNode{{Path: "a.msi", Status: extract.StatusToolMissing}},
	}

	entries := reportjson.CollectMarkdownProcessingEntries(data)
	found := false
	for _, e := range entries {
		if e.Location == "a.msi" {
			found = true
			if e.Status != "tool-missing" {
				t.Fatalf("expected status tool-missing, got %q", e.Status)
			}
			if e.Classification != "tool-missing" {
				t.Fatalf("expected classification tool-missing, got %q", e.Classification)
			}
		}
	}
	if !found {
		t.Fatal("tool-missing entry not found")
	}
}

func TestCollectProcessingEntriesIncludesArchiveMetadataContext(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{{
			Path:         "a.zip",
			Status:       extract.StatusFailed,
			StatusDetail: "7zz failed",
			Tool:         "7zz",
			Format:       identify.FormatInfo{Format: identify.ZIP},
			ArchiveMeta: &extract.ArchiveMetadata{
				Type:             "zip",
				Methods:          []string{"Deflate"},
				HasEncryptedItem: true,
			},
		}},
	}

	entries := reportjson.CollectMarkdownProcessingEntries(data)
	if len(entries) == 0 {
		t.Fatal("expected extraction entry")
	}

	got := entries[0]
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if got.DetectedFormat != "ZIP" {
		t.Fatalf("detected = %q, want ZIP", got.DetectedFormat)
	}
	if got.Tool != "7zz" {
		t.Fatalf("tool = %q, want 7zz", got.Tool)
	}
	if got.ArchiveType != "zip" {
		t.Fatalf("archive type = %q, want zip", got.ArchiveType)
	}
	if got.ArchiveMethod != "Deflate" {
		t.Fatalf("archive method = %q, want Deflate", got.ArchiveMethod)
	}
	if got.Encrypted != "yes" {
		t.Fatalf("encrypted = %q, want yes", got.Encrypted)
	}
}
