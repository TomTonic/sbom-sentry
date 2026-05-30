package domain

import (
	"testing"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func TestCollectVulnStats(t *testing.T) {
	t.Parallel()

	v := &vulnscan.Result{
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"a": {
				{VulnerabilityID: "CVE-1"},
				{VulnerabilityID: "CVE-2"},
			},
			"b": {
				{VulnerabilityID: "CVE-1"},
			},
		},
	}

	matches, unique, affected := CollectVulnStats(v)
	if matches != 3 || unique != 2 || affected != 2 {
		t.Fatalf("CollectVulnStats = (%d,%d,%d), want (3,2,2)", matches, unique, affected)
	}
}

func TestCollectSuppressionStats(t *testing.T) {
	t.Parallel()

	records := []assembly.SuppressionRecord{
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionLowValueFile},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionPURLDuplicate},
	}

	stats := CollectSuppressionStats(records)
	if stats.FSArtifacts != 2 || stats.LowValueFiles != 1 || stats.WeakDuplicate != 1 || stats.PURLDuplicate != 1 {
		t.Fatalf("unexpected suppression stats: %+v", stats)
	}
}

func TestCollectExtractionScanAndPolicyStats(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.jar", Status: extract.StatusFailed},
			{Path: "b.jar", Status: extract.StatusToolMissing},
			{Path: "c.jar", Status: extract.StatusSecurityBlocked},
		},
	}
	ext := CollectExtractionStats(tree)
	if ext.Total != 4 || ext.Extracted != 1 || ext.Failed != 1 || ext.ToolMissing != 1 || ext.SecurityBlocked != 1 {
		t.Fatalf("unexpected extraction stats: %+v", ext)
	}

	scans := []scan.ScanResult{{NodePath: "a"}, {NodePath: "b", Error: testErr("x")}}
	scn := CollectScanStats(scans)
	if scn.Total != 2 || scn.Successful != 1 || scn.Errors != 1 || scn.NoComponentTasks != 1 {
		t.Fatalf("unexpected scan stats: %+v", scn)
	}

	pol := CollectPolicyStats([]policy.Decision{{Action: policy.ActionContinue}, {Action: policy.ActionSkip}, {Action: policy.ActionAbort}})
	if pol.Total != 3 || pol.Continue != 1 || pol.Skip != 1 || pol.Abort != 1 {
		t.Fatalf("unexpected policy stats: %+v", pol)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }
