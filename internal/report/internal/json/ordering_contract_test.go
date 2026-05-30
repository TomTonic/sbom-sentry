package json

import (
	"testing"

	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestOrderingContractSlicesPreserveProcessingOrder(t *testing.T) {
	t.Parallel()

	scans := []scan.ScanResult{{NodePath: "z/path"}, {NodePath: "a/path"}}
	decisions := []policy.Decision{
		{Trigger: "max-files", NodePath: "z/path", Action: policy.ActionSkip, Detail: "skip z"},
		{Trigger: "max-depth", NodePath: "a/path", Action: policy.ActionContinue, Detail: "continue a"},
	}

	jsonScans := buildScans(scans)
	if len(jsonScans) != 2 || jsonScans[0].NodePath != "z/path" || jsonScans[1].NodePath != "a/path" {
		t.Fatalf("JSON scan order changed: %+v", jsonScans)
	}

	jsonDecisions := buildDecisions(decisions)
	if len(jsonDecisions) != 2 || jsonDecisions[0].NodePath != "z/path" || jsonDecisions[1].NodePath != "a/path" {
		t.Fatalf("JSON decision order changed: %+v", jsonDecisions)
	}
}
