package sarif

import (
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func TestOrderingContractRulesAndResults(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Input.Filename = "delivery.zip"
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "ref-z", Name: "zlib", Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/z/path/zlib.jar"}}},
		{BOMRef: "ref-a", Name: "alpha", Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery/a/path/alpha.jar"}}},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-z": {{VulnerabilityID: "CVE-2026-0001", Severity: "high"}},
			"ref-a": {{VulnerabilityID: "CVE-2026-0002", Severity: "medium"}, {VulnerabilityID: "CVE-2026-0001", Severity: "critical"}},
		},
	}

	rules := buildRules(data.Vulnerabilities)
	if len(rules) != 2 || rules[0].ID != "CVE-2026-0001" || rules[1].ID != "CVE-2026-0002" {
		t.Fatalf("SARIF rule ordering changed: %+v", rules)
	}

	results := buildResults(data)
	got := make([]string, 0, len(results))
	for i := range results {
		uri := ""
		if len(results[i].Locations) > 0 {
			uri = results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		got = append(got, results[i].RuleID+"@"+uri)
	}
	want := []string{
		"CVE-2026-0001@delivery/a/path/alpha.jar",
		"CVE-2026-0002@delivery/a/path/alpha.jar",
		"CVE-2026-0001@delivery/z/path/zlib.jar",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SARIF result ordering = %v, want %v", got, want)
	}
}
