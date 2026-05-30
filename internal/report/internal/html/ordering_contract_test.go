package html

import (
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// TestOrderingContractVulnerabilities verifies that HTML vulnerability rows are
// sorted by vulnerability ID and then bom-ref.
func TestOrderingContractVulnerabilities(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "ref-z", Name: "zlib", Version: "1.2.13"},
		{BOMRef: "ref-a", Name: "alpha", Version: "1.0.0"},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-z": {
				{VulnerabilityID: "CVE-2026-0002", Severity: "medium"},
				{VulnerabilityID: "CVE-2026-0001", Severity: "high"},
			},
			"ref-a": {
				{VulnerabilityID: "CVE-2026-0001", Severity: "critical"},
			},
		},
	}

	rows := collectVulns(data)
	got := make([]string, 0, len(rows))
	for i := range rows {
		got = append(got, rows[i].ID+"|"+rows[i].Package)
	}
	want := []string{
		"CVE-2026-0001|alpha",
		"CVE-2026-0001|zlib",
		"CVE-2026-0002|zlib",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HTML vulnerability ordering = %v, want %v", got, want)
	}
}
