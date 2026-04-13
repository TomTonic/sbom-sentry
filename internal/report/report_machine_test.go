package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestGenerateMachineIncludesProcessingIssues verifies that machine output
// includes processing issues for downstream automation.
func TestGenerateMachineIncludesProcessingIssues(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ProcessingIssues = []ProcessingIssue{{
		Stage:   "scan",
		Message: "syft catalog error",
	}}

	var buf bytes.Buffer
	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid machine report JSON: %v", err)
	}

	issues, ok := parsed["issues"].([]interface{})
	if !ok || len(issues) != 1 {
		t.Fatalf("issues missing or wrong size: %#v", parsed["issues"])
	}
	issue, ok := issues[0].(map[string]interface{})
	if !ok {
		t.Fatalf("issue entry has wrong type: %#v", issues[0])
	}
	if issue["stage"] != "scan" || issue["message"] != "syft catalog error" {
		t.Fatalf("unexpected issue payload: %#v", issue)
	}
}

// TestGenerateMachineIncludesEvidencePaths verifies that machine-readable scan
// entries expose evidence paths for downstream automation.
func TestGenerateMachineIncludesEvidencePaths(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{{
		NodePath: "test.zip/lib.jar",
		BOM:      &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "pkg:maven/com.acme/demo@1.0.0"}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {"test.zip/lib.jar/META-INF/MANIFEST.MF"},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report struct {
		Scans []struct {
			NodePath      string   `json:"nodePath"`
			EvidencePaths []string `json:"evidencePaths"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.Scans) != 1 {
		t.Fatalf("machine report scans = %d, want 1", len(report.Scans))
	}
	if !reflect.DeepEqual(report.Scans[0].EvidencePaths, []string{"test.zip/lib.jar/META-INF/MANIFEST.MF"}) {
		t.Fatalf("evidencePaths = %v, want manifest path", report.Scans[0].EvidencePaths)
	}
}

// TestGenerateMachineProducesValidJSON verifies that the machine-readable
// report is valid JSON with the expected schema.
func TestGenerateMachineProducesValidJSON(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report["schemaVersion"] != "1.0.0" {
		t.Errorf("schemaVersion = %v, want %q", report["schemaVersion"], "1.0.0")
	}

	if report["input"] == nil {
		t.Error("missing 'input' field in JSON report")
	}

	if report["config"] == nil {
		t.Error("missing 'config' field in JSON report")
	}

	if report["extraction"] == nil {
		t.Error("missing 'extraction' field in JSON report")
	}

	generator, ok := report["generator"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'generator' field in JSON report")
	}
	if generator["version"] != "v1.2.3" {
		t.Fatalf("generator.version = %v, want %q", generator["version"], "v1.2.3")
	}
}

// TestGenerateMachineContainsTiming verifies that the machine report
// includes start/end times and duration.
func TestGenerateMachineContainsTiming(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMachine(data, &buf); err != nil {
		t.Fatalf("GenerateMachine error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report["startTime"] == nil {
		t.Error("missing startTime in JSON report")
	}

	if report["endTime"] == nil {
		t.Error("missing endTime in JSON report")
	}

	if report["duration"] == nil {
		t.Error("missing duration in JSON report")
	}
}
