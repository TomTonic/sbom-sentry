package json

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGenerateV2IncludesCanonicalEnvelope(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SBOMPath = "/tmp/out/test.cdx.json"

	var buf bytes.Buffer
	if err := GenerateV2(data, &buf); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, key := range []string{"schema", "run", "input", "generator", "config", "runtime", "raw", "entities", "projections", "integrity", "compatibility"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing top-level key %q", key)
		}
	}

	schemaObj, ok := parsed["schema"].(map[string]any)
	if !ok {
		t.Fatalf("schema has unexpected type: %T", parsed["schema"])
	}
	if got := schemaObj["version"]; got != reportV2SchemaVersion {
		t.Fatalf("schema.version = %v, want %s", got, reportV2SchemaVersion)
	}

	rawObj, ok := parsed["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw has unexpected type: %T", parsed["raw"])
	}
	artifactPaths, ok := rawObj["artifactPaths"].(map[string]any)
	if !ok {
		t.Fatalf("raw.artifactPaths has unexpected type: %T", rawObj["artifactPaths"])
	}
	if got := artifactPaths["sbomPath"]; got != data.SBOMPath {
		t.Fatalf("raw.artifactPaths.sbomPath = %v, want %s", got, data.SBOMPath)
	}

	configObj, ok := parsed["config"].(map[string]any)
	if !ok {
		t.Fatalf("config has unexpected type: %T", parsed["config"])
	}
	passwords, ok := configObj["passwords"].(map[string]any)
	if !ok {
		t.Fatalf("config.passwords has unexpected type: %T", configObj["passwords"])
	}
	if got := passwords["sensitiveRedacted"]; got != true {
		t.Fatalf("config.passwords.sensitiveRedacted = %v, want true", got)
	}
}

func TestGenerateV2ConformsSchemaV2(t *testing.T) {
	t.Parallel()

	schemaBytes, readErr := os.ReadFile("report.schema.v2.json")
	if readErr != nil {
		t.Fatalf("read schema: %v", readErr)
	}
	var schemaDoc any
	if unmarshalErr := json.Unmarshal(schemaBytes, &schemaDoc); unmarshalErr != nil {
		t.Fatalf("unmarshal schema: %v", unmarshalErr)
	}

	compiler := jsonschema.NewCompiler()
	if addErr := compiler.AddResource("report.schema.v2.json", schemaDoc); addErr != nil {
		t.Fatalf("add schema resource: %v", addErr)
	}
	schema, err := compiler.Compile("report.schema.v2.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	data := makeTestReportData()
	var out bytes.Buffer
	if err := GenerateV2(data, &out); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var doc any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal generated v2 json: %v", err)
	}

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("generated v2 report does not match schema: %v", err)
	}
}

func TestGenerateV2PopulatesEntitiesAndIntegrity(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "test.zip",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{Path: "test.zip/app.jar", Status: extract.StatusSyftNative, Format: identify.FormatInfo{Format: identify.ZIP}},
		},
	}

	components := []cdx.Component{
		{
			BOMRef:     "pkg:gomod/github.com/acme/app@1.0.0",
			Name:       "github.com/acme/app",
			Version:    "1.0.0",
			Type:       cdx.ComponentTypeLibrary,
			PackageURL: "pkg:gomod/github.com/acme/app@1.0.0",
		},
		{
			BOMRef:     "pkg:gomod/github.com/acme/dep@2.0.0",
			Name:       "github.com/acme/dep",
			Version:    "2.0.0",
			Type:       cdx.ComponentTypeLibrary,
			PackageURL: "pkg:gomod/github.com/acme/dep@2.0.0",
		},
	}
	data.BOM = &cdx.BOM{Components: &components}
	data.Scans = []scan.ScanResult{{
		NodePath: "test.zip/app.jar",
		BOM:      &cdx.BOM{Components: &[]cdx.Component{components[0]}},
	}}
	data.PolicyDecisions = []policy.Decision{{
		Trigger:  "scan",
		NodePath: "test.zip/app.jar",
		Action:   policy.ActionContinue,
		Detail:   "ok",
	}}
	data.ProcessingIssues = []ProcessingIssue{{Stage: "scan", Message: "warning"}}
	data.Suppressions = []assembly.SuppressionRecord{{
		Reason:    assembly.SuppressionPURLDuplicate,
		Component: components[1],
		KeptName:  components[0].Name,
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			components[0].BOMRef: {
				{VulnerabilityID: "CVE-2026-0001", Severity: "high"},
			},
		},
	}

	var out bytes.Buffer
	if err := GenerateV2(data, &out); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal generated report: %v", err)
	}

	entities, ok := parsed["entities"].(map[string]any)
	if !ok {
		t.Fatalf("entities has unexpected type: %T", parsed["entities"])
	}
	nodes, _ := entities["nodes"].([]any)
	scanTasks, _ := entities["scanTasks"].([]any)
	componentsOut, _ := entities["components"].([]any)
	packageGroups, _ := entities["packageGroups"].([]any)
	vulnerabilitiesOut, _ := entities["vulnerabilities"].([]any)

	if len(nodes) != 2 {
		t.Fatalf("entities.nodes count = %d, want 2", len(nodes))
	}
	if len(scanTasks) != 1 {
		t.Fatalf("entities.scanTasks count = %d, want 1", len(scanTasks))
	}
	if len(componentsOut) != 2 {
		t.Fatalf("entities.components count = %d, want 2", len(componentsOut))
	}
	if len(packageGroups) != 2 {
		t.Fatalf("entities.packageGroups count = %d, want 2", len(packageGroups))
	}
	if len(vulnerabilitiesOut) != 1 {
		t.Fatalf("entities.vulnerabilities count = %d, want 1", len(vulnerabilitiesOut))
	}

	integrity, ok := parsed["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("integrity has unexpected type: %T", parsed["integrity"])
	}
	if got := int(integrity["danglingReferenceCount"].(float64)); got != 0 {
		t.Fatalf("integrity.danglingReferenceCount = %d, want 0", got)
	}
	if got := integrity["validationState"]; got != "ok" {
		t.Fatalf("integrity.validationState = %v, want ok", got)
	}
	counts, ok := integrity["counts"].(map[string]any)
	if !ok {
		t.Fatalf("integrity.counts has unexpected type: %T", integrity["counts"])
	}
	if got := int(counts["components"].(float64)); got != len(componentsOut) {
		t.Fatalf("integrity.counts.components = %d, want %d", got, len(componentsOut))
	}
}

func TestGenerateV2FlagsDanglingVulnerabilityComponentRef(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "pkg:gomod/github.com/acme/app@1.0.0",
		Name:       "github.com/acme/app",
		Version:    "1.0.0",
		Type:       cdx.ComponentTypeLibrary,
		PackageURL: "pkg:gomod/github.com/acme/app@1.0.0",
	}}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"pkg:gomod/github.com/acme/missing@9.9.9": {
				{VulnerabilityID: "CVE-2026-9999", Severity: "critical"},
			},
		},
	}

	var out bytes.Buffer
	if err := GenerateV2(data, &out); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal generated report: %v", err)
	}
	integrity, ok := parsed["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("integrity has unexpected type: %T", parsed["integrity"])
	}

	if got := int(integrity["danglingReferenceCount"].(float64)); got == 0 {
		t.Fatal("expected dangling references, got 0")
	}
	if got := integrity["validationState"]; got != "warning" {
		t.Fatalf("integrity.validationState = %v, want warning", got)
	}
	validationErrors, _ := integrity["validationErrors"].([]any)
	if len(validationErrors) == 0 {
		t.Fatal("expected non-empty integrity.validationErrors")
	}
}
