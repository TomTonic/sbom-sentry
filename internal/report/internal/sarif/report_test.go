package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

type testLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID string `json:"ruleId"`
			Level  string `json:"level"`
		} `json:"results"`
		Properties struct {
			VulnerabilityEnrichmentState     string `json:"vulnerabilityEnrichmentState"`
			VulnerabilityEnrichmentRequested bool   `json:"vulnerabilityEnrichmentRequested"`
		} `json:"properties"`
	} `json:"runs"`
}

func renderSARIF(t *testing.T, data ReportData) testLog {
	t.Helper()
	var buf bytes.Buffer
	if err := Generate(data, &buf); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	var log testLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs = %d, want 1", len(log.Runs))
	}
	return log
}

func TestGenerateProducesValidDocument(t *testing.T) {
	t.Parallel()

	log := renderSARIF(t, makeTestReportData())
	if !strings.Contains(log.Schema, "sarif") {
		t.Errorf("$schema = %q, want a SARIF schema reference", log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if log.Runs[0].Tool.Driver.Name != "extract-sbom" {
		t.Errorf("driver name = %q, want %q", log.Runs[0].Tool.Driver.Name, "extract-sbom")
	}
}

func TestGenerateEmitsRuleAndResultPerMatch(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "ref-a", Name: "libcurl", Version: "8.0.0"}}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-a": {{VulnerabilityID: "CVE-2024-0001", Severity: "critical", Description: "buffer overflow"}},
		},
	}

	log := renderSARIF(t, data)
	run := log.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "CVE-2024-0001" {
		t.Errorf("rules = %+v, want one rule with id CVE-2024-0001", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != "CVE-2024-0001" {
		t.Errorf("result ruleId = %q, want %q", run.Results[0].RuleID, "CVE-2024-0001")
	}
	if run.Results[0].Level != "error" {
		t.Errorf("result level = %q, want %q for a critical-severity match", run.Results[0].Level, "error")
	}
}

func TestGenerateRecordsEnrichmentAuditState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		vulns             *vulnscan.Result
		wantState         string
		wantRequested     bool
		wantExecSuccess   bool
		wantNotifLevelSet string
	}{
		{name: "enrichment not requested", vulns: nil, wantState: "not-requested", wantRequested: false, wantExecSuccess: true, wantNotifLevelSet: "note"},
		{name: "grype unavailable", vulns: &vulnscan.Result{Requested: true, State: vulnscan.StateUnavailable}, wantState: "unavailable", wantRequested: true, wantExecSuccess: false, wantNotifLevelSet: "error"},
		{name: "enrichment completed", vulns: &vulnscan.Result{Requested: true, State: vulnscan.StateCompleted}, wantState: "completed", wantRequested: true, wantExecSuccess: true, wantNotifLevelSet: "note"},
		{name: "enrichment completed with errors", vulns: &vulnscan.Result{Requested: true, State: vulnscan.StateCompletedWithErrors}, wantState: "completed-with-errors", wantRequested: true, wantExecSuccess: true, wantNotifLevelSet: "warning"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := makeTestReportData()
			data.Vulnerabilities = tc.vulns
			run := renderSARIF(t, data).Runs[0]

			if run.Properties.VulnerabilityEnrichmentState != tc.wantState {
				t.Errorf("properties.vulnerabilityEnrichmentState = %q, want %q", run.Properties.VulnerabilityEnrichmentState, tc.wantState)
			}
			if run.Properties.VulnerabilityEnrichmentRequested != tc.wantRequested {
				t.Errorf("properties.vulnerabilityEnrichmentRequested = %v, want %v", run.Properties.VulnerabilityEnrichmentRequested, tc.wantRequested)
			}
			if len(run.Invocations) != 1 {
				t.Fatalf("invocations = %d, want 1", len(run.Invocations))
			}
			if run.Invocations[0].ExecutionSuccessful != tc.wantExecSuccess {
				t.Errorf("invocation.executionSuccessful = %v, want %v", run.Invocations[0].ExecutionSuccessful, tc.wantExecSuccess)
			}
			notifs := run.Invocations[0].ToolExecutionNotifications
			if len(notifs) != 1 {
				t.Fatalf("toolExecutionNotifications = %d, want 1", len(notifs))
			}
			if notifs[0].Level != tc.wantNotifLevelSet {
				t.Errorf("notification level = %q, want %q", notifs[0].Level, tc.wantNotifLevelSet)
			}
			if strings.TrimSpace(notifs[0].Message.Text) == "" {
				t.Error("notification message text is empty, want an explanatory message")
			}
		})
	}
}
