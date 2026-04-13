package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestResidualRiskWithUnsafeMode verifies that the residual risk section
// identifies unsafe mode as a risk.
func TestResidualRiskWithUnsafeMode(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Residual Risk") {
		t.Error("missing residual risk section")
	}

	if !strings.Contains(output, "sandbox isolation") {
		t.Error("residual risk does not mention sandbox isolation")
	}
}

// TestResidualRiskWithScanErrors verifies that scan errors are reported
// as a residual risk.
func TestResidualRiskWithScanErrors(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{
		{
			NodePath: "test.zip",
			Error:    &testError{msg: "syft failed"},
		},
	}

	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "scan") || !strings.Contains(output, "errors") {
		t.Error("residual risk does not mention scan errors")
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
