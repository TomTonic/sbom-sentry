package releasetest

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseScriptIntegration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("release script integration test requires linux or darwin")
	}

	requireExternalToolsOrSkip(t)

	repoRoot := findRepoRoot(t)
	candidate := strings.TrimSpace(os.Getenv("RELEASE_TEST_CANDIDATE"))
	if candidate == "" {
		candidate = filepath.Join(t.TempDir(), "extract-sbom")

		build := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/extract-sbom")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build release candidate failed: %v\n%s", err, string(out))
		}
	} else {
		if info, err := os.Stat(candidate); err != nil {
			t.Fatalf("RELEASE_TEST_CANDIDATE does not exist: %s (%v)", candidate, err)
		} else if info.IsDir() {
			t.Fatalf("RELEASE_TEST_CANDIDATE must point to a file, got directory: %s", candidate)
		}
	}

	scriptPath := filepath.Join(repoRoot, ".github", "release-test", "run-release-test.sh")
	inputZip := filepath.Join(repoRoot, "integration", "vendorsuite", "testdata", "vendor-suite-3.2.zip")
	expectedPaths := filepath.Join(repoRoot, ".github", "release-test", "expected-delivery-paths.txt")

	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(),
		"RELEASE_TEST_CANDIDATE="+candidate,
		"RELEASE_TEST_INPUT_ZIP="+inputZip,
		"RELEASE_TEST_EXPECTED_PATHS="+expectedPaths,
	)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	if err := cmd.Run(); err != nil {
		t.Fatalf("release script failed: %v\n%s", err, combined.String())
	}
}

func requireExternalToolsOrSkip(t *testing.T) {
	t.Helper()

	missing := make([]string, 0, 4)
	for _, tool := range []string{"bash", "jq", "unshield"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}

	if _, err7zz := exec.LookPath("7zz"); err7zz != nil {
		if _, err7z := exec.LookPath("7z"); err7z != nil {
			missing = append(missing, "7zz/7z")
		}
	}

	if len(missing) > 0 {
		t.Skipf(
			"Skipping release script integration test; missing required tools: %s. This is acceptable because the release container test validates this later as well, but fail-early is not possible in this environment. Install these tools on the execution environment to enable this test.",
			strings.Join(missing, ", "),
		)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}

	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not find repository root from %s: %v", wd, err)
	}
	return root
}

// TestReleaseGrypeRoundtrip runs extract-sbom --grype against the vendor-suite
// zip and validates that the JSON report reports a completed vulnerability
// enrichment with a non-empty grypeVersion.  The test is skipped when Grype or
// any other required external tool is absent so it degrades gracefully in
// environments without the full toolchain.
func TestReleaseGrypeRoundtrip(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("grype roundtrip test requires linux or darwin")
	}

	requireExternalToolsOrSkip(t)
	if _, err := exec.LookPath("grype"); err != nil {
		t.Skip("skipping grype roundtrip: grype not installed")
	}

	repoRoot := findRepoRoot(t)
	candidate := strings.TrimSpace(os.Getenv("RELEASE_TEST_CANDIDATE"))
	if candidate == "" {
		candidate = filepath.Join(t.TempDir(), "extract-sbom")
		build := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/extract-sbom")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build failed: %v\n%s", err, string(out))
		}
	} else {
		if strings.Contains(candidate, string(os.PathSeparator)) {
			t.Fatalf("RELEASE_TEST_CANDIDATE must be a command name without path separators: %q", candidate)
		}
		resolved, err := exec.LookPath(candidate)
		if err != nil {
			t.Fatalf("RELEASE_TEST_CANDIDATE not found in PATH: %v", err)
		}
		candidate = resolved
	}

	inputZip := filepath.Join(repoRoot, "integration", "vendorsuite", "testdata", "vendor-suite-3.2.zip")
	outDir := t.TempDir()

	// #nosec G702 -- candidate is either locally built or resolved via LookPath after validation.
	cmd := exec.Command(candidate,
		"--grype",
		"--report", "both",
		"--unsafe",
		"--output-dir", outDir,
		"--root-name", "vendor-suite",
		inputZip,
	)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 1 {
			t.Fatalf("extract-sbom --grype failed: %v\n%s", err, combined.String())
		}
	}

	machineReportPath := filepath.Join(outDir, "vendor-suite-3.2.report.json")
	humanReportPath := filepath.Join(outDir, "vendor-suite-3.2.report.md")

	if _, err := os.Stat(machineReportPath); err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	if _, err := os.Stat(humanReportPath); err != nil {
		t.Fatalf("markdown report not written: %v", err)
	}

	raw, err := os.ReadFile(machineReportPath)
	if err != nil {
		t.Fatalf("reading JSON report: %v", err)
	}

	var report struct {
		Vulnerabilities struct {
			State        string `json:"state"`
			Requested    bool   `json:"requested"`
			GrypeVersion string `json:"grypeVersion"`
		} `json:"vulnerabilities"`
	}
	if unmarshalErr := json.Unmarshal(raw, &report); unmarshalErr != nil {
		t.Fatalf("parsing JSON report JSON: %v", unmarshalErr)
	}

	if report.Vulnerabilities.State != "completed" {
		t.Errorf("vulnerabilities.state = %q, want completed", report.Vulnerabilities.State)
	}
	if !report.Vulnerabilities.Requested {
		t.Error("vulnerabilities.requested = false, want true")
	}
	if report.Vulnerabilities.GrypeVersion == "" {
		t.Error("vulnerabilities.grypeVersion is empty")
	}

	humanRaw, err := os.ReadFile(humanReportPath)
	if err != nil {
		t.Fatalf("reading markdown report: %v", err)
	}
	if !bytes.Contains(humanRaw, []byte("Vulnerability")) {
		t.Error("markdown report does not contain 'Vulnerability' section")
	}

	t.Logf("grype roundtrip passed (grypeVersion=%s)", report.Vulnerabilities.GrypeVersion)
}
