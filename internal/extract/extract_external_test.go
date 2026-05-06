package extract

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtract7zMarksToolMissingWhenUnavailable(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("missing")
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sandbox.NewPassthroughSandbox(), t.TempDir(), config.DefaultLimits(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusToolMissing {
		t.Fatalf("status = %v, want %v", node.Status, StatusToolMissing)
	}
	if node.Tool != "7zz" {
		t.Fatalf("tool = %q, want %q", node.Tool, "7zz")
	}
}

func TestExtract7zUsesSandboxOutputAndSummarizesFiles(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-7zz", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{name: "recording", run: func(_ string, _ []string, _ string, outputDir string) error {
		if err := os.MkdirAll(filepath.Join(outputDir, "nested"), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "nested", "a.txt"), []byte("alpha"), 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(outputDir, "b.txt"), []byte("beta"), 0o600)
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sb, t.TempDir(), config.DefaultLimits(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sb.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(sb.calls))
	}
	if sb.calls[0].cmd != "7zz" {
		t.Fatalf("cmd = %q, want %q", sb.calls[0].cmd, "7zz")
	}
	if node.Status != StatusExtracted {
		t.Fatalf("status = %v, want %v", node.Status, StatusExtracted)
	}
	if node.SandboxUsed != "recording" {
		t.Fatalf("sandbox = %q, want %q", node.SandboxUsed, "recording")
	}
	if node.EntriesCount != 2 {
		t.Fatalf("entries = %d, want 2", node.EntriesCount)
	}
	if node.TotalSize != int64(len("alpha")+len("beta")) {
		t.Fatalf("total size = %d, want %d", node.TotalSize, len("alpha")+len("beta"))
	}
	if node.ExtractedDir == "" {
		t.Fatal("expected extracted dir to be recorded")
	}
	CleanupNode(node)
}

func TestExtractUnshieldPassesDestinationDirectory(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-unshield", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{name: "recording", run: func(_ string, args []string, _ string, outputDir string) error {
		wantArgs := []string{"-d", outputDir, "x", "/tmp/setup.cab"}
		if !reflect.DeepEqual(args, wantArgs) {
			return fmt.Errorf("args = %v, want %v", args, wantArgs)
		}
		return os.WriteFile(filepath.Join(outputDir, "payload.bin"), []byte("payload"), 0o600)
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.InstallShieldCAB}}
	err := extractUnshield(context.Background(), node, "/tmp/setup.cab", sb, t.TempDir(), config.DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Status != StatusExtracted {
		t.Fatalf("status = %v, want %v", node.Status, StatusExtracted)
	}
	if node.EntriesCount != 1 {
		t.Fatalf("entries = %d, want 1", node.EntriesCount)
	}
	CleanupNode(node)
}

func TestExtract7zRejectsUnsafePostExtractionOutput(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-7zz", nil
	}
	t.Cleanup(func() {
		lookPath = originalLookPath
	})

	sb := &recordingSandbox{run: func(_ string, _ []string, _ string, outputDir string) error {
		return os.Symlink("/etc/passwd", filepath.Join(outputDir, "escape-link"))
	}}

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.CAB}}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sb, t.TempDir(), config.DefaultLimits(), "")
	if err == nil {
		t.Fatal("expected hard security error, got nil")
	}
	if _, ok := err.(*safeguard.HardSecurityError); !ok {
		t.Fatalf("error = %T, want *safeguard.HardSecurityError", err)
	}
	if node.ExtractedDir != "" {
		t.Fatal("unsafe extraction output should not be retained")
	}
}

func TestExtract7zToolMissingRecordsStatusCorrectly(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	dir := t.TempDir()

	savedLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("executable not found")
	}
	defer func() { lookPath = savedLookPath }()

	cabContent := []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	cabPath := filepath.Join(dir, "setup.cab")
	if err := os.WriteFile(cabPath, cabContent, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = cabPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), cabPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	if tree.Status != StatusToolMissing {
		t.Errorf("status = %v, want StatusToolMissing", tree.Status)
	}
	if tree.Tool != "7zz" {
		t.Errorf("Tool = %q, want 7zz", tree.Tool)
	}
}

func TestExtractInstallShieldToolMissingRecordsStatusCorrectly(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	dir := t.TempDir()

	savedLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", fmt.Errorf("executable not found")
	}
	defer func() { lookPath = savedLookPath }()

	iscContent := []byte{'I', 'S', 'c', '(', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	iscPath := filepath.Join(dir, "data1.cab")
	if err := os.WriteFile(iscPath, iscContent, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = iscPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), iscPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	if tree.Status != StatusToolMissing {
		t.Errorf("status = %v, want StatusToolMissing", tree.Status)
	}
	if tree.Tool != "unshield" {
		t.Errorf("Tool = %q, want unshield", tree.Tool)
	}
}

func TestFormatExtractionFailureDetailAddsTarHint(t *testing.T) {
	t.Parallel()

	node := &ExtractionNode{Format: identify.FormatInfo{Format: identify.TAR}}
	err := errors.New("sandbox: 7zz execution failed: exit status 2\nstderr: extract: read tar entry: archive/tar: invalid tar header")

	detail := formatExtractionFailureDetail("7zz", node, "/tmp/broken.tar", err)
	if !strings.Contains(detail, "invalid tar header") {
		t.Fatalf("detail missing raw cause: %q", detail)
	}
	if !strings.Contains(detail, "hint:") {
		t.Fatalf("detail missing hint: %q", detail)
	}
	if strings.Contains(detail, "broken.tar") {
		t.Fatalf("detail should stay compact and not repeat filename: %q", detail)
	}
}

// TestSummarizeToolError verifies that no error information is silently lost,
// including for unrecognised or multi-line error formats produced by
// alternative 7-Zip distributions (p7zip, older 7za, etc.).
func TestSummarizeToolError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		errMsg  string
		wantAll []string // all substrings that must appear in the result
	}{
		{
			// Typical real 7-Zip output: version banner on first stderr line,
			// then ERRORS: section on a subsequent line.
			name:    "standard ERRORS section",
			errMsg:  "sandbox: 7zz execution failed: exit status 2\nstderr: 7-Zip 24.09\n\nERRORS:\nCan not open the file as archive\n",
			wantAll: []string{"Can not open the file as archive"},
		},
		{
			// Section header directly on the first stderr line (edge case now
			// handled correctly: strip "stderr:" BEFORE section detection).
			name:    "ERRORS header on first stderr line",
			errMsg:  "sandbox: 7zz execution failed: exit status 2\nstderr: ERRORS:\nerr1\nerr2\n",
			wantAll: []string{"err1", "err2"},
		},
		{
			name:    "multiple ERRORS lines – all returned up to cap",
			errMsg:  "sandbox: 7zz execution failed: exit status 2\nstderr: 7-Zip 24.09\nERRORS:\nerr1\nerr2\nerr3\nerr4\n",
			wantAll: []string{"err1", "err2", "err3", "more error"},
		},
		{
			name:    "ERRORS and WARNINGS combined – both returned",
			errMsg:  "sandbox: 7zz execution failed: exit status 2\nstderr: 7-Zip 24.09\nERRORS:\nsome error\nWARNINGS:\nsome warning\n",
			wantAll: []string{"some error", "warning: some warning"},
		},
		{
			name:    "only WARNINGS section (exit 1 warning)",
			errMsg:  "sandbox: 7zz execution failed: exit status 1\nstderr: 7-Zip 24.09\nWARNINGS:\nThere are data after the end of archive\n",
			wantAll: []string{"warning: There are data after the end of archive"},
		},
		{
			// WARNINGS: directly on the first stderr line.
			name:    "WARNINGS header on first stderr line",
			errMsg:  "sandbox: 7zz execution failed: exit status 1\nstderr: WARNINGS:\nwarn1\n",
			wantAll: []string{"warning: warn1"},
		},
		{
			name:    "multiple WARNINGS – all returned up to cap",
			errMsg:  "sandbox: 7zz execution failed: exit status 1\nstderr: 7-Zip 24.09\nWARNINGS:\nwarn1\nwarn2\nwarn3\n",
			wantAll: []string{"warning: warn1", "warning: warn2"},
		},
		{
			// p7zip / unknown variant: no section headers, plain error lines.
			// Previously only the first line was returned; now all are preserved.
			name:    "multi-line error without section headers (p7zip style)",
			errMsg:  "sandbox: 7za execution failed: exit status 2\nstderr: ERROR: archive damaged\ndetail: file offset 0x1234 is invalid\n",
			wantAll: []string{"ERROR: archive damaged", "detail: file offset"},
		},
		{
			// If generic lines AND a WARNINGS section are present, warnings
			// must not be silently suppressed.
			name:    "generic lines with WARNINGS – warnings not suppressed",
			errMsg:  "sandbox: 7zz execution failed: exit status 1\nstderr: 1 file, 12345 bytes\nWARNINGS:\ndata after end of archive\n",
			wantAll: []string{"warning: data after end of archive"},
		},
		{
			// When all lines are sandbox noise, fall back to the raw error string.
			name:    "all-noise lines fall back to raw error",
			errMsg:  "sandbox: 7zz execution failed: exit status 2",
			wantAll: []string{"exit status 2"},
		},
		{
			// The word "execution failed" in a real 7zip error line must NOT
			// be filtered out (only "sandbox:" prefix is noise).
			name:    "execution-failed in real error line is not filtered",
			errMsg:  "sandbox: 7zz execution failed: exit status 2\nstderr: ERRORS:\nSubprocess execution failed with code 5\n",
			wantAll: []string{"execution failed with code 5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := summarizeToolError(errors.New(tt.errMsg))
			for _, want := range tt.wantAll {
				if !strings.Contains(got, want) {
					t.Errorf("summarizeToolError() = %q; missing substring %q", got, want)
				}
			}
		})
	}
}

// TestIsToolNoiseLine verifies the noise-line classifier.
// In particular it ensures that "execution failed" inside a real error
// message is no longer filtered (regression guard for the prior over-broad
// strings.Contains check).
func TestIsToolNoiseLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line      string
		wantNoise bool
	}{
		// Sandbox wrapper lines – always noise.
		{"sandbox: 7zz execution failed: exit status 2", true},
		{"sandbox: bwrap execution failed: exit status 1", true},
		{"sandbox: cannot find 7zz: ...", true},
		// Standard 7-Zip banner / progress – noise.
		{"7-Zip 24.09 (x64) : Copyright ...", true},
		{"7-Zip [64] 16.02 : Copyright ...", true},
		{"Scanning the drive for archives:", true},
		{"Extracting archive: input.cab", true},
		{"Path = test.cab", true},
		{"Type = Cab", true},
		{"Physical Size = 1234", true},
		{"Headers Size = 128", true},
		{"Tail Size = 0", true},
		{"Characteristics = ...", true},
		// Empty – noise.
		{"", true},
		{"   ", true},
		// Real error/output lines – NOT noise.
		{"execution failed", false}, // doesn't start with "sandbox:"
		{"Subprocess execution failed with code 5", false},
		{"Can not open the file as archive", false},
		{"Wrong password", false},
		{"ERROR: archive is damaged", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			if got := isToolNoiseLine(tt.line); got != tt.wantNoise {
				t.Errorf("isToolNoiseLine(%q) = %v, want %v", tt.line, got, tt.wantNoise)
			}
		})
	}
}
