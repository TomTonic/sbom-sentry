package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateAcceptsMinimalConfig verifies that a user can run sbom-sentry
// with only mandatory paths plus default operational modes.
func TestValidateAcceptsMinimalConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	input := filepath.Join(tmp, "input.bin")
	if err := os.WriteFile(input, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write input fixture: %v", err)
	}

	cfg := Config{
		InputPath:     input,
		OutputDir:     filepath.Join(tmp, "out"),
		SBOMFormat:    "cyclonedx-json",
		PolicyMode:    PolicyStrict,
		InterpretMode: InterpretInstallerSemantic,
		ReportMode:    ReportHuman,
		Language:      "en",
		RootMetadata:  RootMetadata{Properties: map[string]string{}},
		Limits:        DefaultLimits(),
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

// TestParseRootPropertyRejectsMalformedInput verifies malformed key-value
// metadata is rejected so report and SBOM metadata remain deterministic.
func TestParseRootPropertyRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	if _, _, err := ParseRootProperty("missing-separator"); err == nil {
		t.Fatal("expected parse error for malformed property")
	}
}

// TestRootMetadataValidateDateFormat verifies user-provided delivery dates must
// follow YYYY-MM-DD to avoid ambiguous output semantics.
func TestRootMetadataValidateDateFormat(t *testing.T) {
	t.Parallel()

	rm := RootMetadata{DeliveryDate: "10-04-2026", Properties: map[string]string{}}
	if err := rm.Validate(); err == nil {
		t.Fatal("expected date format validation failure")
	}
}
