// Config module tests: Validate that configuration parsing, defaults, and
// validation work correctly. This belongs to the configuration subsystem
// which governs all runtime parameters for delivery inspection.
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultLimitsMatchDesignSpec verifies that DefaultLimits returns values
// matching DESIGN.md §6.1 defaults. Users rely on these defaults being safe
// for typical vendor deliveries without manual tuning.
func TestDefaultLimitsMatchDesignSpec(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"MaxDepth is 6", l.MaxDepth, 6},
		{"MaxFiles is 200000", l.MaxFiles, 200000},
		{"MaxTotalSize is 20 GiB", l.MaxTotalSize, int64(20 * 1024 * 1024 * 1024)},
		{"MaxEntrySize is 2 GiB", l.MaxEntrySize, int64(2 * 1024 * 1024 * 1024)},
		{"MaxRatio is 150", l.MaxRatio, 150},
		{"Timeout is 60s", l.Timeout, 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

// TestDefaultConfigHasSensibleValues verifies that DefaultConfig returns a
// config with correct default values for all fields. Users create configs
// from defaults and override only what they need.
func TestDefaultConfigHasSensibleValues(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()

	if cfg.SBOMFormat != "cyclonedx-json" {
		t.Errorf("SBOMFormat = %q, want cyclonedx-json", cfg.SBOMFormat)
	}
	if cfg.PolicyMode != PolicyStrict {
		t.Errorf("PolicyMode = %v, want strict", cfg.PolicyMode)
	}
	if cfg.InterpretMode != InterpretInstallerSemantic {
		t.Errorf("InterpretMode = %v, want installer-semantic", cfg.InterpretMode)
	}
	if cfg.ReportMode != ReportHuman {
		t.Errorf("ReportMode = %v, want human", cfg.ReportMode)
	}
	if cfg.Language != "en" {
		t.Errorf("Language = %q, want en", cfg.Language)
	}
	if cfg.WorkDir != os.TempDir() {
		t.Errorf("WorkDir = %q, want %q", cfg.WorkDir, os.TempDir())
	}
}

// TestParsePolicyModeAcceptsValidValues verifies that ParsePolicyMode
// correctly maps string input to PolicyMode values, enabling reliable
// CLI flag parsing.
func TestParsePolicyModeAcceptsValidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    PolicyMode
		wantErr bool
	}{
		{"strict lowercase", "strict", PolicyStrict, false},
		{"partial lowercase", "partial", PolicyPartial, false},
		{"strict mixed case", "Strict", PolicyStrict, false},
		{"partial mixed case", "PARTIAL", PolicyPartial, false},
		{"invalid value rejected", "aggressive", PolicyStrict, true},
		{"empty string rejected", "", PolicyStrict, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePolicyMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePolicyMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParsePolicyMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseInterpretModeAcceptsValidValues verifies that InterpretMode
// parsing supports both documented modes. The interpretation mode controls
// how MSI and installer content is modeled in the SBOM.
func TestParseInterpretModeAcceptsValidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    InterpretMode
		wantErr bool
	}{
		{"physical", "physical", InterpretPhysical, false},
		{"installer-semantic", "installer-semantic", InterpretInstallerSemantic, false},
		{"invalid rejected", "deep", InterpretPhysical, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseInterpretMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseReportModeAcceptsValidValues verifies that ReportMode parsing
// supports all three documented output modes. Users select human, machine,
// or both depending on their automation needs.
func TestParseReportModeAcceptsValidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    ReportMode
		wantErr bool
	}{
		{"human", "human", ReportHuman, false},
		{"machine", "machine", ReportMachine, false},
		{"both", "both", ReportBoth, false},
		{"invalid rejected", "xml", ReportHuman, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseReportMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRootMetadataValidateChecksDeliveryDateFormat verifies that delivery
// date validation enforces YYYY-MM-DD format and rejects invalid calendar
// dates. Delivery dates appear in the SBOM and must be unambiguous.
func TestRootMetadataValidateChecksDeliveryDateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		date    string
		wantErr bool
	}{
		{"valid date", "2024-01-15", false},
		{"empty date is OK", "", false},
		{"invalid format MM-DD-YYYY", "01-15-2024", true},
		{"invalid date Feb 31", "2024-02-31", true},
		{"invalid format no dashes", "20240115", true},
		{"valid leap year", "2024-02-29", false},
		{"invalid non-leap year", "2023-02-29", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rm := &RootMetadata{DeliveryDate: tt.date}
			err := rm.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConfigValidateRejectsInvalidConfig verifies that Config.Validate
// catches missing or invalid required fields. This prevents runtime errors
// by failing fast at startup.
func TestConfigValidateRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	// Create a valid temporary input file and output directory.
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.zip")
	if err := os.WriteFile(inputFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{"valid config", func(_ *Config) {}, false},
		{"missing input path", func(c *Config) { c.InputPath = "" }, true},
		{"missing output dir", func(c *Config) { c.OutputDir = "" }, true},
		{"nonexistent input file", func(c *Config) { c.InputPath = "/nonexistent/file.zip" }, true},
		{"input is directory", func(c *Config) { c.InputPath = tmpDir }, true},
		{"unsupported language", func(c *Config) { c.Language = "fr" }, true},
		{"missing work dir", func(c *Config) { c.WorkDir = "" }, true},
		{"nonexistent work dir", func(c *Config) { c.WorkDir = "/nonexistent/work-dir" }, true},
		{"work dir is file", func(c *Config) { c.WorkDir = inputFile }, true},
		{"unsupported SBOM format", func(c *Config) { c.SBOMFormat = "spdx" }, true},
		{"max-depth zero", func(c *Config) { c.Limits.MaxDepth = 0 }, true},
		{"max-files zero", func(c *Config) { c.Limits.MaxFiles = 0 }, true},
		{"max-ratio zero", func(c *Config) { c.Limits.MaxRatio = 0 }, true},
		{"timeout too short", func(c *Config) { c.Limits.Timeout = 500 * time.Millisecond }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			cfg.InputPath = inputFile
			cfg.OutputDir = tmpDir
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPolicyModeStringReturnsReadableName verifies that String() on
// PolicyMode returns the canonical string representation used in reports
// and configuration display.
func TestPolicyModeStringReturnsReadableName(t *testing.T) {
	t.Parallel()
	if PolicyStrict.String() != "strict" {
		t.Errorf("PolicyStrict.String() = %q", PolicyStrict.String())
	}
	if PolicyPartial.String() != "partial" {
		t.Errorf("PolicyPartial.String() = %q", PolicyPartial.String())
	}
}

// TestInterpretModeStringReturnsReadableName verifies the human-readable
// name of interpretation modes for inclusion in audit reports.
func TestInterpretModeStringReturnsReadableName(t *testing.T) {
	t.Parallel()
	if InterpretPhysical.String() != "physical" {
		t.Errorf("got %q", InterpretPhysical.String())
	}
	if InterpretInstallerSemantic.String() != "installer-semantic" {
		t.Errorf("got %q", InterpretInstallerSemantic.String())
	}
}

// TestReportModeStringReturnsReadableName verifies the human-readable
// name of report modes for use in log messages and configuration display.
func TestReportModeStringReturnsReadableName(t *testing.T) {
	t.Parallel()
	if ReportHuman.String() != "human" {
		t.Errorf("got %q", ReportHuman.String())
	}
	if ReportMachine.String() != "machine" {
		t.Errorf("got %q", ReportMachine.String())
	}
	if ReportBoth.String() != "both" {
		t.Errorf("got %q", ReportBoth.String())
	}
}
