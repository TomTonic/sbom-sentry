package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sbom-sentry/internal/config"
)

// TestParseKeyValue verifies key=value parsing for root properties.
func TestParseKeyValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
		wantOK  bool
	}{
		// Valid cases
		{
			name:    "simple key=value",
			input:   "foo=bar",
			wantKey: "foo",
			wantVal: "bar",
			wantOK:  true,
		},
		{
			name:    "key with multiple equals signs",
			input:   "key=value=with=equals",
			wantKey: "key",
			wantVal: "value=with=equals",
			wantOK:  true,
		},
		{
			name:    "empty value is valid",
			input:   "key=",
			wantKey: "key",
			wantVal: "",
			wantOK:  true,
		},
		{
			name:    "alphanumeric key and value",
			input:   "my_key123=my_value456",
			wantKey: "my_key123",
			wantVal: "my_value456",
			wantOK:  true,
		},
		{
			name:    "value with special characters",
			input:   "key=value-with_special.chars@123",
			wantKey: "key",
			wantVal: "value-with_special.chars@123",
			wantOK:  true,
		},

		// Invalid cases
		{
			name:    "no equals sign",
			input:   "foobar",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "equals sign at start",
			input:   "=value",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "only equals sign",
			input:   "=",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "empty string",
			input:   "",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotVal, gotOK := parseKeyValue(tt.input)
			if gotKey != tt.wantKey || gotVal != tt.wantVal || gotOK != tt.wantOK {
				t.Errorf("parseKeyValue(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.input, gotKey, gotVal, gotOK, tt.wantKey, tt.wantVal, tt.wantOK)
			}
		})
	}
}

// TestRootCmdStructure verifies that rootCmd returns a properly configured cobra.Command.
func TestRootCmdStructure(t *testing.T) {
	t.Parallel()

	cmd := rootCmd()

	tests := []struct {
		name      string
		condition bool
		message   string
	}{
		{"has Use", cmd.Use != "", "rootCmd should have Use"},
		{"has Short", cmd.Short != "", "rootCmd should have Short description"},
		{"has Long", cmd.Long != "", "rootCmd should have Long description"},
		{"has RunE", cmd.RunE != nil, "rootCmd should have RunE callback"},
		{"requires args", cmd.Args != nil, "rootCmd should specify argument requirements"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.condition {
				t.Error(tt.message)
			}
		})
	}
}

// TestRootCmdFlagsExist verifies that all expected flags are registered.
func TestRootCmdFlagsExist(t *testing.T) {
	t.Parallel()

	cmd := rootCmd()
	flags := cmd.Flags()

	expectedFlags := []string{
		"config",
		"output-dir",
		"work-dir",
		"format",
		"policy",
		"mode",
		"report",
		"language",
		"root-manufacturer",
		"root-name",
		"root-version",
		"root-delivery-date",
		"root-property",
		"unsafe",
		"max-depth",
		"max-files",
		"max-size",
		"max-entry-size",
		"max-ratio",
		"timeout",
	}

	for _, flagName := range expectedFlags {
		t.Run(flagName, func(t *testing.T) {
			flag := flags.Lookup(flagName)
			if flag == nil {
				t.Errorf("flag %q not found", flagName)
			}
		})
	}
}

// TestLoadConfigRespectsPrecedence verifies that configuration loading honors
// the documented precedence of flags over environment over config file.
func TestLoadConfigRespectsPrecedence(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	configOutputDir := filepath.Join(dir, "config-output")
	configWorkDir := filepath.Join(dir, "config-work")
	if err := os.MkdirAll(configOutputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configWorkDir, 0o750); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "sbom-sentry.yaml")
	configContent := "output-dir: \"" + configOutputDir + "\"\n" +
		"work-dir: \"" + configWorkDir + "\"\n" +
		"policy: partial\n" +
		"mode: physical\n" +
		"report: machine\n" +
		"language: de\n" +
		"root-version: config-version\n" +
		"max-files: 321\n" +
		"timeout: 42s\n" +
		"root-property:\n" +
		"  - source=config\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SBOM_SENTRY_LANGUAGE", "en")
	t.Setenv("SBOM_SENTRY_ROOT_VERSION", "env-version")

	cmd := rootCmd()
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("report", "both"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("root-version", "flag-version"); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.OutputDir != configOutputDir {
		t.Fatalf("OutputDir = %q, want %q", cfg.OutputDir, configOutputDir)
	}
	if cfg.WorkDir != configWorkDir {
		t.Fatalf("WorkDir = %q, want %q", cfg.WorkDir, configWorkDir)
	}
	if cfg.Language != "en" {
		t.Fatalf("Language = %q, want %q", cfg.Language, "en")
	}
	if cfg.RootMetadata.Version != "flag-version" {
		t.Fatalf("RootMetadata.Version = %q, want %q", cfg.RootMetadata.Version, "flag-version")
	}
	if cfg.ReportMode != config.ReportBoth {
		t.Fatalf("ReportMode = %v, want %v", cfg.ReportMode, config.ReportBoth)
	}
	if cfg.PolicyMode != config.PolicyPartial {
		t.Fatalf("PolicyMode = %v, want %v", cfg.PolicyMode, config.PolicyPartial)
	}
	if cfg.InterpretMode != config.InterpretPhysical {
		t.Fatalf("InterpretMode = %v, want %v", cfg.InterpretMode, config.InterpretPhysical)
	}
	if cfg.Limits.MaxFiles != 321 {
		t.Fatalf("MaxFiles = %d, want %d", cfg.Limits.MaxFiles, 321)
	}
	if cfg.Limits.Timeout != 42*time.Second {
		t.Fatalf("Timeout = %s, want %s", cfg.Limits.Timeout, 42*time.Second)
	}
	if cfg.RootMetadata.Properties["source"] != "config" {
		t.Fatalf("root property source = %q, want %q", cfg.RootMetadata.Properties["source"], "config")
	}
}

// TestLoadConfigReturnsErrorForInvalidExplicitConfig verifies that an explicit
// malformed config file is rejected rather than being silently ignored.
func TestLoadConfigReturnsErrorForInvalidExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(configPath, []byte("report: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected loadConfig to fail for malformed explicit config file")
	}
}
