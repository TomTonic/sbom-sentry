package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TomTonic/extract-sbom/internal/config"
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
		"markdown-render-engine",
		"markdown-template-file",
		"root-manufacturer",
		"root-name",
		"root-version",
		"root-delivery-date",
		"root-property",
		"grype",
		"unsafe",
		"max-depth",
		"max-files",
		"max-size",
		"max-entry-size",
		"max-ratio",
		"timeout",
		"progress",
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

	configPath := filepath.Join(dir, "extract-sbom.yaml")
	configContent := "output-dir: \"" + configOutputDir + "\"\n" +
		"work-dir: \"" + configWorkDir + "\"\n" +
		"policy: partial\n" +
		"mode: physical\n" +
		"report: json\n" +
		"language: de\n" +
		"root-version: config-version\n" +
		"max-files: 321\n" +
		"timeout: 42s\n" +
		"root-property:\n" +
		"  - source=config\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("EXTRACT_SBOM_LANGUAGE", "en")
	t.Setenv("EXTRACT_SBOM_ROOT_VERSION", "env-version")

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
	if cfg.ReportSelection != config.ReportBoth {
		t.Fatalf("ReportSelection = %v, want %v", cfg.ReportSelection, config.ReportBoth)
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

func TestLoadConfigRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("policy", "bogus"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestLoadConfigParsesGrypeFlag(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("grype", "true"); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if !cfg.GrypeEnabled {
		t.Fatal("GrypeEnabled = false, want true")
	}
}

func TestLoadConfigParsesHumanRenderOptions(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	tplPath := filepath.Join(dir, "human.tpl")
	if err := os.WriteFile(tplPath, []byte("{{.Body}}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("markdown-render-engine", "template-wrapper"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("markdown-template-file", tplPath); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.MarkdownRenderEngine != "template-wrapper" {
		t.Fatalf("MarkdownRenderEngine = %q, want %q", cfg.MarkdownRenderEngine, "template-wrapper")
	}
	if cfg.MarkdownTemplateFile != tplPath {
		t.Fatalf("MarkdownTemplateFile = %q, want %q", cfg.MarkdownTemplateFile, tplPath)
	}
}

func TestLoadConfigParsesDeprecatedHumanRenderFlags(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	tplPath := filepath.Join(dir, "legacy-human.tpl")
	if err := os.WriteFile(tplPath, []byte("{{.Body}}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("human-render-engine", "template-wrapper"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("human-template-file", tplPath); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.MarkdownRenderEngine != "template-wrapper" {
		t.Fatalf("MarkdownRenderEngine = %q, want %q", cfg.MarkdownRenderEngine, "template-wrapper")
	}
	if cfg.MarkdownTemplateFile != tplPath {
		t.Fatalf("MarkdownTemplateFile = %q, want %q", cfg.MarkdownTemplateFile, tplPath)
	}
}

func TestLoadConfigRejectsInvalidMode(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("mode", "bogus"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestLoadConfigRejectsInvalidReport(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("report", "bogus"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid report mode")
	}
}

func TestLoadConfigRejectsInvalidProgress(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("progress", "bogus"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid progress level")
	}
}

func TestLoadConfigRejectsInvalidTimeout(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("timeout", "not-a-duration"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestLoadConfigRejectsInvalidRootProperty(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	if err := cmd.Flags().Set("root-property", "no-equals-sign"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(cmd, []string{inputPath}); err == nil {
		t.Fatal("expected error for invalid root-property format")
	}
}

func TestLoadConfigSkipExtensions(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("skip-extensions", ".docx,.xlsx"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if len(cfg.SkipExtensions) != 2 {
		t.Fatalf("SkipExtensions = %v, want 2 elements", cfg.SkipExtensions)
	}
}

// TestRootCmdRunEReturnsLoadConfigError verifies that the RunE callback
// surfaces loadConfig errors rather than proceeding with the pipeline.
func TestRootCmdRunEReturnsLoadConfigError(t *testing.T) {
	cmd := rootCmd()
	// Set an invalid policy value so loadConfig returns an error.
	if err := cmd.Flags().Set("policy", "bogus"); err != nil {
		t.Fatal(err)
	}
	// Invoke RunE directly.
	err := cmd.RunE(cmd, []string{"/nonexistent/input.zip"})
	if err == nil {
		t.Fatal("expected RunE to return loadConfig error")
	}
}

func TestLoadConfigMultipleRootProperties(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("root-property", "key1=val1"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("root-property", "key2=val2"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if cfg.RootMetadata.Properties["key1"] != "val1" || cfg.RootMetadata.Properties["key2"] != "val2" {
		t.Fatalf("properties = %v, want key1=val1 and key2=val2", cfg.RootMetadata.Properties)
	}
}

func TestLoadConfigValidTimeout(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("timeout", "30s"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if cfg.Limits.Timeout != 30*time.Second {
		t.Fatalf("Timeout = %s, want 30s", cfg.Limits.Timeout)
	}
}

// TestLoadPasswordFile validates that loadPasswordFile reads passwords from a
// file correctly, ignoring blank lines and comment lines beginning with '#'.
func TestLoadPasswordFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "simple list",
			content: "alpha\nbeta\ngamma\n",
			want:    []string{"alpha", "beta", "gamma"},
		},
		{
			name:    "comments and blank lines are ignored",
			content: "# header comment\n\nalpha\n  \n# another comment\nbeta\n",
			want:    []string{"alpha", "beta"},
		},
		{
			name:    "empty file yields empty slice",
			content: "",
			want:    nil,
		},
		{
			name:    "only comments yields empty slice",
			content: "# pw1\n# pw2\n",
			want:    nil,
		},
		{
			name:    "trailing whitespace is trimmed from entries",
			content: "  pw1  \npw2\n",
			want:    []string{"pw1", "pw2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pwFile := filepath.Join(dir, "passwords.txt")
			if err := os.WriteFile(pwFile, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := loadPasswordFile(pwFile)
			if err != nil {
				t.Fatalf("loadPasswordFile error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i, v := range tc.want {
				if got[i] != v {
					t.Errorf("passwords[%d] = %q, want %q", i, got[i], v)
				}
			}
		})
	}
}

// TestLoadPasswordFileMissing validates that loadPasswordFile returns an error
// when the specified file does not exist.
func TestLoadPasswordFileMissing(t *testing.T) {
	t.Parallel()
	_, err := loadPasswordFile("/nonexistent/path/passwords.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadConfigPasswordFlag validates that --password flags are collected into
// Config.Passwords in the order they were supplied.
func TestLoadConfigPasswordFlag(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("password", "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("password", "beta"); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if len(cfg.Passwords) != 2 || cfg.Passwords[0] != "alpha" || cfg.Passwords[1] != "beta" {
		t.Errorf("Passwords = %v, want [alpha beta]", cfg.Passwords)
	}
}

// TestLoadConfigPasswordFile validates that --password-file is loaded and its
// passwords are appended to Config.Passwords after any --password entries.
func TestLoadConfigPasswordFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	pwFile := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(pwFile, []byte("fromfile1\nfromfile2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("password", "fromflag"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("password-file", pwFile); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cmd, []string{inputPath})
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	// Expected: flag passwords first, then file passwords.
	want := []string{"fromflag", "fromfile1", "fromfile2"}
	if len(cfg.Passwords) != len(want) {
		t.Fatalf("Passwords = %v, want %v", cfg.Passwords, want)
	}
	for i, v := range want {
		if cfg.Passwords[i] != v {
			t.Errorf("Passwords[%d] = %q, want %q", i, cfg.Passwords[i], v)
		}
	}
}

// TestLoadConfigMissingPasswordFile validates that --password-file with a
// non-existent path is rejected with a descriptive error.
func TestLoadConfigMissingPasswordFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "output")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	if err := cmd.Flags().Set("output-dir", outputDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("work-dir", workDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("password-file", "/nonexistent/pw.txt"); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(cmd, []string{inputPath})
	if err == nil {
		t.Fatal("expected error for missing password file, got nil")
	}
}
