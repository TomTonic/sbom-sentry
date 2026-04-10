// Package main provides the CLI entry point for sbom-sentry.
// sbom-sentry is a tool for standardized incoming inspection of software
// deliveries. Given a single delivery file, it produces a consolidated
// CycloneDX SBOM and a formal audit report.
//
// Configuration is resolved from (in order of precedence):
//  1. Command-line flags
//  2. Environment variables (SBOM_SENTRY_<FLAG_NAME>)
//  3. Configuration file (--config or auto-discovered)
//  4. Built-in defaults
//
// Configuration files are YAML format and searched in:
//   - Current directory: .sbom-sentry.yaml, .sbom-sentry.yml
//   - Home directory: ~/.sbom-sentry.yaml
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/orchestrator"
)

// scriptVersion is set at build time via -ldflags.
var scriptVersion = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	var (
		configPath string
		outputDir  string
		workDir    string
		sbomFormat string
		policyStr  string
		modeStr    string
		reportStr  string
		language   string
		mfg        string
		name       string
		version    string
		delivDate  string
		rootProps  []string
		unsafe     bool
		maxDepth   int
		maxFiles   int
		maxSize    int64
		maxEntry   int64
		maxRatio   int
		timeout    string
	)

	cmd := &cobra.Command{
		Use:   "sbom-sentry [flags] <input-file>",
		Short: "Standardized incoming inspection of software deliveries",
		Long: `sbom-sentry inspects a software delivery file and produces:
  1. A consolidated CycloneDX SBOM
  2. A formal audit report

It recursively extracts nested archives, invokes Syft for component
cataloging, and merges all findings into a single SBOM with full
delivery-path traceability.

Configuration can be set via:
  - Command-line flags (highest precedence)
  - Environment variables (SBOM_SENTRY_<FLAG_NAME>)
  - Configuration file (YAML format)
  - Built-in defaults (lowest precedence)`,
		Version: scriptVersion,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd, args)
			if err != nil {
				return err
			}

			// Print unsafe warning.
			if cfg.Unsafe {
				fmt.Fprintln(os.Stderr, "WARNING: --unsafe mode is active. External extraction tools will run WITHOUT sandbox isolation.")
				fmt.Fprintln(os.Stderr, "This mode should only be used in controlled environments or for forensic analysis.")
				fmt.Fprintln(os.Stderr)
			}

			// Set up context with signal handling.
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			// Run the pipeline.
			result := orchestrator.Run(ctx, cfg)
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
			}

			if result.SBOMPath != "" {
				fmt.Fprintf(os.Stderr, "SBOM: %s\n", result.SBOMPath)
			}
			if result.ReportPath != "" {
				fmt.Fprintf(os.Stderr, "Report: %s\n", result.ReportPath)
			}

			os.Exit(int(result.ExitCode))
			return nil
		},
	}

	// Get defaults for proper flag initialization.
	defaults := config.DefaultConfig()

	// Configuration file flag.
	cmd.Flags().StringVar(&configPath, "config", "", "Configuration file path (YAML format; auto-discovered if not set)")

	// CLI flags (also bound to viper for env var / config file support).
	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", ".", "Target directory for SBOM and report output")
	cmd.Flags().StringVar(&workDir, "work-dir", defaults.WorkDir, "Base directory for temporary extraction work")
	cmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx-json", "SBOM output format")
	cmd.Flags().StringVar(&policyStr, "policy", "strict", "Policy mode: strict (abort on limit) or partial (skip and continue)")
	cmd.Flags().StringVar(&modeStr, "mode", "installer-semantic", "Interpretation mode: physical or installer-semantic")
	cmd.Flags().StringVar(&reportStr, "report", "human", "Report output mode: human, machine, or both")
	cmd.Flags().StringVar(&language, "language", "en", "Report language: en or de")
	cmd.Flags().StringVar(&mfg, "root-manufacturer", "", "Manufacturer/supplier for the SBOM root component")
	cmd.Flags().StringVar(&name, "root-name", "", "Software/product name for the SBOM root component")
	cmd.Flags().StringVar(&version, "root-version", "", "Version for the SBOM root component")
	cmd.Flags().StringVar(&delivDate, "root-delivery-date", "", "Delivery date (YYYY-MM-DD) for the SBOM root component")
	cmd.Flags().StringArrayVar(&rootProps, "root-property", nil, "Additional root metadata as key=value (repeatable)")
	cmd.Flags().BoolVar(&unsafe, "unsafe", false, "Allow unsandboxed extraction (MUST never be silent)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", defaults.Limits.MaxDepth, "Maximum extraction recursion depth")
	cmd.Flags().IntVar(&maxFiles, "max-files", defaults.Limits.MaxFiles, "Maximum total extracted file count")
	cmd.Flags().Int64Var(&maxSize, "max-size", defaults.Limits.MaxTotalSize, "Maximum total uncompressed size in bytes")
	cmd.Flags().Int64Var(&maxEntry, "max-entry-size", defaults.Limits.MaxEntrySize, "Maximum single entry size in bytes")
	cmd.Flags().IntVar(&maxRatio, "max-ratio", defaults.Limits.MaxRatio, "Maximum compression ratio per entry")
	cmd.Flags().StringVar(&timeout, "timeout", "", "Per-extraction timeout")

	return cmd
}

func loadConfig(cmd *cobra.Command, args []string) (config.Config, error) {
	v := viper.New()
	v.SetConfigName(".sbom-sentry")
	v.AddConfigPath(".")
	if home, err := os.UserHomeDir(); err == nil {
		v.AddConfigPath(home)
	}

	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return config.Config{}, fmt.Errorf("read config flag: %w", err)
	}
	if configPath != "" {
		v.SetConfigFile(configPath)
	}

	v.SetEnvPrefix("SBOM_SENTRY")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	var bindErr error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if bindErr != nil {
			return
		}
		if bindFlagErr := v.BindPFlag(f.Name, f); bindFlagErr != nil {
			bindErr = fmt.Errorf("bind flag %s to viper: %w", f.Name, bindFlagErr)
		}
	})
	if bindErr != nil {
		return config.Config{}, bindErr
	}

	if readErr := v.ReadInConfig(); readErr != nil {
		var notFound viper.ConfigFileNotFoundError
		if configPath != "" || !errors.As(readErr, &notFound) {
			return config.Config{}, fmt.Errorf("read config: %w", readErr)
		}
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = args[0]
	cfg.OutputDir = v.GetString("output-dir")
	cfg.WorkDir = v.GetString("work-dir")
	cfg.SBOMFormat = v.GetString("format")
	cfg.Language = v.GetString("language")
	cfg.RootMetadata.Manufacturer = v.GetString("root-manufacturer")
	cfg.RootMetadata.Name = v.GetString("root-name")
	cfg.RootMetadata.Version = v.GetString("root-version")
	cfg.RootMetadata.DeliveryDate = v.GetString("root-delivery-date")
	cfg.Unsafe = v.GetBool("unsafe")
	cfg.Limits.MaxDepth = v.GetInt("max-depth")
	cfg.Limits.MaxFiles = v.GetInt("max-files")
	cfg.Limits.MaxTotalSize = v.GetInt64("max-size")
	cfg.Limits.MaxEntrySize = v.GetInt64("max-entry-size")
	cfg.Limits.MaxRatio = v.GetInt("max-ratio")

	policyMode, err := config.ParsePolicyMode(v.GetString("policy"))
	if err != nil {
		return config.Config{}, err
	}
	cfg.PolicyMode = policyMode

	interpretMode, err := config.ParseInterpretMode(v.GetString("mode"))
	if err != nil {
		return config.Config{}, err
	}
	cfg.InterpretMode = interpretMode

	reportMode, err := config.ParseReportMode(v.GetString("report"))
	if err != nil {
		return config.Config{}, err
	}
	cfg.ReportMode = reportMode

	timeoutValue := v.GetString("timeout")
	if timeoutValue != "" {
		dur, err := time.ParseDuration(timeoutValue)
		if err != nil {
			return config.Config{}, fmt.Errorf("invalid timeout: %v", err)
		}
		cfg.Limits.Timeout = dur
	}

	for _, prop := range v.GetStringSlice("root-property") {
		k, value, ok := parseKeyValue(prop)
		if !ok {
			return config.Config{}, fmt.Errorf("invalid --root-property format: %q (expected key=value)", prop)
		}
		if cfg.RootMetadata.Properties == nil {
			cfg.RootMetadata.Properties = make(map[string]string)
		}
		cfg.RootMetadata.Properties[k] = value
	}

	return cfg, nil
}

// parseKeyValue splits "key=value" into its parts.
func parseKeyValue(s string) (string, string, bool) {
	idx := -1
	for i, c := range s {
		if c == '=' {
			idx = i
			break
		}
	}
	if idx < 0 || idx == 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
