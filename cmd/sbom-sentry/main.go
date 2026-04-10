package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sbom-sentry/internal/config"
	"sbom-sentry/internal/orchestrator"
)

func main() {
	cfg := config.Config{
		SBOMFormat:    "cyclonedx-json",
		PolicyMode:    config.PolicyStrict,
		InterpretMode: config.InterpretInstallerSemantic,
		ReportMode:    config.ReportHuman,
		Language:      "en",
		Limits:        config.DefaultLimits(),
		RootMetadata: config.RootMetadata{
			Properties: map[string]string{},
		},
	}

	var rootProperties []string

	cmd := &cobra.Command{
		Use:   "sbom-sentry --input <path> --output-dir <dir>",
		Short: "Generate a recursive delivery SBOM and audit report",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, raw := range rootProperties {
				k, v, err := config.ParseRootProperty(raw)
				if err != nil {
					return err
				}
				cfg.RootMetadata.Properties[k] = v
			}

			if cfg.Unsafe {
				_, _ = fmt.Fprintln(os.Stderr, "WARNING: --unsafe is active; external extraction may run without sandbox isolation")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Limits.Timeout)
			defer cancel()

			return orchestrator.Run(ctx, cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.InputPath, "input", "", "path to input delivery file")
	cmd.Flags().StringVar(&cfg.OutputDir, "output-dir", "", "directory for generated SBOM and report")
	cmd.Flags().StringVar(&cfg.SBOMFormat, "format", cfg.SBOMFormat, "SBOM format (cyclonedx-json)")
	cmd.Flags().Var(newPolicyValue(&cfg.PolicyMode), "policy", "strict | partial")
	cmd.Flags().Var(newInterpretModeValue(&cfg.InterpretMode), "mode", "installer-semantic | physical")
	cmd.Flags().Var(newReportModeValue(&cfg.ReportMode), "report", "human | machine | both")
	cmd.Flags().StringVar(&cfg.Language, "language", cfg.Language, "report language: en | de")
	cmd.Flags().StringVar(&cfg.RootMetadata.Manufacturer, "root-manufacturer", "", "root component manufacturer")
	cmd.Flags().StringVar(&cfg.RootMetadata.Name, "root-name", "", "root component name")
	cmd.Flags().StringVar(&cfg.RootMetadata.Version, "root-version", "", "root component version")
	cmd.Flags().StringVar(&cfg.RootMetadata.DeliveryDate, "root-delivery-date", "", "delivery date YYYY-MM-DD")
	cmd.Flags().StringArrayVar(&rootProperties, "root-property", nil, "root property key=value (repeatable)")
	cmd.Flags().BoolVar(&cfg.Unsafe, "unsafe", false, "allow unsandboxed extraction if bubblewrap is unavailable")
	cmd.Flags().IntVar(&cfg.Limits.MaxDepth, "max-depth", cfg.Limits.MaxDepth, "maximum recursive extraction depth")
	cmd.Flags().IntVar(&cfg.Limits.MaxFiles, "max-files", cfg.Limits.MaxFiles, "maximum extracted files per subtree")
	cmd.Flags().Int64Var(&cfg.Limits.MaxTotalSize, "max-size", cfg.Limits.MaxTotalSize, "maximum extracted bytes per subtree")
	cmd.Flags().Int64Var(&cfg.Limits.MaxEntrySize, "max-entry-size", cfg.Limits.MaxEntrySize, "maximum extracted bytes per entry")
	cmd.Flags().IntVar(&cfg.Limits.MaxRatio, "max-ratio", cfg.Limits.MaxRatio, "maximum compression ratio percentage")
	cmd.Flags().DurationVar(&cfg.Limits.Timeout, "timeout", cfg.Limits.Timeout, "overall run timeout (e.g. 5m)")

	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("output-dir")

	if err := cmd.Execute(); err != nil {
		var exitErr *orchestrator.ExitError
		if errors.As(err, &exitErr) {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(exitErr.Code)
		}
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

type policyValue struct {
	target *config.PolicyMode
}

func newPolicyValue(target *config.PolicyMode) *policyValue {
	return &policyValue{target: target}
}

func (v *policyValue) Set(s string) error {
	switch config.PolicyMode(s) {
	case config.PolicyStrict, config.PolicyPartial:
		*v.target = config.PolicyMode(s)
		return nil
	default:
		return fmt.Errorf("invalid policy: %s", s)
	}
}

func (v *policyValue) Type() string { return "policy" }

func (v *policyValue) String() string { return string(*v.target) }

type interpretModeValue struct {
	target *config.InterpretMode
}

func newInterpretModeValue(target *config.InterpretMode) *interpretModeValue {
	return &interpretModeValue{target: target}
}

func (v *interpretModeValue) Set(s string) error {
	switch config.InterpretMode(s) {
	case config.InterpretInstallerSemantic, config.InterpretPhysical:
		*v.target = config.InterpretMode(s)
		return nil
	default:
		return fmt.Errorf("invalid mode: %s", s)
	}
}

func (v *interpretModeValue) Type() string { return "interpret-mode" }

func (v *interpretModeValue) String() string { return string(*v.target) }

type reportModeValue struct {
	target *config.ReportMode
}

func newReportModeValue(target *config.ReportMode) *reportModeValue {
	return &reportModeValue{target: target}
}

func (v *reportModeValue) Set(s string) error {
	switch config.ReportMode(s) {
	case config.ReportHuman, config.ReportMachine, config.ReportBoth:
		*v.target = config.ReportMode(s)
		return nil
	default:
		return fmt.Errorf("invalid report mode: %s", s)
	}
}

func (v *reportModeValue) Type() string { return "report-mode" }

func (v *reportModeValue) String() string { return string(*v.target) }
