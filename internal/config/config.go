package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PolicyMode controls how limit/resource violations are handled.
type PolicyMode string

const (
	// PolicyStrict aborts processing when a non-hard-security limit violation is encountered.
	PolicyStrict PolicyMode = "strict"
	// PolicyPartial skips the offending subtree and continues processing.
	PolicyPartial PolicyMode = "partial"
)

// InterpretMode controls how container structures are interpreted.
type InterpretMode string

const (
	// InterpretInstallerSemantic enables installer-aware behavior where available.
	InterpretInstallerSemantic InterpretMode = "installer-semantic"
	// InterpretPhysical treats containers as physical archives without installer semantics.
	InterpretPhysical InterpretMode = "physical"
)

// ReportMode controls which report output(s) are generated.
type ReportMode string

const (
	// ReportHuman emits a human-readable markdown report.
	ReportHuman ReportMode = "human"
	// ReportMachine emits a machine-readable JSON report.
	ReportMachine ReportMode = "machine"
	// ReportBoth emits both human and machine-readable reports.
	ReportBoth ReportMode = "both"
)

// Config stores all user-configurable runtime options for sbom-sentry.
type Config struct {
	InputPath     string
	OutputDir     string
	SBOMFormat    string
	PolicyMode    PolicyMode
	InterpretMode InterpretMode
	ReportMode    ReportMode
	Language      string
	RootMetadata  RootMetadata
	Unsafe        bool
	Limits        Limits
	WorkDir       string
}

// RootMetadata contains user-provided metadata for the root SBOM component.
type RootMetadata struct {
	Manufacturer string
	Name         string
	Version      string
	DeliveryDate string
	Properties   map[string]string
}

// Limits defines extraction safety and resource constraints.
type Limits struct {
	MaxDepth     int
	MaxFiles     int
	MaxTotalSize int64
	MaxEntrySize int64
	MaxRatio     int
	Timeout      time.Duration
}

// DefaultLimits returns conservative extraction defaults that bound resource use
// for untrusted inputs while remaining practical for common vendor deliveries.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:     8,
		MaxFiles:     20000,
		MaxTotalSize: 2 * 1024 * 1024 * 1024, // 2 GiB
		MaxEntrySize: 256 * 1024 * 1024,      // 256 MiB
		MaxRatio:     300,
		Timeout:      5 * time.Minute,
	}
}

// Validate checks configuration invariants before any processing starts.
// It verifies path accessibility, enum-like field values, and root metadata format.
func (c *Config) Validate() error {
	if c.InputPath == "" {
		return errors.New("input path is required")
	}
	st, err := os.Stat(c.InputPath)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	if st.IsDir() {
		return errors.New("input path must be a file")
	}

	if c.OutputDir == "" {
		return errors.New("output-dir is required")
	}
	if err := os.MkdirAll(c.OutputDir, 0o750); err != nil {
		return fmt.Errorf("create output-dir: %w", err)
	}
	tmp, err := os.CreateTemp(c.OutputDir, ".writable-check-")
	if err != nil {
		return fmt.Errorf("output-dir is not writable: %w", err)
	}
	_ = tmp.Close()
	_ = os.Remove(tmp.Name())

	switch c.PolicyMode {
	case PolicyStrict, PolicyPartial:
	default:
		return fmt.Errorf("invalid policy mode: %q", c.PolicyMode)
	}
	switch c.InterpretMode {
	case InterpretInstallerSemantic, InterpretPhysical:
	default:
		return fmt.Errorf("invalid interpretation mode: %q", c.InterpretMode)
	}
	switch c.ReportMode {
	case ReportHuman, ReportMachine, ReportBoth:
	default:
		return fmt.Errorf("invalid report mode: %q", c.ReportMode)
	}
	switch c.Language {
	case "en", "de":
	default:
		return fmt.Errorf("invalid language: %q", c.Language)
	}

	if c.SBOMFormat == "" {
		c.SBOMFormat = "cyclonedx-json"
	}
	if c.SBOMFormat != "cyclonedx-json" {
		return fmt.Errorf("unsupported sbom format: %q", c.SBOMFormat)
	}

	if c.Limits.MaxDepth < 0 || c.Limits.MaxFiles <= 0 || c.Limits.MaxTotalSize <= 0 || c.Limits.MaxEntrySize <= 0 || c.Limits.MaxRatio <= 0 || c.Limits.Timeout <= 0 {
		return errors.New("invalid limits: all limits must be positive (max-depth can be 0)")
	}

	if err := c.RootMetadata.Validate(); err != nil {
		return fmt.Errorf("invalid root metadata: %w", err)
	}

	if c.WorkDir != "" {
		abs, err := filepath.Abs(c.WorkDir)
		if err != nil {
			return fmt.Errorf("resolve work dir: %w", err)
		}
		c.WorkDir = abs
		if err := os.MkdirAll(c.WorkDir, 0o750); err != nil {
			return fmt.Errorf("create work dir: %w", err)
		}
	}

	return nil
}

// Validate normalizes and validates root metadata from CLI/config sources.
// It ensures date formatting is canonical and property keys are well-formed.
func (r *RootMetadata) Validate() error {
	if r.DeliveryDate != "" {
		if _, err := time.Parse("2006-01-02", r.DeliveryDate); err != nil {
			return fmt.Errorf("delivery-date must be YYYY-MM-DD: %w", err)
		}
	}

	if r.Properties == nil {
		r.Properties = map[string]string{}
	}
	normalized := make(map[string]string, len(r.Properties))
	for k, v := range r.Properties {
		key := strings.TrimSpace(k)
		if key == "" {
			return errors.New("root property key must not be empty")
		}
		normalized[key] = strings.TrimSpace(v)
	}
	r.Properties = normalized

	return nil
}

// ParseRootProperty converts one key=value CLI argument into structured data.
// It returns an error for malformed entries or empty keys.
func ParseRootProperty(raw string) (string, string, error) {
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("root-property must be key=value, got %q", raw)
	}
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])
	if k == "" {
		return "", "", errors.New("root-property key must not be empty")
	}
	return k, v, nil
}
