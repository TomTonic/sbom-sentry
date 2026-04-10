// Package config provides the central configuration types and defaults for
// sbom-sentry. It defines the Config struct that all modules depend on, along
// with validation logic and sensible default limits matching the design
// specification.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// PolicyMode controls behavior when resource limits are reached during extraction.
type PolicyMode int

const (
	// PolicyStrict aborts the entire run on any limit violation.
	PolicyStrict PolicyMode = iota
	// PolicyPartial skips the offending subtree and continues processing elsewhere.
	PolicyPartial
)

// String returns the human-readable name of the policy mode.
func (p PolicyMode) String() string {
	switch p {
	case PolicyStrict:
		return "strict"
	case PolicyPartial:
		return "partial"
	default:
		return "unknown"
	}
}

// ParsePolicyMode converts a string to a PolicyMode.
// Valid values are "strict" and "partial" (case-insensitive).
// Returns an error for unrecognized values.
func ParsePolicyMode(s string) (PolicyMode, error) {
	switch strings.ToLower(s) {
	case "strict":
		return PolicyStrict, nil
	case "partial":
		return PolicyPartial, nil
	default:
		return PolicyStrict, fmt.Errorf("unknown policy mode: %q (valid: strict, partial)", s)
	}
}

// InterpretMode controls how container formats are modeled in the SBOM.
type InterpretMode int

const (
	// InterpretPhysical models only artifacts that are directly present or extractable.
	InterpretPhysical InterpretMode = iota
	// InterpretInstallerSemantic additionally models installer-derived relationships.
	InterpretInstallerSemantic
)

// String returns the human-readable name of the interpretation mode.
func (m InterpretMode) String() string {
	switch m {
	case InterpretPhysical:
		return "physical"
	case InterpretInstallerSemantic:
		return "installer-semantic"
	default:
		return "unknown"
	}
}

// ParseInterpretMode converts a string to an InterpretMode.
// Valid values are "physical" and "installer-semantic" (case-insensitive).
// Returns an error for unrecognized values.
func ParseInterpretMode(s string) (InterpretMode, error) {
	switch strings.ToLower(s) {
	case "physical":
		return InterpretPhysical, nil
	case "installer-semantic":
		return InterpretInstallerSemantic, nil
	default:
		return InterpretPhysical, fmt.Errorf("unknown interpret mode: %q (valid: physical, installer-semantic)", s)
	}
}

// ReportMode controls which report output formats are produced.
type ReportMode int

const (
	// ReportHuman produces a human-readable Markdown report.
	ReportHuman ReportMode = iota
	// ReportMachine produces a structured JSON report.
	ReportMachine
	// ReportBoth produces both human-readable and machine-readable reports.
	ReportBoth
)

// String returns the human-readable name of the report mode.
func (r ReportMode) String() string {
	switch r {
	case ReportHuman:
		return "human"
	case ReportMachine:
		return "machine"
	case ReportBoth:
		return "both"
	default:
		return "unknown"
	}
}

// ParseReportMode converts a string to a ReportMode.
// Valid values are "human", "machine", and "both" (case-insensitive).
// Returns an error for unrecognized values.
func ParseReportMode(s string) (ReportMode, error) {
	switch strings.ToLower(s) {
	case "human":
		return ReportHuman, nil
	case "machine":
		return ReportMachine, nil
	case "both":
		return ReportBoth, nil
	default:
		return ReportHuman, fmt.Errorf("unknown report mode: %q (valid: human, machine, both)", s)
	}
}

// RootMetadata holds operator-supplied metadata for the top-level delivery
// component in the SBOM. These values describe the delivered software from
// the procurement/incoming-inspection perspective and always take precedence
// over auto-derived values.
type RootMetadata struct {
	Manufacturer string
	Name         string
	Version      string
	DeliveryDate string            // canonical format: YYYY-MM-DD
	Properties   map[string]string // extra root-level metadata from --root-property
}

// datePattern matches YYYY-MM-DD format.
var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Validate checks RootMetadata for well-formedness.
// It verifies that DeliveryDate, if set, matches YYYY-MM-DD format and
// represents a valid calendar date.
// Returns an error if validation fails.
func (rm *RootMetadata) Validate() error {
	if rm.DeliveryDate != "" {
		if !datePattern.MatchString(rm.DeliveryDate) {
			return fmt.Errorf("delivery date must be in YYYY-MM-DD format, got %q", rm.DeliveryDate)
		}
		// Validate it's a real date.
		if _, err := time.Parse("2006-01-02", rm.DeliveryDate); err != nil {
			return fmt.Errorf("invalid delivery date %q: %w", rm.DeliveryDate, err)
		}
	}
	return nil
}

// Limits defines the resource and safety limits for archive extraction.
// All limits are configurable and have tested defaults matching the design
// specification (DESIGN.md §6.1).
type Limits struct {
	MaxDepth     int           // maximum recursion depth (default: 6)
	MaxFiles     int           // maximum total extracted file count (default: 200,000)
	MaxTotalSize int64         // maximum total uncompressed bytes (default: 20 GiB)
	MaxEntrySize int64         // maximum single entry uncompressed bytes (default: 2 GiB)
	MaxRatio     int           // maximum compression ratio per entry (default: 150)
	Timeout      time.Duration // per-extraction timeout (default: 60s)
}

// DefaultLimits returns the default safety limits as specified in DESIGN.md §6.1.
// These values protect against zip bombs, resource exhaustion, and excessive
// recursion while being generous enough for legitimate vendor deliveries.
//
// The defaults are:
//   - MaxDepth: 6
//   - MaxFiles: 200,000
//   - MaxTotalSize: 20 GiB
//   - MaxEntrySize: 2 GiB
//   - MaxRatio: 150
//   - Timeout: 60s
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:     6,
		MaxFiles:     200000,
		MaxTotalSize: 20 * 1024 * 1024 * 1024, // 20 GiB
		MaxEntrySize: 2 * 1024 * 1024 * 1024,  // 2 GiB
		MaxRatio:     150,
		Timeout:      60 * time.Second,
	}
}

// Config is the central configuration for an sbom-sentry run.
// It is constructed from CLI flags and passed to all modules.
type Config struct {
	InputPath     string
	OutputDir     string
	WorkDir       string        // base directory for temporary extraction work
	SBOMFormat    string        // "cyclonedx-json"
	PolicyMode    PolicyMode    // Strict | Partial
	InterpretMode InterpretMode // Physical | InstallerSemantic
	ReportMode    ReportMode    // Human | Machine | Both
	Language      string        // "en" | "de"
	RootMetadata  RootMetadata
	Unsafe        bool
	Limits        Limits
}

// DefaultConfig returns a Config with sensible defaults.
// InputPath and OutputDir must still be set by the caller.
func DefaultConfig() Config {
	return Config{
		SBOMFormat:    "cyclonedx-json",
		PolicyMode:    PolicyStrict,
		InterpretMode: InterpretInstallerSemantic,
		ReportMode:    ReportHuman,
		Language:      "en",
		WorkDir:       os.TempDir(),
		Limits:        DefaultLimits(),
	}
}

// Validate checks the configuration for consistency and required fields.
// It verifies that the input file exists, the output directory is writable,
// the language is supported, and root metadata is well-formed.
// Returns a descriptive error if any check fails.
func (c *Config) Validate() error {
	if c.InputPath == "" {
		return fmt.Errorf("input path is required")
	}

	info, err := os.Stat(c.InputPath)
	if err != nil {
		return fmt.Errorf("input file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("input path must be a file, not a directory: %s", c.InputPath)
	}

	if c.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}

	outInfo, err := os.Stat(c.OutputDir)
	if err != nil {
		return fmt.Errorf("output directory: %w", err)
	}
	if !outInfo.IsDir() {
		return fmt.Errorf("output path must be a directory: %s", c.OutputDir)
	}

	if c.WorkDir == "" {
		return fmt.Errorf("work directory is required")
	}

	workInfo, err := os.Stat(c.WorkDir)
	if err != nil {
		return fmt.Errorf("work directory: %w", err)
	}
	if !workInfo.IsDir() {
		return fmt.Errorf("work path must be a directory: %s", c.WorkDir)
	}

	probeDir, err := os.MkdirTemp(c.WorkDir, "sbom-sentry-writecheck-*")
	if err != nil {
		return fmt.Errorf("work directory is not writable: %w", err)
	}
	if err := os.RemoveAll(probeDir); err != nil {
		return fmt.Errorf("cleanup work directory probe: %w", err)
	}

	switch c.Language {
	case "en", "de":
		// valid
	default:
		return fmt.Errorf("unsupported language: %q (valid: en, de)", c.Language)
	}

	if c.SBOMFormat != "cyclonedx-json" {
		return fmt.Errorf("unsupported SBOM format: %q (valid: cyclonedx-json)", c.SBOMFormat)
	}

	if err := c.RootMetadata.Validate(); err != nil {
		return fmt.Errorf("root metadata: %w", err)
	}

	if c.Limits.MaxDepth < 1 {
		return fmt.Errorf("max-depth must be at least 1, got %d", c.Limits.MaxDepth)
	}
	if c.Limits.MaxFiles < 1 {
		return fmt.Errorf("max-files must be at least 1, got %d", c.Limits.MaxFiles)
	}
	if c.Limits.MaxTotalSize < 1 {
		return fmt.Errorf("max-size must be at least 1, got %d", c.Limits.MaxTotalSize)
	}
	if c.Limits.MaxEntrySize < 1 {
		return fmt.Errorf("max-entry-size must be at least 1, got %d", c.Limits.MaxEntrySize)
	}
	if c.Limits.MaxRatio < 1 {
		return fmt.Errorf("max-ratio must be at least 1, got %d", c.Limits.MaxRatio)
	}
	if c.Limits.Timeout < 1*time.Second {
		return fmt.Errorf("timeout must be at least 1s, got %s", c.Limits.Timeout)
	}

	return nil
}
