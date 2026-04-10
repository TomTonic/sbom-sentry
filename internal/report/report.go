package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"sbom-sentry/internal/config"
	"sbom-sentry/internal/extract"
	"sbom-sentry/internal/policy"
	"sbom-sentry/internal/scan"
)

// InputSummary captures deterministic identifiers of the inspected input file.
type InputSummary struct {
	FileName string `json:"fileName"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
}

// SandboxSummary captures sandbox selection and fallback context for the run.
type SandboxSummary struct {
	Name   string `json:"name"`
	Unsafe bool   `json:"unsafe"`
}

// ReportData is the immutable processing snapshot used to render reports.
type ReportData struct {
	Input           InputSummary            `json:"input"`
	Config          config.Config           `json:"config"`
	Tree            *extract.ExtractionNode `json:"tree"`
	Scans           []scan.ScanResult       `json:"scans"`
	PolicyDecisions []policy.Decision       `json:"policyDecisions"`
	SandboxInfo     SandboxSummary          `json:"sandbox"`
	StartTime       time.Time               `json:"startTime"`
	EndTime         time.Time               `json:"endTime"`
}

// GenerateHuman writes a deterministic markdown audit report for human readers.
func GenerateHuman(data ReportData, lang string, w io.Writer) error {
	if lang != "en" && lang != "de" {
		lang = "en"
	}

	heading := "# sbom-sentry Audit Report"
	if lang == "de" {
		heading = "# sbom-sentry Audit-Bericht"
	}

	if _, err := fmt.Fprintln(w, heading); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}

	lines := []string{
		"## Input",
		fmt.Sprintf("- File: %s", data.Input.FileName),
		fmt.Sprintf("- Size: %d bytes", data.Input.Size),
		fmt.Sprintf("- SHA-256: %s", data.Input.SHA256),
		fmt.Sprintf("- SHA-512: %s", data.Input.SHA512),
		"",
		"## Configuration",
		fmt.Sprintf("- Policy: %s", data.Config.PolicyMode),
		fmt.Sprintf("- Mode: %s", data.Config.InterpretMode),
		fmt.Sprintf("- Report: %s", data.Config.ReportMode),
		fmt.Sprintf("- Language: %s", data.Config.Language),
		fmt.Sprintf("- Unsafe: %t", data.Config.Unsafe),
		fmt.Sprintf("- Sandbox: %s", data.SandboxInfo.Name),
		"",
		"## Root Metadata",
		fmt.Sprintf("- Manufacturer: %s", valueOrNA(data.Config.RootMetadata.Manufacturer)),
		fmt.Sprintf("- Name: %s", valueOrNA(data.Config.RootMetadata.Name)),
		fmt.Sprintf("- Version: %s", valueOrNA(data.Config.RootMetadata.Version)),
		fmt.Sprintf("- Delivery date: %s", valueOrNA(data.Config.RootMetadata.DeliveryDate)),
		"",
		"## Extraction Log",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}

	if data.Tree != nil {
		if err := writeTreeNode(w, data.Tree, 0); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(w, "- no extraction tree available"); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "## Policy Decisions"); err != nil {
		return err
	}
	if len(data.PolicyDecisions) == 0 {
		if _, err := fmt.Fprintln(w, "- none"); err != nil {
			return err
		}
	} else {
		for _, d := range data.PolicyDecisions {
			if _, err := fmt.Fprintf(w, "- [%s] %s at %s (%s)\n", d.Action, d.Trigger, d.NodePath, d.Detail); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "## Scan Summary"); err != nil {
		return err
	}
	scans := append([]scan.ScanResult(nil), data.Scans...)
	sort.Slice(scans, func(i, j int) bool { return scans[i].NodePath < scans[j].NodePath })
	for _, s := range scans {
		status := "ok"
		if s.Error != nil {
			status = s.Error.Error()
		}
		if _, err := fmt.Fprintf(w, "- %s: %s\n", s.NodePath, status); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "## Residual Risk Statement"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "- sbom-sentry performs static archive inspection and SBOM generation; it is not a malware scanner."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "- Components without recognizable metadata may remain unidentified and should be reviewed manually."); err != nil {
		return err
	}

	return nil
}

// GenerateMachine writes a deterministic JSON report for automation consumers.
func GenerateMachine(data ReportData, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func writeTreeNode(w io.Writer, node *extract.ExtractionNode, depth int) error {
	indent := strings.Repeat("  ", depth)
	if _, err := fmt.Fprintf(w, "%s- %s [%s] (%s)\n", indent, node.Path, node.Status, node.Format.Format); err != nil {
		return err
	}
	if node.StatusDetail != "" {
		if _, err := fmt.Fprintf(w, "%s  detail: %s\n", indent, node.StatusDetail); err != nil {
			return err
		}
	}
	for _, child := range node.Children {
		if err := writeTreeNode(w, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func valueOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "n/a"
	}
	return v
}
