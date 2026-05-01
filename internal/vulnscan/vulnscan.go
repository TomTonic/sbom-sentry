// Package vulnscan performs optional vulnerability enrichment by invoking
// Grype on the generated SBOM and correlating matches to component BOM refs.
package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// State describes the runtime outcome of optional vulnerability enrichment.
type State string

const (
	// StateNotRequested means --grype was not enabled.
	StateNotRequested State = "not-requested"
	// StateCompleted means Grype executed successfully and results were parsed.
	StateCompleted State = "completed"
	// StateCompletedWithErrors means Grype succeeded but correlation had issues.
	StateCompletedWithErrors State = "completed-with-errors"
	// StateUnavailable means Grype could not be executed or parsed.
	StateUnavailable State = "unavailable"
)

// CoverageState captures per-component vulnerability coverage in report output.
type CoverageState string

const (
	// CoverageFound means at least one vulnerability match exists.
	CoverageFound CoverageState = "found"
	// CoverageNone means evaluated with no matches.
	CoverageNone CoverageState = "none"
	// CoverageNotAssessable means no reliable vulnerability lookup could be done.
	CoverageNotAssessable CoverageState = "not-assessable"
)

// Issue captures non-fatal enrichment diagnostics for report transparency.
type Issue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VMatch is one normalized Grype match entry keyed by SBOM bom-ref.
type VMatch struct {
	VulnerabilityID string   `json:"vulnerabilityId"`
	Severity        string   `json:"severity"`
	Namespace       string   `json:"namespace,omitempty"`
	DataSource      string   `json:"dataSource,omitempty"`
	URLs            []string `json:"urls,omitempty"`
	FixState        string   `json:"fixState,omitempty"`
	FixVersions     []string `json:"fixVersions,omitempty"`
	Matcher         string   `json:"matcher,omitempty"`
	MatchType       string   `json:"matchType,omitempty"`
	ArtifactName    string   `json:"artifactName,omitempty"`
	ArtifactVersion string   `json:"artifactVersion,omitempty"`
	ArtifactPURL    string   `json:"artifactPurl,omitempty"`
}

// Result contains all optional vulnerability enrichment outputs.
type Result struct {
	State            State                    `json:"state"`
	Requested        bool                     `json:"requested"`
	GrypeVersion     string                   `json:"grypeVersion,omitempty"`
	DBSchemaVersion  string                   `json:"dbSchemaVersion,omitempty"`
	DBBuilt          string                   `json:"dbBuilt,omitempty"`
	DBUpdated        string                   `json:"dbUpdated,omitempty"`
	MatchesByBOMRef  map[string][]VMatch      `json:"matchesByBomRef,omitempty"`
	CoverageByBOMRef map[string]CoverageState `json:"coverageByBomRef,omitempty"`
	Errors           []Issue                  `json:"errors,omitempty"`
}

// Run executes optional Grype enrichment on the written SBOM path.
// It never mutates the SBOM and is designed to fail soft.
func Run(ctx context.Context, sbomPath string, enabled bool, bom *cdx.BOM) *Result {
	result := &Result{
		Requested:        enabled,
		MatchesByBOMRef:  map[string][]VMatch{},
		CoverageByBOMRef: map[string]CoverageState{},
	}

	if !enabled {
		result.State = StateNotRequested
		return result
	}
	if strings.TrimSpace(sbomPath) == "" {
		result.State = StateUnavailable
		result.Errors = append(result.Errors, Issue{Code: "sbom-missing", Message: "SBOM path is empty; vulnerability enrichment cannot run"})
		applyUnavailableCoverage(result, bom)
		return result
	}

	cmd := exec.CommandContext(ctx, "grype", "sbom:"+sbomPath, "-o", "json") //nolint:gosec // path is controlled local output file
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		result.State = StateUnavailable
		if errors.Is(err, exec.ErrNotFound) {
			result.Errors = append(result.Errors, Issue{Code: "grype-not-found", Message: "grype binary not found on PATH"})
		} else {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			result.Errors = append(result.Errors, Issue{Code: "grype-exec", Message: msg})
		}
		applyUnavailableCoverage(result, bom)
		return result
	}

	var payload grypeJSON
	if err := json.Unmarshal(stdout, &payload); err != nil {
		result.State = StateUnavailable
		result.Errors = append(result.Errors, Issue{Code: "grype-parse", Message: fmt.Sprintf("parse grype JSON: %v", err)})
		applyUnavailableCoverage(result, bom)
		return result
	}

	result.GrypeVersion = payload.Descriptor.Version
	result.DBSchemaVersion = payload.Descriptor.DB.Status.SchemaVersion
	result.DBBuilt = payload.Descriptor.DB.Status.Built
	result.DBUpdated = payload.Descriptor.Timestamp

	knownRefs := map[string]struct{}{}
	for _, ref := range collectBOMRefs(bom) {
		knownRefs[ref] = struct{}{}
	}

	for i := range payload.Matches {
		m := payload.Matches[i]
		ref := strings.TrimSpace(m.Artifact.ID)
		if ref == "" {
			result.Errors = append(result.Errors, Issue{Code: "match-missing-artifact-id", Message: "grype match missing artifact.id"})
			continue
		}

		if len(knownRefs) > 0 {
			if _, ok := knownRefs[ref]; !ok {
				result.Errors = append(result.Errors, Issue{Code: "unknown-bom-ref", Message: fmt.Sprintf("grype match references unknown bom-ref %q", ref)})
			}
		}

		matchType := ""
		matcher := ""
		if len(m.MatchDetails) > 0 {
			matchType = m.MatchDetails[0].Type
			matcher = m.MatchDetails[0].Matcher
		}

		vm := VMatch{
			VulnerabilityID: m.Vulnerability.ID,
			Severity:        normalizeSeverity(m.Vulnerability.Severity),
			Namespace:       m.Vulnerability.Namespace,
			DataSource:      m.Vulnerability.DataSource,
			URLs:            uniqueSortedStrings(m.Vulnerability.URLs),
			FixState:        m.Vulnerability.Fix.State,
			FixVersions:     uniqueSortedStrings(m.Vulnerability.Fix.Versions),
			Matcher:         matcher,
			MatchType:       matchType,
			ArtifactName:    m.Artifact.Name,
			ArtifactVersion: m.Artifact.Version,
			ArtifactPURL:    m.Artifact.PURL,
		}
		result.MatchesByBOMRef[ref] = append(result.MatchesByBOMRef[ref], vm)
	}

	for ref := range result.MatchesByBOMRef {
		sort.Slice(result.MatchesByBOMRef[ref], func(i, j int) bool {
			a := result.MatchesByBOMRef[ref][i]
			b := result.MatchesByBOMRef[ref][j]
			if severityRank(a.Severity) != severityRank(b.Severity) {
				return severityRank(a.Severity) < severityRank(b.Severity)
			}
			if a.VulnerabilityID != b.VulnerabilityID {
				return a.VulnerabilityID < b.VulnerabilityID
			}
			return a.ArtifactName < b.ArtifactName
		})
	}

	applyCoverage(result, bom)
	if len(result.Errors) > 0 {
		result.State = StateCompletedWithErrors
	} else {
		result.State = StateCompleted
	}
	return result
}

// applyCoverage sets CoverageByBOMRef for each bom-ref based on whether matches
// were found or the component is assessable via PURL/CPE.
func applyCoverage(result *Result, bom *cdx.BOM) {
	for _, ref := range collectBOMRefs(bom) {
		matches := result.MatchesByBOMRef[ref]
		if len(matches) > 0 {
			result.CoverageByBOMRef[ref] = CoverageFound
			continue
		}
		if !isAssessableComponent(findBOMComponentByRef(bom, ref)) {
			result.CoverageByBOMRef[ref] = CoverageNotAssessable
			continue
		}
		result.CoverageByBOMRef[ref] = CoverageNone
	}
}

// applyUnavailableCoverage marks every bom-ref CoverageNotAssessable when grype
// could not be executed successfully.
func applyUnavailableCoverage(result *Result, bom *cdx.BOM) {
	for _, ref := range collectBOMRefs(bom) {
		result.CoverageByBOMRef[ref] = CoverageNotAssessable
	}
}

// collectBOMRefs returns a deduplicated, sorted slice of non-empty bom-ref
// values from the BOM component list.
func collectBOMRefs(bom *cdx.BOM) []string {
	if bom == nil || bom.Components == nil {
		return nil
	}
	refs := make([]string, 0, len(*bom.Components))
	for i := range *bom.Components {
		ref := strings.TrimSpace((*bom.Components)[i].BOMRef)
		if ref == "" {
			continue
		}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return uniqueSortedStrings(refs)
}

// findBOMComponentByRef returns the first BOM component whose BOMRef equals ref,
// or nil when not found.
func findBOMComponentByRef(bom *cdx.BOM, ref string) *cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	for i := range *bom.Components {
		if (*bom.Components)[i].BOMRef == ref {
			return &(*bom.Components)[i]
		}
	}
	return nil
}

// isAssessableComponent reports whether comp has a non-empty PURL or CPE that
// grype can use to look up vulnerabilities.
func isAssessableComponent(comp *cdx.Component) bool {
	if comp == nil {
		return false
	}
	return strings.TrimSpace(comp.PackageURL) != "" || strings.TrimSpace(comp.CPE) != ""
}

// normalizeSeverity lowercases and trims raw, returning "unknown" for empty input.
func normalizeSeverity(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return s
	default:
		if s == "" {
			return "unknown"
		}
		return s
	}
}

// severityRank returns a numeric sort key for severity s (0=critical … 5=unknown).
func severityRank(s string) int {
	switch normalizeSeverity(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "negligible":
		return 4
	default:
		return 5
	}
}

// uniqueSortedStrings returns a deduplicated, sorted copy of values.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

type grypeJSON struct {
	Descriptor struct {
		Version   string `json:"version"`
		Timestamp string `json:"timestamp"`
		DB        struct {
			Status struct {
				SchemaVersion string `json:"schemaVersion"`
				Built         string `json:"built"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Artifact struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"artifact"`
	Vulnerability struct {
		ID         string   `json:"id"`
		Severity   string   `json:"severity"`
		Namespace  string   `json:"namespace"`
		DataSource string   `json:"dataSource"`
		URLs       []string `json:"urls"`
		Fix        struct {
			State    string   `json:"state"`
			Versions []string `json:"versions"`
		} `json:"fix"`
	} `json:"vulnerability"`
	MatchDetails []struct {
		Type    string `json:"type"`
		Matcher string `json:"matcher"`
	} `json:"matchDetails"`
}
