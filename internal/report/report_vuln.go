package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// vulnerabilitySummaryRow holds one grype-inspired vulnerability table row.
type vulnerabilitySummaryRow struct {
	PackageAnchorID string
	PackageKey      string
	Name            string
	Installed       string
	FixedIn         string
	VulnerabilityID string
	Severity        string
	CVSSScore       *float64
	CVSSVersion     string
	CVSSVector      string
	Description     string
	EPSS            *float64
	EPSSPercentile  *float64
	Risk            *float64
	KEV             bool
}

// collectVulnStats returns the total match count, number of unique
// vulnerability IDs, and number of affected packages (non-empty bom-ref
// buckets) from a Grype result. All counts are zero when v is nil.
func collectVulnStats(v *vulnscan.Result) (matches, unique, affected int) {
	if v == nil {
		return
	}
	uniqueIDs := map[string]struct{}{}
	for _, vmatches := range v.MatchesByBOMRef {
		if len(vmatches) > 0 {
			affected++
		}
		for i := range vmatches {
			m := vmatches[i]
			matches++
			uniqueIDs[m.VulnerabilityID] = struct{}{}
		}
	}
	unique = len(uniqueIDs)
	return
}

// writeVulnerabilitySummary renders the vulnerability enrichment section to w,
// including state, grype version, and a per-severity summary table.
func writeVulnerabilitySummary(w io.Writer, data ReportData, occurrences []componentOccurrence, t translations) {
	if data.Vulnerabilities == nil || !vulnerabilityRequested(data.Vulnerabilities) {
		fmt.Fprintf(w, "- %s\n", t.vulnEnrichmentNotRequested)
		return
	}

	v := data.Vulnerabilities
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnEnrichmentStateTemplate, v.State))
	if len(v.Errors) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnEnrichmentIssuesTemplate, len(v.Errors)))
	}

	rows := buildVulnerabilitySummaryRows(v, occurrences)
	uniqueVulns := map[string]struct{}{}
	affectedPackages := map[string]struct{}{}
	for i := range rows {
		uniqueVulns[rows[i].VulnerabilityID] = struct{}{}
		affectedPackages[rows[i].PackageKey] = struct{}{}
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnFindingsTemplate, len(rows), len(uniqueVulns), len(affectedPackages)))
	if len(rows) == 0 {
		fmt.Fprintf(w, "- %s\n", t.vulnNoMatchedFindings)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.vulnTableName,
		t.vulnTableInstalled,
		t.vulnTableFixedIn,
		t.vulnTableVulnerability,
		t.vulnTableSeverity,
		t.vulnTableEPSS,
		t.vulnTableRisk,
		t.vulnTableKEV,
	)
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for i := range rows {
		name := escapeMarkdownCell(rows[i].Name)
		if rows[i].PackageAnchorID != "" {
			name = fmt.Sprintf("[%s](#%s)", name, rows[i].PackageAnchorID)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			name,
			emptyDash(rows[i].Installed),
			emptyDash(rows[i].FixedIn),
			rows[i].VulnerabilityID,
			formatSeverity(rows[i].Severity, rows[i].CVSSScore),
			formatEPSS(rows[i].EPSS, rows[i].EPSSPercentile),
			formatRisk(rows[i].Risk),
			formatKEV(rows[i].KEV, t),
		)
	}
}

// buildVulnerabilitySummaryRows builds the sorted vulnerability rows from the
// grype result, correlating matches to component occurrences by bom-ref.
func buildVulnerabilitySummaryRows(v *vulnscan.Result, occurrences []componentOccurrence) []vulnerabilitySummaryRow {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return nil
	}
	byID := map[string]componentOccurrence{}
	for i := range occurrences {
		byID[occurrences[i].ObjectID] = occurrences[i]
	}
	packageGroups := buildPackageOccurrenceGroups(occurrences)
	anchorByOccurrence := map[string]string{}
	for i := range packageGroups {
		for j := range packageGroups[i].Occurrences {
			anchorByOccurrence[packageGroups[i].Occurrences[j].ObjectID] = packageGroups[i].AnchorID
		}
	}

	rows := make([]vulnerabilitySummaryRow, 0)
	seen := map[string]struct{}{}
	for compID, matches := range v.MatchesByBOMRef {
		occ := byID[compID]
		packageName := strings.TrimSpace(occ.PackageName)
		packageVersion := strings.TrimSpace(occ.Version)
		packageAnchorID := anchorByOccurrence[compID]
		for i := range matches {
			name := packageName
			if name == "" {
				name = strings.TrimSpace(matches[i].ArtifactName)
			}
			if packageName == "" {
				packageName = name
			}
			installed := packageVersion
			if installed == "" {
				installed = strings.TrimSpace(matches[i].ArtifactVersion)
			}
			if packageVersion == "" {
				packageVersion = installed
			}
			packageKey := strings.Join([]string{packageName, packageVersion}, "|")
			key := strings.Join([]string{
				packageKey,
				name,
				installed,
				strings.TrimSpace(matches[i].VulnerabilityID),
				normalizeSeverity(matches[i].Severity),
				strings.Join(matches[i].FixVersions, ", "),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			rows = append(rows, vulnerabilitySummaryRow{
				PackageAnchorID: packageAnchorID,
				PackageKey:      packageKey,
				Name:            name,
				Installed:       installed,
				FixedIn:         strings.Join(matches[i].FixVersions, ", "),
				VulnerabilityID: matches[i].VulnerabilityID,
				Severity:        normalizeSeverity(matches[i].Severity),
				CVSSScore:       matches[i].CVSSScore,
				CVSSVersion:     matches[i].CVSSVersion,
				CVSSVector:      matches[i].CVSSVector,
				Description:     matches[i].Description,
				EPSS:            matches[i].EPSS,
				EPSSPercentile:  matches[i].EPSSPercentile,
				Risk:            matches[i].Risk,
				KEV:             matches[i].KEV != nil && *matches[i].KEV,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		leftRisk := 0.0
		rightRisk := 0.0
		if rows[i].Risk != nil {
			leftRisk = *rows[i].Risk
		}
		if rows[j].Risk != nil {
			rightRisk = *rows[j].Risk
		}
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		if rows[i].KEV != rows[j].KEV {
			return rows[i].KEV
		}
		leftEPSSPct := 0.0
		rightEPSSPct := 0.0
		if rows[i].EPSSPercentile != nil {
			leftEPSSPct = *rows[i].EPSSPercentile
		}
		if rows[j].EPSSPercentile != nil {
			rightEPSSPct = *rows[j].EPSSPercentile
		}
		if leftEPSSPct != rightEPSSPct {
			return leftEPSSPct > rightEPSSPct
		}
		leftEPSS := 0.0
		rightEPSS := 0.0
		if rows[i].EPSS != nil {
			leftEPSS = *rows[i].EPSS
		}
		if rows[j].EPSS != nil {
			rightEPSS = *rows[j].EPSS
		}
		if leftEPSS != rightEPSS {
			return leftEPSS > rightEPSS
		}
		if severityRank(rows[i].Severity) != severityRank(rows[j].Severity) {
			return severityRank(rows[i].Severity) < severityRank(rows[j].Severity)
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		if rows[i].VulnerabilityID != rows[j].VulnerabilityID {
			return rows[i].VulnerabilityID < rows[j].VulnerabilityID
		}
		return rows[i].PackageKey < rows[j].PackageKey
	})
	return rows
}

// resolvePackageVulnerabilityBlocks decides whether vulnerability details
// should be rendered once at package level (all occurrence blocks identical)
// or separately under each occurrence (at least one block differs).
func resolvePackageVulnerabilityBlocks(group packageOccurrenceGroup, v *vulnscan.Result, t translations) ([]string, map[string][]string) {
	if len(group.Occurrences) == 0 {
		return nil, nil
	}

	occurrenceBlocks := make(map[string][]string, len(group.Occurrences))
	for i := range group.Occurrences {
		occ := group.Occurrences[i]
		occurrenceBlocks[occ.ObjectID] = occurrenceVulnerabilityLines(occ, v, t)
	}

	first := occurrenceBlocks[group.Occurrences[0].ObjectID]
	if len(group.Occurrences) == 1 {
		return first, nil
	}

	reference := strings.Join(first, "\n")
	for i := 1; i < len(group.Occurrences); i++ {
		candidate := occurrenceBlocks[group.Occurrences[i].ObjectID]
		if strings.Join(candidate, "\n") != reference {
			return nil, occurrenceBlocks
		}
	}

	return first, nil
}

func occurrenceVulnerabilityLines(occ componentOccurrence, v *vulnscan.Result, t translations) []string {
	if v == nil || v.State == vulnscan.StateNotRequested {
		return nil
	}

	matches := v.MatchesByBOMRef[occ.ObjectID]
	if len(matches) > 0 {
		lines := make([]string, 0, 8)
		lines = append(lines, fmt.Sprintf("- %s", fmt.Sprintf(t.vulnStatusFoundTemplate, len(matches))))
		for i := range matches {
			m := matches[i]
			line := fmt.Sprintf("  - `%s` (%s)", m.VulnerabilityID, strings.ToUpper(normalizeSeverity(m.Severity)))
			if m.ArtifactType != "" {
				line += fmt.Sprintf(" type=`%s`", m.ArtifactType)
			}
			if m.Risk != nil {
				line += fmt.Sprintf(" risk=`%s`", formatNumber(*m.Risk))
			}
			line += fmt.Sprintf(" kev=`%s`", formatKEV(m.KEV != nil && *m.KEV, t))
			if m.Namespace != "" {
				line += fmt.Sprintf(" namespace=`%s`", m.Namespace)
			}
			if m.MatchType != "" {
				line += fmt.Sprintf(" match=`%s`", m.MatchType)
			}
			if m.Matcher != "" {
				line += fmt.Sprintf(" matcher=`%s`", m.Matcher)
			}
			lines = append(lines, line)
			if m.DataSource != "" {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailSourceTemplate, formatVulnerabilityReference(m.DataSource))))
			}
			if m.FixState != "" || len(m.FixVersions) > 0 {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailFixTemplate, emptyDash(m.FixState), strings.Join(m.FixVersions, ", "))))
			}
			if m.CVSSVector != "" || m.CVSSVersion != "" || m.CVSSScore != nil {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailCVSSTemplate, emptyDash(m.CVSSVersion), formatRisk(m.CVSSScore), emptyDash(m.CVSSVector))))
			} else {
				lines = append(lines, fmt.Sprintf("    - %s", t.vulnDetailCVSSNone))
			}
			if strings.TrimSpace(m.Description) != "" {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailDescriptionTemplate, strings.TrimSpace(m.Description))))
			} else {
				lines = append(lines, fmt.Sprintf("    - %s", t.vulnDetailDescriptionNone))
			}
			if m.EPSS != nil {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailEPSSTemplate, formatEPSS(m.EPSS, m.EPSSPercentile))))
			}
			for _, u := range m.URLs {
				lines = append(lines, fmt.Sprintf("    - %s", fmt.Sprintf(t.vulnDetailReferenceTemplate, formatVulnerabilityReference(u))))
			}
		}
		return lines
	}

	if v.State == vulnscan.StateUnavailable || v.State == vulnscan.StateCompletedWithErrors {
		return []string{fmt.Sprintf("- %s", t.vulnStatusNotAssessableUnavailable)}
	}
	if occ.PURL == "" && occ.CPE == "" {
		return []string{fmt.Sprintf("- %s", t.vulnStatusNotAssessableNoID)}
	}
	return []string{fmt.Sprintf("- %s", t.vulnStatusNone)}
}

// writeOccurrenceVulnerabilityBlock renders the per-component vulnerability
// detail block within the component occurrence index section.
func writeOccurrenceVulnerabilityBlock(w io.Writer, occ componentOccurrence, v *vulnscan.Result, t translations) {
	for _, line := range occurrenceVulnerabilityLines(occ, v, t) {
		fmt.Fprintln(w, line)
	}
}
