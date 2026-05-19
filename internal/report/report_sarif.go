package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// SARIF 2.1.0 types — only the fields we populate.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool      `json:"tool"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
	Results   []sarifResult   `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	ShortDescription sarifMessage         `json:"shortDescription"`
	Properties       *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Severity string `json:"severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
	Hashes   map[string]string     `json:"hashes,omitempty"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

// GenerateSARIF writes a SARIF 2.1.0 JSON report to w.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - w: the writer to write the SARIF JSON to
//
// Returns an error if writing fails.
func GenerateSARIF(data ReportData, w io.Writer) error {
	// Build rules: one per unique vulnerability ID.
	ruleSet := make(map[string]string) // vulnID → severity
	if data.Vulnerabilities != nil && data.Vulnerabilities.MatchesByBOMRef != nil {
		for _, matches := range data.Vulnerabilities.MatchesByBOMRef {
			for _, m := range matches {
				if _, exists := ruleSet[m.VulnerabilityID]; !exists {
					ruleSet[m.VulnerabilityID] = m.Severity
				}
			}
		}
	}

	// Sort rules for deterministic output.
	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		sev := ruleSet[id]
		rules = append(rules, sarifRule{
			ID: id,
			ShortDescription: sarifMessage{
				Text: id,
			},
			Properties: &sarifRuleProperties{
				Severity: sev,
			},
		})
	}

	// Build artifacts: one for the input file.
	var artifacts []sarifArtifact
	if data.Input.Filename != "" {
		art := sarifArtifact{
			Location: sarifArtifactLocation{URI: data.Input.Filename},
		}
		if data.Input.SHA256 != "" {
			art.Hashes = map[string]string{"sha-256": data.Input.SHA256}
		}
		artifacts = append(artifacts, art)
	}

	// Build a BOMRef → delivery path lookup.
	bomRefDeliveryPath := make(map[string]string)
	if data.BOM != nil && data.BOM.Components != nil {
		for _, c := range *data.BOM.Components {
			if c.Properties == nil {
				continue
			}
			for _, p := range *c.Properties {
				if p.Name == "extract-sbom:delivery-path" && p.Value != "" {
					bomRefDeliveryPath[c.BOMRef] = p.Value
					break
				}
			}
		}
	}

	// Build results.
	var results []sarifResult
	if data.Vulnerabilities != nil && data.Vulnerabilities.MatchesByBOMRef != nil {
		// Sort BOMRefs for deterministic output.
		bomRefs := make([]string, 0, len(data.Vulnerabilities.MatchesByBOMRef))
		for ref := range data.Vulnerabilities.MatchesByBOMRef {
			bomRefs = append(bomRefs, ref)
		}
		sort.Strings(bomRefs)

		for _, bomRef := range bomRefs {
			matches := data.Vulnerabilities.MatchesByBOMRef[bomRef]
			// Sort matches by vulnerability ID.
			sort.Slice(matches, func(i, j int) bool {
				return matches[i].VulnerabilityID < matches[j].VulnerabilityID
			})
			deliveryPath := bomRefDeliveryPath[bomRef]
			if deliveryPath == "" {
				deliveryPath = data.Input.Filename
			}

			for _, m := range matches {
				text := m.Description
				if text == "" {
					text = m.VulnerabilityID + " (" + m.Severity + ")"
				}

				result := sarifResult{
					RuleID:  m.VulnerabilityID,
					Level:   sarifLevel(m.Severity),
					Message: sarifMessage{Text: text},
					Locations: []sarifLocation{
						{
							PhysicalLocation: sarifPhysicalLocation{
								ArtifactLocation: sarifArtifactLocation{
									URI: deliveryPath,
								},
							},
						},
					},
				}
				results = append(results, result)
			}
		}
	}

	version := ""
	if data.Generator.Version != "" {
		version = data.Generator.Version
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "extract-sbom",
						Version: version,
						Rules:   rules,
					},
				},
				Artifacts: artifacts,
				Results:   results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifLevel converts a vulnerability severity to a SARIF level.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
