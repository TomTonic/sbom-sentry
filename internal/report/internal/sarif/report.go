// Package sarif implements the SARIF 2.1.0 audit report renderer.
package sarif

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// InputSummary aliases the shared report input summary contract.
type InputSummary = model.InputSummary

// ReportData aliases the shared report snapshot contract.
type ReportData = model.ReportData

type logDoc struct {
	Schema  string   `json:"$schema"`
	Version string   `json:"version"`
	Runs    []runDoc `json:"runs"`
}

type runDoc struct {
	Tool        toolDoc         `json:"tool"`
	Invocations []invocationDoc `json:"invocations,omitempty"`
	Artifacts   []artifact      `json:"artifacts,omitempty"`
	Results     []resultDoc     `json:"results,omitempty"`
	Properties  *runProperties  `json:"properties,omitempty"`
}

type toolDoc struct {
	Driver driverDoc `json:"driver"`
}

type driverDoc struct {
	Name    string    `json:"name"`
	Version string    `json:"version,omitempty"`
	Rules   []ruleDoc `json:"rules,omitempty"`
}

type ruleDoc struct {
	ID               string          `json:"id"`
	ShortDescription messageDoc      `json:"shortDescription"`
	Properties       *ruleProperties `json:"properties,omitempty"`
}

type ruleProperties struct {
	Severity string `json:"severity,omitempty"`
}

type messageDoc struct {
	Text string `json:"text"`
}

type invocationDoc struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []notification `json:"toolExecutionNotifications,omitempty"`
}

type notification struct {
	Level   string     `json:"level,omitempty"`
	Message messageDoc `json:"message"`
}

type runProperties struct {
	VulnerabilityEnrichmentState     string `json:"vulnerabilityEnrichmentState"`
	VulnerabilityEnrichmentRequested bool   `json:"vulnerabilityEnrichmentRequested"`
}

type artifact struct {
	Location artifactLocation  `json:"location"`
	Hashes   map[string]string `json:"hashes,omitempty"`
}

type artifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

type resultDoc struct {
	RuleID    string        `json:"ruleId"`
	Level     string        `json:"level"`
	Message   messageDoc    `json:"message"`
	Locations []locationDoc `json:"locations,omitempty"`
}

type locationDoc struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
}

// Generate writes a SARIF 2.1.0 JSON report to w.
func Generate(data ReportData, w io.Writer) error {
	rules := buildRules(data.Vulnerabilities)
	artifacts := buildArtifacts(data.Input)
	results := buildResults(data)
	inv, runProps := buildEnrichment(data.Vulnerabilities)

	version := ""
	if data.Generator.Version != "" {
		version = data.Generator.Version
	}

	log := logDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []runDoc{{
			Tool:        toolDoc{Driver: driverDoc{Name: "extract-sbom", Version: version, Rules: rules}},
			Invocations: []invocationDoc{inv},
			Artifacts:   artifacts,
			Results:     results,
			Properties:  &runProps,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildRules(v *vulnscan.Result) []ruleDoc {
	ruleSet := make(map[string]string)
	if v != nil && v.MatchesByBOMRef != nil {
		for _, matches := range v.MatchesByBOMRef {
			for i := range matches {
				if _, exists := ruleSet[matches[i].VulnerabilityID]; !exists {
					ruleSet[matches[i].VulnerabilityID] = matches[i].Severity
				}
			}
		}
	}

	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]ruleDoc, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, ruleDoc{
			ID:               id,
			ShortDescription: messageDoc{Text: id},
			Properties:       &ruleProperties{Severity: ruleSet[id]},
		})
	}
	return rules
}

func buildArtifacts(input InputSummary) []artifact {
	if input.Filename == "" {
		return nil
	}
	art := artifact{Location: artifactLocation{URI: input.Filename}}
	if input.SHA256 != "" {
		art.Hashes = map[string]string{"sha-256": input.SHA256}
	}
	return []artifact{art}
}

func buildResults(data ReportData) []resultDoc {
	if data.Vulnerabilities == nil || data.Vulnerabilities.MatchesByBOMRef == nil {
		return nil
	}

	bomRefDeliveryPath := make(map[string]string)
	if data.BOM != nil && data.BOM.Components != nil {
		comps := *data.BOM.Components
		for i := range comps {
			if comps[i].Properties == nil {
				continue
			}
			for _, p := range *comps[i].Properties {
				if p.Name == "extract-sbom:delivery-path" && p.Value != "" {
					bomRefDeliveryPath[comps[i].BOMRef] = p.Value
					break
				}
			}
		}
	}

	bomRefs := make([]string, 0, len(data.Vulnerabilities.MatchesByBOMRef))
	for ref := range data.Vulnerabilities.MatchesByBOMRef {
		bomRefs = append(bomRefs, ref)
	}
	sort.Strings(bomRefs)

	var results []resultDoc
	for _, bomRef := range bomRefs {
		matches := data.Vulnerabilities.MatchesByBOMRef[bomRef]
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].VulnerabilityID < matches[j].VulnerabilityID
		})
		deliveryPath := bomRefDeliveryPath[bomRef]
		if deliveryPath == "" {
			deliveryPath = data.Input.Filename
		}

		for i := range matches {
			text := matches[i].Description
			if text == "" {
				text = matches[i].VulnerabilityID + " (" + matches[i].Severity + ")"
			}
			results = append(results, resultDoc{
				RuleID:  matches[i].VulnerabilityID,
				Level:   levelForSeverity(matches[i].Severity),
				Message: messageDoc{Text: text},
				Locations: []locationDoc{{
					PhysicalLocation: physicalLocation{ArtifactLocation: artifactLocation{URI: deliveryPath}},
				}},
			})
		}
	}
	return results
}

func buildEnrichment(v *vulnscan.Result) (invocationDoc, runProperties) {
	state, requested := normalizedVulnEnrichmentState(v)

	var level string
	var message string
	executionSuccessful := true
	switch state {
	case vulnscan.StateCompleted:
		level = "note"
		message = "Vulnerability enrichment completed; the results are the complete set of matches found."
	case vulnscan.StateCompletedWithErrors:
		level = "warning"
		message = "Vulnerability enrichment completed with errors; the result set may be incomplete."
	case vulnscan.StateUnavailable:
		level = "error"
		message = "Vulnerability enrichment was requested but Grype was unavailable; an empty result set does NOT indicate the absence of vulnerabilities."
		executionSuccessful = false
	default:
		level = "note"
		message = "Vulnerability enrichment was not requested; this report intentionally contains no vulnerability findings."
	}

	inv := invocationDoc{
		ExecutionSuccessful: executionSuccessful,
		ToolExecutionNotifications: []notification{{
			Level:   level,
			Message: messageDoc{Text: message},
		}},
	}
	props := runProperties{
		VulnerabilityEnrichmentState:     string(state),
		VulnerabilityEnrichmentRequested: requested,
	}
	return inv, props
}

func levelForSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func normalizedVulnEnrichmentState(v *vulnscan.Result) (vulnscan.State, bool) {
	state := vulnscan.StateNotRequested
	requested := false
	if v != nil {
		requested = v.Requested
		if v.State != "" {
			state = v.State
		}
	}
	return state, requested
}
