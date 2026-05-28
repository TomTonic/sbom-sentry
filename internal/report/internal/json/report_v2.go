package json

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

const (
	reportV2SchemaName    = "extract-sbom-report"
	reportV2SchemaVersion = "2.0.0"
)

// GenerateV2 writes the canonical JSON report envelope for schema 2.0.0.
//
// The serializer emits a deterministic top-level structure and delegates
// entity/projection/integrity construction to dedicated builders.
func GenerateV2(data ReportData, w io.Writer) error {
	report := BuildV2Report(data)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// BuildV2Report assembles the canonical JSON v2 report model in memory.
//
// This allows other renderers to consume one normalized data source without
// reparsing serialized JSON.
func BuildV2Report(data ReportData) ReportV2 {
	return buildJSONReportV2Skeleton(data, time.Now().UTC())
}

// buildJSONReportV2Skeleton assembles the complete report payload.
//
// It snapshots raw orchestrator output and enriches it with normalized entities,
// renderer-oriented projections, and integrity diagnostics.
func buildJSONReportV2Skeleton(data ReportData, generatedAt time.Time) ReportV2 {
	rawScans := make([]rawScanV2, len(data.Scans))
	for i := range data.Scans {
		rawScans[i] = toRawScanV2(data.Scans[i])
	}

	entities, index := buildEntitiesV2(data)
	projections := buildProjectionsV2(data, entities, index)
	integrity := buildIntegrityV2(entities, projections)

	return ReportV2{
		Schema: reportSchemaV2{
			Name:        reportV2SchemaName,
			Version:     reportV2SchemaVersion,
			GeneratedAt: generatedAt.Format(time.RFC3339),
		},
		Run: runV2{
			RunID:     runIDFromInput(data),
			StartTime: data.StartTime.UTC().Format(time.RFC3339),
			EndTime:   data.EndTime.UTC().Format(time.RFC3339),
			Duration:  data.EndTime.Sub(data.StartTime).String(),
			ExitCode:  0,
		},
		Input: inputSummaryV2{
			Filename: data.Input.Filename,
			Size:     data.Input.Size,
			SHA256:   data.Input.SHA256,
			SHA512:   data.Input.SHA512,
		},
		Generator: generatorV2{
			Version:  data.Generator.Version,
			Revision: data.Generator.Revision,
			Time:     data.Generator.Time,
			Modified: data.Generator.Modified,
			Display:  data.Generator.String(),
		},
		Config: configSnapshotV2{
			SBOMFormat:           data.Config.SBOMFormat,
			PolicyMode:           data.Config.PolicyMode.String(),
			InterpretMode:        data.Config.InterpretMode.String(),
			ReportSelection:      data.Config.ReportSelection.String(),
			ProgressLevel:        data.Config.ProgressLevel.String(),
			Language:             data.Config.Language,
			MarkdownRenderEngine: data.Config.MarkdownRenderEngine,
			MarkdownTemplateFile: data.Config.MarkdownTemplateFile,
			GrypeEnabled:         data.Config.GrypeEnabled,
			Unsafe:               data.Config.Unsafe,
			ParallelScanners:     data.Config.ParallelScanners,
			SkipExtensions:       append([]string(nil), data.Config.SkipExtensions...),
			RootMetadata: rootMetadataV2{
				Manufacturer: data.Config.RootMetadata.Manufacturer,
				Name:         data.Config.RootMetadata.Name,
				Version:      data.Config.RootMetadata.Version,
				DeliveryDate: data.Config.RootMetadata.DeliveryDate,
				Properties:   data.Config.RootMetadata.Properties,
			},
			Limits: limitsV2{
				MaxDepth:     data.Config.Limits.MaxDepth,
				MaxFiles:     data.Config.Limits.MaxFiles,
				MaxTotalSize: data.Config.Limits.MaxTotalSize,
				MaxEntrySize: data.Config.Limits.MaxEntrySize,
				MaxRatio:     data.Config.Limits.MaxRatio,
				Timeout:      data.Config.Limits.Timeout.String(),
			},
			Passwords: passwordInfoV2{
				Count:             len(data.Config.Passwords),
				SensitiveRedacted: true,
			},
		},
		Runtime: runtimeV2{
			Sandbox: sandboxV2{
				Name:           data.SandboxInfo.Name,
				Available:      data.SandboxInfo.Available,
				UnsafeOverride: data.SandboxInfo.UnsafeOvr,
			},
			ToolVersions: toolVersionsV2{
				SevenZip:   data.ToolVersions.SevenZip,
				Unshield:   data.ToolVersions.Unshield,
				Unsquashfs: data.ToolVersions.Unsquashfs,
				Grype:      data.ToolVersions.Grype,
				GrypeDB:    data.ToolVersions.GrypeDB,
			},
			Warnings: []warningV2{},
		},
		Raw: rawV2{
			ExtractionTreeRaw:   data.Tree,
			ScansRaw:            rawScans,
			BOMRaw:              data.BOM,
			VulnerabilitiesRaw:  data.Vulnerabilities,
			PolicyDecisionsRaw:  copyPolicyDecisions(data.PolicyDecisions),
			ProcessingIssuesRaw: copyProcessingIssues(data.ProcessingIssues),
			SuppressionsRaw:     copySuppressions(data.Suppressions),
			ArtifactPaths: artifactPathsV2{
				SBOMPath: data.SBOMPath,
			},
		},
		Entities:    entities,
		Projections: projections,
		Integrity:   integrity,
		Compatibility: compatibilityV2{
			LegacyAliasesUsed: legacyAliasesV2{},
			MigrationHints: []string{
				"slice-2: entities and integrity are populated from ReportData",
				"slice-3: projections are populated with renderer-oriented views",
			},
		},
	}
}

// toRawScanV2 maps one scan result into the raw snapshot block.
func toRawScanV2(scanResult scan.ScanResult) rawScanV2 {
	out := rawScanV2{
		NodePath:      scanResult.NodePath,
		BOM:           scanResult.BOM,
		EvidencePaths: scanResult.EvidencePaths,
	}
	if scanResult.Error != nil {
		out.Error = scanResult.Error.Error()
	}
	return out
}

// runIDFromInput creates a deterministic run identifier from immutable run inputs.
func runIDFromInput(data ReportData) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s",
		data.Input.Filename,
		data.Input.Size,
		data.Input.SHA256,
		data.Input.SHA512,
		data.StartTime.UTC().Format(time.RFC3339Nano),
		data.EndTime.UTC().Format(time.RFC3339Nano),
	)))
	return "run:" + hex.EncodeToString(sum[:12])
}

// stableID produces compact deterministic IDs with a stable prefix.
func stableID(prefix string, parts ...string) string {
	input := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(input))
	return prefix + ":" + hex.EncodeToString(sum[:12])
}

// copyPolicyDecisions clones decisions so report output cannot mutate caller state.
func copyPolicyDecisions(in []policy.Decision) []policy.Decision {
	out := make([]policy.Decision, len(in))
	copy(out, in)
	return out
}

// copyProcessingIssues clones processing issues for raw report snapshots.
func copyProcessingIssues(in []ProcessingIssue) []ProcessingIssue {
	out := make([]ProcessingIssue, len(in))
	copy(out, in)
	return out
}

// copySuppressions clones suppression records for raw report snapshots.
func copySuppressions(in []assembly.SuppressionRecord) []assembly.SuppressionRecord {
	out := make([]assembly.SuppressionRecord, len(in))
	copy(out, in)
	return out
}
