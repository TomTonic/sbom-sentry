# JSON Report v2 Design

Status: Proposed
Owner: report package
Scope: internal/report/internal/json

## Goals

This design defines a new canonical JSON report format (v2) that:

1. Preserves all run information from pipeline steps 1-7 and the complete step-8 ReportData snapshot.
2. Provides precomputed, semantically prepared projection blocks so Markdown and HTML renderers do not perform domain aggregation.
3. Balances normalized references and practical redundancy for stable rendering and maintainability.

## Non-Goals

1. This document does not define a long-term external public API guarantee for every field yet.
2. This document does not replace CycloneDX/SPDX output artifacts.

## Design Principles

1. Canonical source of truth: v2 JSON is the primary audit snapshot.
2. Stable IDs first: every cross-object relation uses explicit IDs.
3. Bounded redundancy: projection blocks may duplicate display values, but each row must keep source references.
4. Deterministic ordering: all arrays that affect rendering order are pre-sorted and stable.
5. Integrity by construction: references are validated and surfaced in an integrity block.

## Top-Level Structure

The report root object is:

- schema
- run
- input
- generator
- config
- runtime
- raw
- entities
- projections
- integrity
- compatibility

## Field List

### 1) schema

- name: string, fixed value extract-sbom-report
- version: string, fixed value 2.0.0
- generatedAt: RFC3339 timestamp

### 2) run

- runId: stable deterministic ID for this report instance
- startTime: RFC3339
- endTime: RFC3339
- duration: Go duration string
- exitCode: integer

### 3) input

- filename: string
- size: int64
- sha256: string
- sha512: string

### 4) generator

- version: string
- revision: string
- time: string
- modified: bool
- display: string

### 5) config

Effective runtime configuration snapshot (fully expanded values):

- sbomFormat
- policyMode
- interpretMode
- reportSelection
- progressLevel
- language
- markdownRenderEngine
- markdownTemplateFile
- grypeEnabled
- unsafe
- limits
  - maxDepth
  - maxFiles
  - maxTotalSize
  - maxEntrySize
  - maxRatio
  - timeout
- parallelScanners
- skipExtensions
- rootMetadata
  - manufacturer
  - name
  - version
  - deliveryDate
  - properties
- limits
  - maxDepth
  - maxFiles
  - maxTotalSize
  - maxEntrySize
  - maxRatio
  - timeout
- passwords
  - count
  - sensitiveRedacted
- properties

### 6) runtime

- sandbox
  - name
  - available
  - unsafeOverride
- toolVersions
  - sevenZip
  - unshield
  - unsquashfs
  - grype
  - grypeDb
- warnings: array of structured runtime warnings
  - code
  - message
  - relatedNodeId optional

### 7) raw

Near-1:1 raw snapshots from orchestrator outputs:

- extractionTreeRaw
- scansRaw
- bomRaw
- vulnerabilitiesRaw
- policyDecisionsRaw
- processingIssuesRaw
- suppressionsRaw
- artifactPaths
  - sbomPath
  - markdownReportPath optional
  - jsonReportPath optional
  - htmlReportPath optional
  - sarifReportPath optional

### 8) entities

Normalized canonical objects with stable IDs:

- nodes
- scanTasks
- components
- packageGroups
- vulnerabilities
- suppressions
- policyDecisions
- issues

### 9) projections

Prepared rendering models:

- generic
  - summary
  - extractionRows
  - vulnerabilityRows
  - issueRows
  - componentIndex
- markdown
  - sections
  - toc
  - anchors
- html
  - summaryCards
  - tableModels

### 10) integrity

- counts
  - nodes
  - scanTasks
  - components
  - packageGroups
  - vulnerabilities
  - suppressions
  - policyDecisions
  - issues
- danglingReferenceCount
- validationState: ok | warning | error
- validationErrors: array

### 11) compatibility

- legacyAliasesUsed
  - deprecatedFlagsUsed: array
- migrationHints

## ID Model

IDs are plain strings with prefixes:

- node:<hash>
- scan:<hash>
- comp:<bomref-or-hash>
- pkg:<slug-or-hash>
- vuln:<id>:<componentId>
- sup:<hash>
- pol:<sequence>
- issue:<sequence>

Rules:

1. IDs are unique within the report.
2. IDs are immutable for a given deterministic input.
3. Parent-child relations in nodes are acyclic.

## Reference Rules

1. scanTasks.nodeId must exist in entities.nodes.
2. scanTasks.componentIds must exist in entities.components.
3. packageGroups.componentIds must exist in entities.components.
4. vulnerabilities.componentId must exist in entities.components.
5. suppressions.suppressedComponentId and keptComponentId must exist or be explicitly marked unresolved with reason.
6. policyDecisions.nodeId may be empty only when no node is applicable.

## Redundancy Strategy

1. Canonical data lives in entities and raw.
2. projections duplicate only display-ready values needed for rendering speed and deterministic ordering.
3. Every projection row must include sourceRefs array with canonical IDs.
4. If a source reference is unresolved, the row must include resolutionStatus and resolutionReason.

## Mapping: ReportData to v2

- ReportData.Input -> input
- ReportData.Generator -> generator
- ReportData.Config -> config
- ReportData.Tree -> raw.extractionTreeRaw + entities.nodes + projections.generic.extractionRows
- ReportData.Scans -> raw.scansRaw + entities.scanTasks + projections.generic.summary.scan
- ReportData.Vulnerabilities -> raw.vulnerabilitiesRaw + entities.vulnerabilities + projections.generic.vulnerabilityRows
- ReportData.PolicyDecisions -> raw.policyDecisionsRaw + entities.policyDecisions
- ReportData.SandboxInfo -> runtime.sandbox
- ReportData.ProcessingIssues -> raw.processingIssuesRaw + entities.issues + projections.generic.issueRows
- ReportData.StartTime/EndTime -> run
- ReportData.BOM -> raw.bomRaw + entities.components + entities.packageGroups
- ReportData.SBOMPath -> raw.artifactPaths.sbomPath
- ReportData.Suppressions -> raw.suppressionsRaw + entities.suppressions + projections.generic.componentIndex
- ReportData.ToolVersions -> runtime.toolVersions

## Migration Plan

### Phase 0 - Prep

1. Introduce v2 data model types in a new package under internal/report/internal/jsonv2model.
2. Add schema file and schema validation test fixtures.

### Phase 1 - Parallel Build

1. Keep existing v1 JSON output as default.
2. Add config switch to emit v2 JSON (internal or experimental flag).
3. Build v2 from current ReportData in parallel.
4. Add invariants tests for integrity block and stable ordering.

### Phase 2 - Renderer Bridge

1. Add adapter layer from v2 projections to Markdown/HTML renderer inputs.
2. Remove sorting/grouping/correlation from Markdown package and HTML package incrementally.
3. Keep golden output tests for Markdown/HTML to ensure no behavior regressions.

### Phase 3 - Default Switch

1. Make v2 default JSON report.
2. Keep v1 behind legacy compatibility flag for one release window.
3. Emit deprecation warning when v1 is selected.

### Phase 4 - Remove v1

1. Remove v1 serializer and tests after compatibility window.
2. Keep migration notes in release documentation.

## PR Slices

### Slice 1: Schema + Model Skeleton

- Add report.schema.v2.json
- Add v2 Go structs
- Add schema validation tests

### Slice 2: Raw + Entities Population

- Populate raw and entities blocks from ReportData
- Add integrity counters and reference checks

### Slice 3: Projections + Renderer Decoupling

- Populate projections.generic/markdown/html
- Convert Markdown and HTML renderers to consume projections
- Remove domain aggregation from renderer packages

### Slice 4: Default + Cleanup

- Switch default to v2
- Keep temporary v1 compatibility switch
- Update docs and changelog

## Test Strategy

1. Schema validation tests using JSON Schema Draft 2020-12.
2. Determinism tests for IDs and ordering.
3. Integrity tests (no dangling refs except explicitly unresolved suppressions).
4. Golden tests for Markdown/HTML derived from v2 projections.
5. Migration compatibility tests comparing v1 and v2 summary invariants.
