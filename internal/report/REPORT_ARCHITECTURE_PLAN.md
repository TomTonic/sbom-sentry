# Report Module Target Architecture and Refactoring Plan

## Purpose

This document defines the target architecture for `internal/report` and the
step-by-step refactoring plan we will follow from now on.

It is implementation-oriented and should be used as the execution checklist for
future report-module changes.

## Scope

In scope:

- Human report rendering (Markdown, optional template engines)
- HTML report generation
- Machine JSON report generation
- SARIF report generation
- Shared report models, i18n strings, and view-model preparation
- Occurrence/vulnerability/suppression/statistics helpers

Out of scope:

- Orchestrator pipeline flow beyond report integration points
- SBOM assembly internals (except report-facing read models)

## Architectural Goals

1. **Clear responsibility boundaries**
   - Each file owns one concern (rendering, i18n, view model, formatting,
     grouping, normalization, etc.).
2. **Deterministic output stability**
   - Refactors must not change ordering or report semantics unless explicitly
     planned and tested.
3. **Low cognitive load**
   - Keep files cohesive and easier to navigate; avoid monolithic helper files.
4. **Strong regression safety**
   - Every refactoring step includes focused tests + full `go test ./...`.
5. **Incremental delivery**
   - Small, reviewable commits with explicit step IDs.

## Target Module Layout

### A. API and contracts

- `report.go`
  - Public API entry points and input summary helpers.
- `report_types.go`
  - Public and internal report data structures.

### B. Human report pipeline

- `report_human_options.go`
  - Backend/engine selection (`writer`, `template-wrapper`,
    `template-document`) and options dispatch.
- `report_human_viewmodel.go`
  - Pure, deterministic precomputation for human report data.
- `report_human_renderer*.go`
  - Rendering backends only (no heavy business logic).
- `report_human_sections_*.go`
  - Section writers split by concern (summary, config/input metadata,
    extraction/policy/scan, appendices).

### C. Shared domain helpers

- `report_occurrence_*.go`
  - Occurrence extraction, grouping, rendering, and dedupe policy.
- `report_vuln*.go`
  - Vulnerability formatting, ordering, and package-level rendering.
- `report_suppression*.go`
  - Suppression explanation and replacement-link resolution.
- `report_stats_*.go`
  - Extraction and scan statistics collectors.

### D. Output-specific generators

- `report_machine.go`
- `report_html*.go`
- `report_sarif*.go`

### E. Localization

- `report_i18n*.go`
  - Catalog definitions and language selection logic, organized by section
    domain to keep each file small and readable.

## Refactoring Rules

1. No behavior change unless explicitly stated in the step objective.
2. Preserve public API signatures unless a dedicated API step says otherwise.
3. Keep each step independently releasable.
4. Run, at minimum, after each step:
   - `go test ./internal/report`
   - `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...`
   - `go test ./...`
5. Update this document when step status changes.

## Stepwise Refactoring Plan

Status values:

- `PLANNED`: not started
- `IN_PROGRESS`: currently being implemented
- `DONE`: merged and validated
- `BLOCKED`: cannot proceed without decision/input

### REP-ARCH-001 - Establish architecture baseline

- Status: `DONE`
- Objective: Create this architecture-and-plan document in the module.
- Output: `internal/report/REPORT_ARCHITECTURE_PLAN.md`
- Exit criteria:
  - Shared understanding of target structure and step IDs.

### REP-ARCH-002 - Occurrence logic decomposition

- Status: `DONE`
- Objective: Split large occurrence implementation into focused files
  (`collect`, `group`, `render`).
- Exit criteria:
  - Original monolithic occurrence file removed.
  - Tests and lint green.

### REP-ARCH-003 - Human section writer split

- Status: `DONE`
- Objective: Break `report_human_main.go` into section-domain files:
  - `report_human_sections_summary.go`
  - `report_human_sections_process.go`
  - `report_human_sections_appendix.go`
- Exit criteria:
  - No semantic or ordering changes in generated Markdown.
  - Existing tests unchanged or expanded for parity.

### REP-ARCH-004 - i18n catalog modularization

- Status: `DONE`
- Objective: Split `report_i18n.go` by domain while preserving key coverage and
  lookup behavior:
  - `report_i18n_core.go`
  - `report_i18n_human.go`
  - `report_i18n_html.go`
  - `report_i18n_vuln.go`
- Exit criteria:
  - Language output remains bit-for-bit equivalent except for intentionally
    corrected typos.

### REP-ARCH-005 - Human renderer backend hard boundaries

- Status: `DONE`
- Objective: Ensure renderer files contain rendering orchestration only, while
  data shaping lives in view-model/helpers.
- Exit criteria:
  - No business-rule branching in backend glue beyond engine dispatch and
    template execution.

### REP-ARCH-006 - HTML generator domain extraction

- Status: `DONE`
- Objective: Split `report_html.go` into:
  - template/view model builder
  - vulnerability table formatter
  - extraction tree formatter
- Exit criteria:
  - HTML output structure unchanged.
  - Existing HTML tests remain green.

### REP-ARCH-007 - Machine/SARIF helper normalization

- Status: `DONE`
- Objective: Consolidate repeated formatting and ordering helpers used by
  `report_machine.go` and `report_sarif.go` into focused shared helpers.
- Exit criteria:
  - No report schema/output regressions.
  - Deterministic ordering preserved.

### REP-ARCH-008 - Cross-report ordering contract tests

- Status: `DONE`
- Objective: Add explicit tests for deterministic ordering invariants shared by
  human/machine/HTML/SARIF outputs.
- Exit criteria:
  - Determinism assertions exist for key sortable entities
    (occurrences, vulnerabilities, section blocks).

### REP-ARCH-009 - Documentation and module guide sync

- Status: `DONE`
- Objective: Align `MODULE_GUIDE.md` with finalized report module boundaries and
  design decisions after refactoring steps complete.
- Exit criteria:
  - Module guide matches actual file/module architecture.

### REP-ARCH-010 - Final hardening pass

- Status: `DONE`
- Objective: Remove dead helpers, tighten comments/GoDoc, and ensure file-size
  cohesion targets are met.
- Exit criteria:
  - No oversized mixed-responsibility files remain in report module.
  - Lint and full test suite green.

## Execution Order

Mandatory order:

`REP-ARCH-003 -> REP-ARCH-004 -> REP-ARCH-005 -> REP-ARCH-006 -> REP-ARCH-007 -> REP-ARCH-008 -> REP-ARCH-009 -> REP-ARCH-010`

`REP-ARCH-001` and `REP-ARCH-002` are already complete.

## Change Control

For every future refactoring PR/commit in `internal/report`, include:

- The step ID in commit message and PR notes (for traceability)
- A short statement: behavior-preserving vs. behavior-changing
- Validation commands executed and their result

---

## Current Next Step

`Completed: REP-ARCH-010 - Final hardening pass`
