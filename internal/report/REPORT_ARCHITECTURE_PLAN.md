# Report Module Target Architecture and Refactoring Plan

## Purpose

This document defines the target architecture for `internal/report` after the
first decomposition wave (`REP-ARCH-001` through `REP-ARCH-010`).

It is implementation-oriented and serves as the execution checklist for the
next consolidation phase.

## Scope

In scope:

- Human report rendering (Markdown, optional template backends)
- HTML report generation
- Machine JSON report generation
- SARIF report generation
- Shared report models, localization, and deterministic ordering logic
- Report-domain helpers for occurrences, vulnerabilities, suppressions, and
  statistics

Out of scope:

- Orchestrator pipeline flow beyond report integration points
- SBOM assembly internals except report-facing read models
- Additional Go modules; decomposition stays inside the existing repository
  module

## Architectural Review Outcome

The first refactoring wave was useful as a **behavior-preserving migration**,
but it is not an acceptable end state.

What worked:

- Large mixed-responsibility files were decomposed safely.
- Deterministic ordering and output contracts were made more explicit.
- Validation discipline improved and the migration stayed reviewable.

What did not work well enough:

- The package stayed flat and now has too many files in one directory.
- Naming drifted (`report_i18n_*` vs. `report_html_i18n.go`, verb-based helper
  files, output families and domain families mixed together).
- The root `report` package still owns too much implementation detail.
- Tests are behavior-oriented, but their file ownership does not consistently
  mirror the implementation slices they validate.

The next phase therefore optimizes for **package-level cohesion**, **predictable
naming**, and a **minimal root facade**.

## Architectural Goals

1. **Package-level responsibility boundaries**
   - Each package owns one report concern; files inside a package remain small,
     cohesive, and easy to scan.
2. **Deterministic output stability**
   - Refactors must not change ordering or report semantics unless explicitly
     planned and tested.
3. **Low cognitive load**
   - Prefer a small number of clearly named packages over a large number of
     root-level files with long prefixes.
4. **Minimal root API**
   - The root `report` package should be a thin orchestrator-facing facade.
5. **Strong regression safety**
   - Every step includes focused tests and full repository validation.
6. **AGENTS.md compliance**
   - Files remain small and cohesive, but not at the expense of discoverability.

## Feasibility Note

The current import surface of `internal/report` is already narrow enough to
support a facade-plus-subpackage structure. The root package is consumed only by
the orchestrator and its pipeline-level tests, so internal package extraction is
low-risk.

## Target Package Layout

The target structure uses **Go subpackages inside the existing repository
module**, not additional `go.mod` modules.

### A. Root facade package

- `internal/report`
  - Thin facade used by the orchestrator.
  - Owns top-level entry points and compatibility shims during migration.
  - Must not own human/HTML/machine/SARIF/domain implementation logic.

### B. Shared internal packages

- `internal/report/internal/model`
  - Shared report data structures (`ReportData`, `InputSummary`, tool/version
    summaries, anchors, section descriptors, stable constants).
- `internal/report/internal/domain`
  - Domain helpers grouped by noun: occurrence, vulnerability, suppression,
    statistics.
- `internal/report/internal/i18n`
  - Translation catalogs and language selection shared across outputs when
    sharing is actually useful.

### C. Output packages

- `internal/report/internal/human`
  - Human Markdown rendering, templating, sections, and human-specific i18n.
- `internal/report/internal/html`
  - HTML rendering, view-model preparation, and HTML-specific i18n.
- `internal/report/internal/machine`
  - Machine JSON rendering.
- `internal/report/internal/sarif`
  - SARIF rendering.

### D. Example file naming inside packages

- `render.go`
- `template.go`
- `sections.go`
- `i18n.go`
- `occurrence.go`
- `vulnerability.go`
- `suppression.go`
- `stats.go`

The directory already supplies the namespace. Repeating `report_` or `html_`
inside package-local file names is unnecessary.

## Naming Rules

1. Prefer noun-based names over process verbs when naming domain files.
2. Avoid `*_helpers.go` as a stable end-state file name.
3. Keep output-specific code inside output-specific packages.
4. Keep localization naming consistent across outputs.
5. Let the package boundary communicate ownership before the file name does.

## Test Layout Rules

1. Tests move with the owning package instead of accumulating in the facade.
2. Test file names should mirror the owning implementation slice where useful:
   - `render.go` -> `render_test.go`
   - `i18n.go` -> `i18n_test.go`
   - `occurrence.go` -> `occurrence_test.go`
3. Cross-output contract tests may stay at facade level, but only when they
   validate behavior that genuinely spans multiple output packages.

## Refactoring Rules

1. No behavior change unless explicitly stated in the step objective.
2. Public API compatibility is **not** a goal by itself; optimize it where that
   improves the final structure.
3. Keep each step independently releasable.
4. Run, at minimum, after each step:
   - `go test ./internal/report/...`
   - `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...`
   - `go test ./...`
5. Update this document when step status changes.

## Baseline Steps Already Completed

These steps are complete and remain valuable as the migration baseline:

- `REP-ARCH-001` establish architecture baseline
- `REP-ARCH-002` occurrence logic decomposition
- `REP-ARCH-003` human section writer split
- `REP-ARCH-004` i18n catalog modularization
- `REP-ARCH-005` human renderer boundary cleanup
- `REP-ARCH-006` HTML generator domain extraction
- `REP-ARCH-007` machine/SARIF helper normalization
- `REP-ARCH-008` cross-report ordering contract tests
- `REP-ARCH-009` module guide synchronization
- `REP-ARCH-010` final hardening pass for the flat-package design

## Consolidation Steps

Status values:

- `PLANNED`: not started
- `IN_PROGRESS`: currently being implemented
- `DONE`: merged and validated
- `BLOCKED`: cannot proceed without decision/input

### REP-ARCH-011 - Introduce facade and shared model package

- Status: `DONE`
- Objective: Turn `internal/report` into a thin facade and move shared report
  contracts into `internal/report/internal/model`.
- Exit criteria:
  - Root package keeps only orchestrator-facing entry points and minimal option
    wiring.
  - Shared data types/constants no longer live in the same package as output
    implementation.

### REP-ARCH-012 - Move human rendering into a human package

- Status: `DONE`
- Objective: Consolidate the human renderer into
  `internal/report/internal/human` with package-local files such as
  `render.go`, `template.go`, `sections.go`, and `i18n.go`.
- Exit criteria:
  - Flat `report_human_*` file family removed from the root package.
  - Human tests move next to human implementation.

### REP-ARCH-013 - Normalize HTML package structure and naming

- Status: `DONE`
- Objective: Move HTML report code into `internal/report/internal/html` and
  normalize naming so HTML-specific i18n is package-local `i18n.go`, not a
  root-level special case.
- Exit criteria:
  - HTML implementation is discoverable through the package boundary alone.
  - HTML naming becomes consistent with the rest of the module.

### REP-ARCH-014 - Move machine and SARIF generators behind package boundaries

- Status: `DONE`
- Objective: Move machine and SARIF rendering into dedicated `machine` and
  `sarif` packages.
- Exit criteria:
  - Output-specific generator code is no longer mixed into the root facade.
  - Root package delegates to package-local renderers.

### REP-ARCH-015 - Rebundle domain helpers by noun, not verb

- Status: `DONE`
- Objective: Replace the current verb/helper split with domain-centered files in
  `internal/report/internal/domain`.
- Exit criteria:
  - Occurrence, vulnerability, suppression, and statistics logic are grouped by
    domain responsibility.
  - `*_helpers.go` style names are removed from the final structure.

### REP-ARCH-016 - Collapse the exported API surface

- Status: `DONE`
- Objective: Reduce the root package API to the minimum surface the orchestrator
  actually needs.
- Exit criteria:
  - Optional human templating helpers/types are internalized or moved behind the
    facade.
  - Exported symbols reflect real integration needs rather than migration-era
    convenience.

### REP-ARCH-017 - Re-align test ownership and names

- Status: `DONE`
- Objective: Move tests to the owning packages and rename them so file names
  reflect the implementation slices they validate.
- Exit criteria:
  - Broad catch-all test files are reduced.
  - Package-local tests mirror the implementation layout.

### REP-ARCH-018 - Documentation sync and final cleanup

- Status: `PLANNED`
- Objective: Sync `MODULE_GUIDE.md`, remove stale comments/history references,
  and perform a final cleanup once the package consolidation is complete.
- Exit criteria:
  - Documentation matches the implemented package structure.
  - No stale references to removed root-level file names remain.

## Execution Order

Mandatory order:

`REP-ARCH-011 -> REP-ARCH-012 -> REP-ARCH-013 -> REP-ARCH-014 -> REP-ARCH-015 -> REP-ARCH-016 -> REP-ARCH-017 -> REP-ARCH-018`

`REP-ARCH-001` through `REP-ARCH-010` remain the completed baseline.

## Change Control

For every future refactoring commit in `internal/report`, include:

- The step ID in commit message and PR notes
- A short statement: behavior-preserving vs. behavior-changing
- Validation commands executed and their result

## Current Next Step

`REP-ARCH-018 - Documentation sync and final cleanup`
