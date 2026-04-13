# Coding Agent Instructions — extract-sbom

This document defines **how** the project must be implemented,
independent of the functional design in DESIGN.md.

---

## 1. Language and Project Basics

- All relevant code must be written in **Go**
- Use Go modules for dependency management
- Minimize external dependencies where practical
- Existing, well-maintained tools and libraries may be used when they
   reduce implementation risk, improve archive coverage, or provide
   stronger safety guarantees than a bespoke implementation
- The selection of such tools is a solution design decision and must be
   documented in the software module guide, including the reason for the
   choice and the intended scope of use

---

## 2. Code Style and Quality

- Go source files should be small, cohesive, and responsibility-focused
- Target: ≤ 400 LOC for ~85% of files
- More than 600 LOC is a strong indicator for splitting
- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` with a project configuration
- Keep functions focused and reasonably small
- Prefer returned errors over panics
- Use error wrapping (`fmt.Errorf("context: %w", err)`)
- Never use `panic` in library code

---

## 3. Documentation Requirements

All project documentation shall be in English.

### 3.1 Solution Design Documentation

An overall software module guide shall be maintained, describing:

- The abstract interaction between the software modules
- The abstract interface definition of every software module
- The design decisions encapsulated within every software module
- It shall cover own code as well as external tools, libraries, and
   helper binaries selected for the implementation

### 3.2 Code Documentation

Every non-trivial function or data structure must have a GoDoc comment describing:

- What it does
- Why it exists
- How it is typically used
- Relevant parameters and return values
- Constraints or assumptions

### 3.3 Test Documentation

Each test must be documented **outside-in**, from the user's perspective:

- What end-user behavior is being validated
- In which part of the system the behavior belongs
- What concrete outcome is expected

Table-driven tests must have descriptive subtest names
that read as explicit assertions.

---

## 4. Testing Requirements

### 4.1 Mandatory Test Categories

The project must include:

1. **Unit tests**
   - Happy path + corner cases
   - Load and stress tests where advisable

2. **Integration tests**
   - Focussed on interfaces between software modules
   - Between Go modules
   - Between Go code and external tools
   - Include tests with real supported archive formats (for example ZIP, CAB, MSI, TAR)

3. **End-to-end tests**
   - One input file → SBOM + audit report
   - Nested container scenarios
   - Limit-trigger behavior

### 4.2 Coverage

- Aim for high and meaningful coverage (>80%)
- Critical security paths must be explicitly tested
- Fuzz tests are encouraged for archive parsing

---

## 5. Security Expectations

- Treat all input as hostile
- Protect against zip bombs, path traversal, and resource exhaustion
- Isolation failures must surface as explicit, testable outcomes

---

## 6. CI / CD Requirements

All changes must be validated by automated checks, including:

- `go build`
- `go test`
- `go test -race`
- `go test -cover`
- `golangci-lint`
- Additional format-specific linters or validators when the project
   introduces such file types; the selection is a solution design
   decision documented in the software module guide

CI must fail on linting or test failures.

---

## 7. Commit Message Rules

- Use imperative mood (“Add feature”, not “Added feature”)
- Keep subject lines concise
- Prefix dependency updates consistently (`deps-upd:`)
- Separate subject and body with a blank line

---

## 8. Syft Usage Guidelines

- Syft is mandatory
- Prefer library-mode usage
- Do not shell out unless unavoidable
- Capture sufficient metadata for SBOM and report explanation

---

## 9. Reporting Obligations

- Reports must be deterministic in structure
- All skipped or failed steps must be documented
- Language selection (EN/DE) must be explicit
- Avoid jargon; explain decisions and consequences

---

## 10. Definition of Done

Work is complete when:

- The tool builds and runs on Linux
- One input file yields one SBOM and one audit report
- Recursive extraction behaves as specified
- Limits and policies are enforced and tested
- CI passes without exceptions
- Output is auditable, reproducible, and understandable
