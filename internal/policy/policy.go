// Package policy evaluates limit violations and determines processing behavior
// based on the configured policy mode. In strict mode, any violation produces
// an abort. In partial mode, the offending subtree is skipped and processing
// continues elsewhere. Hard security failures always abort the affected subtree
// regardless of policy mode.
package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
)

// Action represents the policy response to a violation.
type Action int

const (
	// ActionAbort stops the entire processing run.
	ActionAbort Action = iota
	// ActionSkip skips the offending subtree and continues elsewhere.
	ActionSkip
	// ActionContinue allows processing to proceed (informational only).
	ActionContinue
)

// String returns the human-readable name of the action.
func (a Action) String() string {
	switch a {
	case ActionAbort:
		return "abort"
	case ActionSkip:
		return "skip"
	case ActionContinue:
		return "continue"
	default:
		return "unknown"
	}
}

// Violation represents a condition that the policy engine must evaluate.
type Violation struct {
	Type     string // "hard-security", "resource-limit", "scan-error"
	NodePath string // where in the extraction tree this occurred
	Error    error  // the underlying error
}

// Decision records the policy engine's response to a specific violation.
// All decisions are collected for inclusion in the audit report.
type Decision struct {
	Trigger  string // what limit or condition was hit
	NodePath string // where in the extraction tree
	Action   Action // what the engine decided to do
	Detail   string // human-readable explanation
}

// Engine evaluates violations against the configured policy mode and
// accumulates all decisions for the audit trail.
type Engine struct {
	mode      config.PolicyMode
	decisions []Decision
	mu        sync.Mutex
}

// NewEngine creates a policy Engine with the specified mode.
// In strict mode, resource limit violations produce abort decisions.
// In partial mode, resource limit violations produce skip decisions.
// Hard security violations always produce abort decisions for the affected subtree.
//
// Parameters:
//   - mode: the policy mode (PolicyStrict or PolicyPartial)
//
// Returns a ready-to-use Engine.
func NewEngine(mode config.PolicyMode) *Engine {
	return &Engine{mode: mode}
}

// Evaluate processes a violation and returns the resulting Decision.
// The decision is also recorded internally for later retrieval via Decisions().
//
// Hard security violations (safeguard.HardSecurityError) always produce
// ActionAbort for the affected subtree, regardless of policy mode.
// Resource limit violations produce ActionAbort in strict mode and
// ActionSkip in partial mode.
// Other errors produce ActionAbort in strict mode and ActionSkip in partial mode.
//
// Parameters:
//   - v: the violation to evaluate
//
// Returns the Decision made.
func (e *Engine) Evaluate(v Violation) Decision {
	var d Decision
	d.NodePath = v.NodePath

	switch {
	case isHardSecurity(v.Error):
		d.Trigger = "hard-security"
		d.Action = ActionAbort
		d.Detail = fmt.Sprintf("Hard security violation at %s: %v", v.NodePath, v.Error)

	case isResourceLimit(v.Error):
		d.Trigger = extractLimitName(v.Error)
		if e.mode == config.PolicyStrict {
			d.Action = ActionAbort
			d.Detail = fmt.Sprintf("Resource limit %s exceeded at %s (strict mode: aborting)", d.Trigger, v.NodePath)
		} else {
			d.Action = ActionSkip
			d.Detail = fmt.Sprintf("Resource limit %s exceeded at %s (partial mode: skipping subtree)", d.Trigger, v.NodePath)
		}

	default:
		d.Trigger = v.Type
		if e.mode == config.PolicyStrict {
			d.Action = ActionAbort
			d.Detail = fmt.Sprintf("Error at %s: %v (strict mode: aborting)", v.NodePath, v.Error)
		} else {
			d.Action = ActionSkip
			d.Detail = fmt.Sprintf("Error at %s: %v (partial mode: skipping)", v.NodePath, v.Error)
		}
	}

	e.mu.Lock()
	e.decisions = append(e.decisions, d)
	e.mu.Unlock()

	return d
}

// Decisions returns a copy of all decisions made by the engine.
// This is used to populate the audit report with a complete list
// of all policy evaluations during the run.
func (e *Engine) Decisions() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Decision, len(e.decisions))
	copy(result, e.decisions)
	return result
}

// HasHardSecurityIncident returns true if any decision was triggered by
// a hard security violation. This is used by the orchestrator to determine
// the exit code.
func (e *Engine) HasHardSecurityIncident() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range e.decisions {
		if d.Trigger == "hard-security" {
			return true
		}
	}
	return false
}

// HasAbort returns true if any decision resulted in an abort action.
func (e *Engine) HasAbort() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range e.decisions {
		if d.Action == ActionAbort {
			return true
		}
	}
	return false
}

// HasSkip returns true if any decision resulted in a skip action,
// indicating incomplete coverage.
func (e *Engine) HasSkip() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range e.decisions {
		if d.Action == ActionSkip {
			return true
		}
	}
	return false
}

// isHardSecurity checks if an error is a hard security violation.
// Uses errors.As to correctly handle wrapped errors (fmt.Errorf %w).
func isHardSecurity(err error) bool {
	var target *safeguard.HardSecurityError
	return errors.As(err, &target)
}

// isResourceLimit checks if an error is a resource limit violation.
// Uses errors.As to correctly handle wrapped errors (fmt.Errorf %w).
func isResourceLimit(err error) bool {
	var target *safeguard.ResourceLimitError
	return errors.As(err, &target)
}

// extractLimitName extracts the limit name from a ResourceLimitError.
func extractLimitName(err error) string {
	var rle *safeguard.ResourceLimitError
	if errors.As(err, &rle) {
		return rle.Limit
	}
	return "unknown"
}
