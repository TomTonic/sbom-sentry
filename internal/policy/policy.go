package policy

import "sbom-sentry/internal/config"

// Action is the policy engine output for a processed violation.
type Action string

const (
	// ActionAbort stops processing due to the violation.
	ActionAbort Action = "Abort"
	// ActionSkip skips the current subtree and continues elsewhere.
	ActionSkip Action = "Skip"
	// ActionContinue records a violation but keeps processing unchanged.
	ActionContinue Action = "Continue"
)

// Violation describes a single policy-relevant limit event.
type Violation struct {
	Trigger  string
	NodePath string
	Detail   string
}

// Decision records the chosen action for a violation.
type Decision struct {
	Trigger  string
	NodePath string
	Action   Action
	Detail   string
}

// Engine evaluates policy behavior based on configured mode.
type Engine struct {
	mode      config.PolicyMode
	decisions []Decision
}

// NewEngine constructs a policy engine for the provided mode.
func NewEngine(mode config.PolicyMode) *Engine {
	return &Engine{mode: mode}
}

// Evaluate returns the policy decision for the given violation and stores it
// for later reporting.
func (e *Engine) Evaluate(v Violation) Decision {
	d := Decision{Trigger: v.Trigger, NodePath: v.NodePath, Detail: v.Detail}
	if e.mode == config.PolicyStrict {
		d.Action = ActionAbort
	} else {
		d.Action = ActionSkip
	}
	e.decisions = append(e.decisions, d)
	return d
}

// Decisions returns all decisions accumulated so far.
func (e *Engine) Decisions() []Decision {
	out := make([]Decision, len(e.decisions))
	copy(out, e.decisions)
	return out
}
