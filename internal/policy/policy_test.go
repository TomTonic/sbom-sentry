// Policy module tests: Verify that the policy engine correctly evaluates
// violations and produces appropriate decisions based on policy mode.
// The policy engine is a critical decision point that determines whether
// processing continues, skips, or aborts.
package policy

import (
	"fmt"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
)

// TestNewEngineCreatesEmptyEngine verifies that a freshly created engine
// has no decisions recorded.
func TestNewEngineCreatesEmptyEngine(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyStrict)
	if len(engine.Decisions()) != 0 {
		t.Errorf("new engine has %d decisions, want 0", len(engine.Decisions()))
	}
}

// TestHardSecurityAlwaysAbortsRegardlessOfMode verifies that hard security
// violations produce abort decisions in both strict and partial modes.
// This is a fundamental security invariant.
func TestHardSecurityAlwaysAbortsRegardlessOfMode(t *testing.T) {
	t.Parallel()

	modes := []struct {
		name string
		mode config.PolicyMode
	}{
		{"strict", config.PolicyStrict},
		{"partial", config.PolicyPartial},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			engine := NewEngine(m.mode)

			d := engine.Evaluate(Violation{
				Type:     "hard-security",
				NodePath: "/test.zip/evil",
				Error:    &safeguard.HardSecurityError{Violation: "path traversal"},
			})

			if d.Action != ActionAbort {
				t.Errorf("hard security in %s mode: action = %v, want abort", m.name, d.Action)
			}

			if d.Trigger != "hard-security" {
				t.Errorf("trigger = %q, want %q", d.Trigger, "hard-security")
			}
		})
	}
}

// TestResourceLimitStrictModeAborts verifies that resource limit violations
// in strict mode produce abort decisions.
func TestResourceLimitStrictModeAborts(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyStrict)

	d := engine.Evaluate(Violation{
		Type:     "resource-limit",
		NodePath: "/test.zip",
		Error: &safeguard.ResourceLimitError{
			Limit:   "max-files",
			Current: 300000,
			Max:     200000,
			Path:    "/test.zip",
		},
	})

	if d.Action != ActionAbort {
		t.Errorf("resource limit in strict mode: action = %v, want abort", d.Action)
	}

	if d.Trigger != "max-files" {
		t.Errorf("trigger = %q, want %q", d.Trigger, "max-files")
	}
}

// TestResourceLimitPartialModeSkips verifies that resource limit violations
// in partial mode produce skip decisions, allowing other subtrees to continue.
func TestResourceLimitPartialModeSkips(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	d := engine.Evaluate(Violation{
		Type:     "resource-limit",
		NodePath: "/test.zip",
		Error: &safeguard.ResourceLimitError{
			Limit:   "max-depth",
			Current: 7,
			Max:     6,
			Path:    "/test.zip/nested.zip/deeper.zip",
		},
	})

	if d.Action != ActionSkip {
		t.Errorf("resource limit in partial mode: action = %v, want skip", d.Action)
	}
}

// TestGenericErrorStrictModeAborts verifies that non-security, non-resource
// errors produce abort in strict mode.
func TestGenericErrorStrictModeAborts(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyStrict)

	d := engine.Evaluate(Violation{
		Type:     "scan-error",
		NodePath: "/test.zip/lib.jar",
		Error:    &testError{msg: "syft cataloging failed"},
	})

	if d.Action != ActionAbort {
		t.Errorf("generic error in strict mode: action = %v, want abort", d.Action)
	}
}

// TestGenericErrorPartialModeSkips verifies that non-security, non-resource
// errors produce skip in partial mode.
func TestGenericErrorPartialModeSkips(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	d := engine.Evaluate(Violation{
		Type:     "extraction",
		NodePath: "/test.zip/corrupt.tar",
		Error:    &testError{msg: "unexpected EOF"},
	})

	if d.Action != ActionSkip {
		t.Errorf("generic error in partial mode: action = %v, want skip", d.Action)
	}
}

// TestDecisionsReturnsAllEvaluated verifies that the engine accumulates
// all decisions for the audit trail.
func TestDecisionsReturnsAllEvaluated(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	engine.Evaluate(Violation{
		Type: "resource-limit", NodePath: "/a",
		Error: &safeguard.ResourceLimitError{Limit: "max-files", Current: 1, Max: 0, Path: "/a"},
	})
	engine.Evaluate(Violation{
		Type: "hard-security", NodePath: "/b",
		Error: &safeguard.HardSecurityError{Violation: "symlink"},
	})
	engine.Evaluate(Violation{
		Type: "scan-error", NodePath: "/c",
		Error: &testError{msg: "failed"},
	})

	decisions := engine.Decisions()
	if len(decisions) != 3 {
		t.Errorf("Decisions() count = %d, want 3", len(decisions))
	}
}

// TestDecisionsReturnsCopy verifies that Decisions returns a copy,
// not a reference to the internal slice.
func TestDecisionsReturnsCopy(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyStrict)
	engine.Evaluate(Violation{
		Type: "test", NodePath: "/x",
		Error: &testError{msg: "test"},
	})

	d1 := engine.Decisions()
	d1[0].Detail = "mutated"

	d2 := engine.Decisions()
	if d2[0].Detail == "mutated" {
		t.Error("Decisions() returned a reference, not a copy")
	}
}

// TestHasHardSecurityIncident verifies the convenience method for
// checking hard security incidents.
func TestHasHardSecurityIncident(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	if engine.HasHardSecurityIncident() {
		t.Error("empty engine reports hard security incident")
	}

	engine.Evaluate(Violation{
		Type: "resource-limit", NodePath: "/a",
		Error: &safeguard.ResourceLimitError{Limit: "max-files", Current: 1, Max: 0, Path: "/a"},
	})

	if engine.HasHardSecurityIncident() {
		t.Error("resource-limit-only engine reports hard security incident")
	}

	engine.Evaluate(Violation{
		Type: "hard-security", NodePath: "/b",
		Error: &safeguard.HardSecurityError{Violation: "zip-slip"},
	})

	if !engine.HasHardSecurityIncident() {
		t.Error("engine with hard security violation does not report it")
	}
}

// TestHasAbort verifies abort detection.
func TestHasAbort(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyStrict)

	if engine.HasAbort() {
		t.Error("empty engine reports abort")
	}

	engine.Evaluate(Violation{
		Type: "scan-error", NodePath: "/a",
		Error: &testError{msg: "fail"},
	})

	if !engine.HasAbort() {
		t.Error("strict engine with error does not report abort")
	}
}

// TestHasSkip verifies skip detection.
func TestHasSkip(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	if engine.HasSkip() {
		t.Error("empty engine reports skip")
	}

	engine.Evaluate(Violation{
		Type: "resource-limit", NodePath: "/a",
		Error: &safeguard.ResourceLimitError{Limit: "max-depth", Current: 7, Max: 6, Path: "/a"},
	})

	if !engine.HasSkip() {
		t.Error("partial engine with resource limit does not report skip")
	}
}

// TestActionString verifies human-readable action names.
func TestActionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		action Action
		want   string
	}{
		{ActionAbort, "abort"},
		{ActionSkip, "skip"},
		{ActionContinue, "continue"},
		{Action(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.action.String(); got != tt.want {
				t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

// testError is a simple error for testing non-security, non-resource errors.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestWrappedHardSecurityErrorIsClassifiedCorrectly verifies that a
// HardSecurityError wrapped via fmt.Errorf %w is still recognized by
// the policy engine as a hard security violation. Without errors.As,
// wrapped errors would fall through to the generic default case.
func TestWrappedHardSecurityErrorIsClassifiedCorrectly(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	// Wrap the error like an upstream caller might do.
	inner := &safeguard.HardSecurityError{Violation: "symlink", Path: "evil.txt", Detail: "symlink escape"}
	wrapped := fmt.Errorf("extract: failed at node: %w", inner)

	d := engine.Evaluate(Violation{
		Type:     "hard-security",
		NodePath: "/test.zip/evil.txt",
		Error:    wrapped,
	})

	if d.Action != ActionAbort {
		t.Errorf("wrapped HardSecurityError: action = %v, want abort", d.Action)
	}
	if d.Trigger != "hard-security" {
		t.Errorf("wrapped HardSecurityError: trigger = %q, want %q", d.Trigger, "hard-security")
	}
}

// TestWrappedResourceLimitErrorIsClassifiedCorrectly verifies that a
// ResourceLimitError wrapped via fmt.Errorf %w is still recognized by
// the policy engine and produces the correct trigger name.
func TestWrappedResourceLimitErrorIsClassifiedCorrectly(t *testing.T) {
	t.Parallel()

	engine := NewEngine(config.PolicyPartial)

	inner := &safeguard.ResourceLimitError{Limit: "max-files", Current: 999, Max: 100, Path: "/test.zip"}
	wrapped := fmt.Errorf("safeguard: %w", inner)

	d := engine.Evaluate(Violation{
		Type:     "resource-limit",
		NodePath: "/test.zip",
		Error:    wrapped,
	})

	if d.Action != ActionSkip {
		t.Errorf("wrapped ResourceLimitError in partial mode: action = %v, want skip", d.Action)
	}
	if d.Trigger != "max-files" {
		t.Errorf("wrapped ResourceLimitError: trigger = %q, want %q", d.Trigger, "max-files")
	}
}
