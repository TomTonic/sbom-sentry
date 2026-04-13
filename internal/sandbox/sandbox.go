// Package sandbox provides isolation wrappers for executing external binaries
// (7-Zip, unshield) during archive extraction. It supports Bubblewrap-based
// namespace isolation on Linux and a passthrough fallback for environments
// where sandboxing is unavailable (requiring --unsafe).
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// Sandbox defines the interface for executing external commands in an
// isolated environment. Implementations bind-mount the input path read-only
// and the output directory read-write, preventing the external tool from
// accessing the broader filesystem.
type Sandbox interface {
	// Run executes the command inside the sandbox.
	// inputPath is bind-mounted read-only; outputDir is bind-mounted read-write.
	// The command and args refer to paths as they appear inside the sandbox.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout
	//   - cmd: the external binary to execute (e.g., "7zz", "unshield")
	//   - args: arguments to pass to the binary
	//   - inputPath: host filesystem path to the input file (mounted read-only)
	//   - outputDir: host filesystem path to the output directory (mounted read-write)
	//
	// Returns an error if execution fails or the sandbox cannot be established.
	Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error

	// Available reports whether this sandbox mechanism is functional on the
	// current system.
	Available() bool

	// Name returns a human-readable identifier for audit logging.
	Name() string
}

// BwrapSandbox implements Sandbox using Bubblewrap (bwrap) for Linux
// namespace isolation. It creates new mount, PID, IPC, UTS, network, and
// user namespaces for each invocation.
type BwrapSandbox struct {
	bwrapPath string
}

// NewBwrapSandbox creates a new Bubblewrap-based sandbox.
// It locates the bwrap binary on the system PATH.
//
// Usage: call Available() to check if bwrap is installed before using Run().
func NewBwrapSandbox() *BwrapSandbox {
	path, _ := exec.LookPath("bwrap")
	return &BwrapSandbox{bwrapPath: path}
}

// Available reports whether bwrap is installed and the current OS is Linux.
// Bubblewrap requires Linux namespaces and is not available on macOS.
func (b *BwrapSandbox) Available() bool {
	return b.bwrapPath != "" && runtime.GOOS == "linux"
}

// Name returns "bwrap" for audit logging.
func (b *BwrapSandbox) Name() string {
	return "bwrap"
}

// Run executes the command under Bubblewrap namespace isolation.
// The input file's directory is bind-mounted read-only at /input, and the
// output directory is bind-mounted read-write at /output. Network access,
// IPC, and PID namespaces are all isolated.
func (b *BwrapSandbox) Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error {
	if !b.Available() {
		return fmt.Errorf("sandbox: bwrap is not available")
	}

	inputDir := filepath.Dir(inputPath)
	inputName := filepath.Base(inputPath)

	// Resolve the actual command to execute inside the sandbox.
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		return fmt.Errorf("sandbox: cannot find %s: %w", cmd, err)
	}

	bwrapArgs := []string{
		"--ro-bind", inputDir, "/input",
		"--bind", outputDir, "/output",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
		"--symlink", "/usr/lib64", "/lib64",
	}

	// Only mount the tool's parent directory if it is NOT already visible
	// under one of the always-mounted prefixes (/usr, /lib). This prevents
	// accidentally exposing sensitive host directories when the tool binary
	// lives in an unexpected location (e.g., /opt/custom/bin/).
	cmdDir := filepath.Dir(cmdPath)
	if !isUnderMountedPrefix(cmdDir) {
		bwrapArgs = append(bwrapArgs, "--ro-bind", cmdPath, cmdPath)
	}

	bwrapArgs = append(bwrapArgs,
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--unshare-all",
		"--new-session",
		"--die-with-parent",
		"--",
		cmd,
	)

	// Replace input/output paths in args with sandbox-internal paths.
	for _, arg := range args {
		sandboxArg := arg
		sandboxArg = replacePrefix(sandboxArg, inputPath, "/input/"+inputName)
		sandboxArg = replacePrefix(sandboxArg, outputDir, "/output")
		bwrapArgs = append(bwrapArgs, sandboxArg)
	}

	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, b.bwrapPath, bwrapArgs...)
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		return fmt.Errorf("sandbox: bwrap execution failed: %w\nstderr: %s", err, stderr.String())
	}

	return nil
}

// isUnderMountedPrefix reports whether dir falls under one of the
// always-mounted read-only prefixes (/usr, /lib). Used to avoid redundant
// or security-problematic bind-mounts of tool parent directories.
func isUnderMountedPrefix(dir string) bool {
	for _, prefix := range []string{"/usr", "/lib"} {
		if dir == prefix || strings.HasPrefix(dir, prefix+"/") {
			return true
		}
	}
	return false
}

// replacePrefix replaces a path prefix in a string.
func replacePrefix(s, prefix, replacement string) string {
	if s == prefix {
		return replacement
	}
	if len(s) > len(prefix) && s[:len(prefix)] == prefix && s[len(prefix)] == '/' {
		return replacement + s[len(prefix):]
	}
	return s
}

// PassthroughSandbox implements Sandbox without any isolation.
// It executes commands directly on the host. This is the fallback used
// when --unsafe is specified and bwrap is not available.
type PassthroughSandbox struct{}

// NewPassthroughSandbox creates a new passthrough (no-isolation) sandbox.
// This should only be used when the operator has explicitly opted into
// unsafe mode via --unsafe.
func NewPassthroughSandbox() *PassthroughSandbox {
	return &PassthroughSandbox{}
}

// Available always returns true — passthrough execution is always possible.
func (p *PassthroughSandbox) Available() bool {
	return true
}

// Name returns "passthrough" for audit logging, making it clear in the
// report that no isolation was used.
func (p *PassthroughSandbox) Name() string {
	return "passthrough"
}

// Run executes the command directly without sandbox isolation.
// The inputPath and outputDir are used as-is on the host filesystem.
func (p *PassthroughSandbox) Run(ctx context.Context, cmd string, args []string, _ string, _ string) error {
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		return fmt.Errorf("sandbox: cannot find %s: %w", cmd, err)
	}

	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, cmdPath, args...)
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		return fmt.Errorf("sandbox: %s execution failed: %w\nstderr: %s", cmd, err, stderr.String())
	}

	return nil
}

// DeniedSandbox implements Sandbox by refusing all execution attempts.
// It is used when bwrap is unavailable and --unsafe was not specified,
// ensuring that external tools never run unsandboxed without explicit opt-in.
type DeniedSandbox struct{}

// NewDeniedSandbox creates a sandbox that blocks all execution.
// This is the gated backend described in the design: external tool invocations
// fail with a clear error message rather than silently running unsandboxed.
func NewDeniedSandbox() *DeniedSandbox {
	return &DeniedSandbox{}
}

// Available always returns false — this sandbox blocks execution.
func (d *DeniedSandbox) Available() bool {
	return false
}

// Name returns "denied" for audit logging.
func (d *DeniedSandbox) Name() string {
	return "denied"
}

// Run always returns an error explaining that sandboxed execution is not possible.
func (d *DeniedSandbox) Run(_ context.Context, cmd string, _ []string, _ string, _ string) error {
	return fmt.Errorf("sandbox: cannot execute %s: bwrap is not available and --unsafe was not specified; "+
		"pass --unsafe to allow unsandboxed extraction", cmd)
}

// Resolve determines the appropriate sandbox implementation based on the
// configuration. If bwrap is available, it returns a BwrapSandbox. If bwrap
// is unavailable and cfg.Unsafe is true, it returns a PassthroughSandbox.
// If bwrap is unavailable and cfg.Unsafe is false, it returns a DeniedSandbox
// that blocks all external tool execution with a clear error.
//
// Parameters:
//   - cfg: the run configuration, particularly the Unsafe flag
//
// Returns the selected Sandbox implementation and an optional resolution error.
//
// If bwrap is unavailable and cfg.Unsafe is false, Resolve returns a
// DeniedSandbox together with a non-nil error so callers can surface the
// condition explicitly while preserving deterministic denied behavior.
// newBwrapSandboxFunc is the factory used by Resolve to create a
// BwrapSandbox. Tests can override this to simulate bwrap absence on
// platforms where bwrap is actually installed.
var newBwrapSandboxFunc = func() *BwrapSandbox {
	return NewBwrapSandbox()
}

func Resolve(cfg config.Config) (Sandbox, error) {
	bwrap := newBwrapSandboxFunc()
	if bwrap.Available() {
		return bwrap, nil
	}

	if cfg.Unsafe {
		return NewPassthroughSandbox(), nil
	}

	return NewDeniedSandbox(), fmt.Errorf("sandbox: bwrap is not available and --unsafe was not specified")
}
