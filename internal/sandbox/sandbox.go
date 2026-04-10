package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"sbom-sentry/internal/config"
)

// Sandbox executes external tools under an isolation mechanism when possible.
type Sandbox interface {
	// Run executes cmd with args using the sandbox runtime.
	Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error
	// Available reports whether the sandbox backend is ready.
	Available() bool
	// Name returns the backend name for reporting/auditing.
	Name() string
}

type bwrapSandbox struct{}

type passthroughSandbox struct{}

type gatedSandbox struct{}

// NewBwrapSandbox returns a Bubblewrap-backed sandbox implementation.
func NewBwrapSandbox() Sandbox {
	return &bwrapSandbox{}
}

// NewPassthroughSandbox returns a no-isolation sandbox backend.
func NewPassthroughSandbox() Sandbox {
	return &passthroughSandbox{}
}

// Resolve selects a sandbox backend based on availability and the unsafe flag.
func Resolve(cfg config.Config) (Sandbox, error) {
	b := NewBwrapSandbox()
	if b.Available() {
		return b, nil
	}
	if cfg.Unsafe {
		return NewPassthroughSandbox(), nil
	}
	return &gatedSandbox{}, nil
}

func (s *bwrapSandbox) Available() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil
}

func (s *bwrapSandbox) Name() string {
	return "bwrap"
}

func (s *bwrapSandbox) Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error {
	inputDir := filepath.Dir(inputPath)
	inputFile := filepath.Base(inputPath)

	fullArgs := []string{
		"--ro-bind", inputDir, "/input",
		"--bind", outputDir, "/output",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--unshare-all",
		"--new-session",
		"--die-with-parent",
		"--",
		cmd,
	}

	mapped := make([]string, 0, len(args))
	for _, arg := range args {
		replaced := strings.ReplaceAll(arg, "{input}", "/input/"+inputFile)
		replaced = strings.ReplaceAll(replaced, "{output}", "/output")
		mapped = append(mapped, replaced)
	}

	fullArgs = append(fullArgs, mapped...)
	c := exec.CommandContext(ctx, "bwrap", fullArgs...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandboxed command failed: %w: %s", err, string(out))
	}
	return nil
}

func (s *passthroughSandbox) Available() bool {
	return true
}

func (s *passthroughSandbox) Name() string {
	return "passthrough"
}

func (s *passthroughSandbox) Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error {
	mapped := make([]string, 0, len(args))
	for _, arg := range args {
		replaced := strings.ReplaceAll(arg, "{input}", inputPath)
		replaced = strings.ReplaceAll(replaced, "{output}", outputDir)
		mapped = append(mapped, replaced)
	}
	c := exec.CommandContext(ctx, cmd, mapped...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %w: %s", err, string(out))
	}
	return nil
}

func (s *gatedSandbox) Available() bool {
	return false
}

func (s *gatedSandbox) Name() string {
	return "unavailable"
}

func (s *gatedSandbox) Run(_ context.Context, _ string, _ []string, _ string, _ string) error {
	return fmt.Errorf("sandbox unavailable: install bubblewrap or re-run with --unsafe")
}
