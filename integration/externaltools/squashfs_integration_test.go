// Squashfs extraction integration tests: validate the boundary between
// extract-sbom's Go extraction flow and the external `unsquashfs` helper that
// the project added for SquashFS filesystem images and Snap packages. The
// behavior being checked belongs to the extraction subsystem; the expected
// outcome is that a SquashFS-magic input is dispatched to `unsquashfs`, that a
// missing `unsquashfs` transparently falls back to 7-Zip, and that an
// `unsquashfs` failure surfaces as an explicit, auditable failed status.
//
// The external tools are simulated with fake binaries on PATH (the same
// technique used by the 7-Zip isolation tests) so the boundary is exercised
// deterministically regardless of which archive tools the CI host has
// installed.
package externaltools_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// createSquashfsInput writes a file carrying the little-endian SquashFS magic
// ("hsqs") so the identify module classifies it as identify.Squashfs and the
// extraction flow routes it to extractSquashfs.
func createSquashfsInput(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "image.squashfs")
	content := make([]byte, 64)
	copy(content, []byte{0x68, 0x73, 0x71, 0x73}) // "hsqs"
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write squashfs input: %v", err)
	}
	return path
}

// fakeUnsquashfsScript is a POSIX-sh body emulating `unsquashfs`. It answers
// the version probe and, for an extraction call ("-d <outdir> -f <image>"),
// materializes a small predictable file tree in the output directory.
const fakeUnsquashfsScript = `
if [ "$1" = "-version" ]; then
  echo "unsquashfs version 4.5.1 (2022/03/13) integration-fake"
  exit 0
fi
[ "$1" = "-d" ] || exit 71
outdir="$2"
mkdir -p "$outdir/usr/bin"
printf 'fake-payload' > "$outdir/usr/bin/app"
printf 'license text' > "$outdir/LICENSE"
`

// TestUnsquashfsIntegrationExtractsSquashfsImage verifies that a SquashFS image
// is extracted through the dedicated `unsquashfs` tool: the extraction node
// must report success, name `unsquashfs` as the tool used, and account for the
// files the tool materialized.
func TestUnsquashfsIntegrationExtractsSquashfsImage(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, binDir, "unsquashfs", fakeUnsquashfsScript)
	prependPath(t, binDir)

	input := createSquashfsInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected extraction tree")
	}
	if tree.Status != extract.StatusExtracted {
		t.Fatalf("status = %v (%s), want %v", tree.Status, tree.StatusDetail, extract.StatusExtracted)
	}
	if tree.Tool != "unsquashfs" {
		t.Errorf("tool = %q, want %q", tree.Tool, "unsquashfs")
	}
	if tree.EntriesCount != 2 {
		t.Errorf("entriesCount = %d, want 2 (the files unsquashfs materialized)", tree.EntriesCount)
	}
}

// TestUnsquashfsIntegrationFallsBackTo7zWhenUnavailable verifies the documented
// fallback: when `unsquashfs` is not on PATH, SquashFS extraction is still
// attempted through the 7-Zip binary so the image is not silently skipped.
func TestUnsquashfsIntegrationFallsBackTo7zWhenUnavailable(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Only a fake 7zz is provided — `unsquashfs` is intentionally absent.
	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 41
outarg="$3"
case "$outarg" in
  -o*) outdir="${outarg#-o}" ;;
  *) exit 42 ;;
esac
/bin/mkdir -p "$outdir"
printf 'payload' > "$outdir/extracted.bin"
`)
	// Keep PATH hermetic so a host-installed unsquashfs cannot be discovered.
	t.Setenv("PATH", binDir)

	input := createSquashfsInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected extraction tree")
	}
	if tree.Status != extract.StatusExtracted {
		t.Fatalf("status = %v (%s), want %v", tree.Status, tree.StatusDetail, extract.StatusExtracted)
	}
	if tree.Tool != "7zz" {
		t.Errorf("tool = %q, want %q (7-Zip fallback)", tree.Tool, "7zz")
	}
}

// TestUnsquashfsIntegrationFailureSurfacesAsFailedStatus verifies that a crash
// or error from `unsquashfs` is not swallowed: the extraction node must end in
// the failed state with a diagnostic detail naming the tool, so the audit
// report can document the blind spot.
func TestUnsquashfsIntegrationFailureSurfacesAsFailedStatus(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, binDir, "unsquashfs", `
if [ "$1" = "-version" ]; then
  echo "unsquashfs version 4.5.1 (2022/03/13) integration-fake"
  exit 0
fi
echo "unsquashfs: cannot read filesystem" >&2
exit 1
`)
	prependPath(t, binDir)

	input := createSquashfsInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected extraction tree")
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
	if !strings.Contains(tree.StatusDetail, "unsquashfs") {
		t.Errorf("statusDetail = %q, want it to mention %q", tree.StatusDetail, "unsquashfs")
	}
}
