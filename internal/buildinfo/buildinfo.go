// Package buildinfo provides build and VCS metadata for extract-sbom.
//
// It reads Go build metadata from runtime/debug and supports an explicit
// linker-injected release version to ensure release binaries report the exact
// GitHub tag used for publication.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// ReleaseVersion is optionally injected at link time.
//
// Example:
//
//	-X github.com/TomTonic/extract-sbom/internal/buildinfo.ReleaseVersion=v1.2.3
var ReleaseVersion = ""

// Info captures build and VCS metadata for the running binary.
type Info struct {
	Version  string
	Revision string
	Time     string
	Modified bool
}

// Read returns build metadata for the current binary.
func Read() Info {
	bi := Info{Version: "(devel)"}

	if rv := strings.TrimSpace(ReleaseVersion); rv != "" {
		bi.Version = rv
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		if bi.Version == "(devel)" {
			bi.Version = "(unknown)"
		}
		return bi
	}

	if bi.Version == "(devel)" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		bi.Version = info.Main.Version
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			bi.Revision = s.Value
		case "vcs.time":
			bi.Time = s.Value
		case "vcs.modified":
			bi.Modified = s.Value == "true"
		}
	}

	// Release binaries are built in CI with an explicit release version injected
	// via ldflags. For those artifacts, reporting "dirty" is confusing for
	// operators and does not add actionable value in audit reports.
	if strings.TrimSpace(ReleaseVersion) != "" {
		bi.Modified = false
	}

	return bi
}

// String formats build metadata into a concise single-line representation.
func (b Info) String() string {
	version := b.Version
	if version == "" {
		version = "(devel)"
	}

	parts := []string{version}
	if b.Revision != "" {
		rev := b.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		parts = append(parts, "rev "+rev)
	}
	if b.Time != "" {
		parts = append(parts, b.Time)
	}
	if b.Modified {
		parts = append(parts, "dirty")
	}

	return strings.Join(parts, " ")
}
