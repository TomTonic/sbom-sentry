package buildinfo

import (
	"strings"
	"testing"
)

func TestReadUsesReleaseVersionOverride(t *testing.T) {
	t.Parallel()

	old := ReleaseVersion
	ReleaseVersion = "v9.9.9"
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	if info.Version != "v9.9.9" {
		t.Fatalf("version = %q, want %q", info.Version, "v9.9.9")
	}
}

func TestInfoStringFormatsFields(t *testing.T) {
	t.Parallel()

	info := Info{
		Version:  "v1.2.3",
		Revision: "0123456789abcdef",
		Time:     "2026-04-11T12:34:56Z",
		Modified: true,
	}

	got := info.String()
	want := "v1.2.3 rev 0123456789ab 2026-04-11T12:34:56Z dirty"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestReadReleaseVersionSuppressesDirtyMarker(t *testing.T) {
	t.Parallel()

	old := ReleaseVersion
	ReleaseVersion = "v1.2.3"
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	if info.Modified {
		t.Fatal("expected Modified=false when ReleaseVersion is injected")
	}
	if strings.Contains(info.String(), "dirty") {
		t.Fatalf("String() = %q, must not contain dirty for release builds", info.String())
	}
}
