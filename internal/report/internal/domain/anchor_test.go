package domain

import "testing"

func TestOccurrenceAnchorID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "component-occurrence"},
		{name: "alnum", in: "pkg-maven_alpha1", want: "component-pkg-maven_alpha1"},
		{name: "mixed punctuation", in: "pkg:maven/org.acme/demo@1.0.0", want: "component-pkg-maven-org-acme-demo-1-0-0"},
		{name: "trailing separators trimmed", in: "abc///", want: "component-abc"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := OccurrenceAnchorID(tc.in); got != tc.want {
				t.Fatalf("OccurrenceAnchorID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
