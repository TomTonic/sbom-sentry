package domain

import "testing"

func TestCompareOccurrenceAllFields(t *testing.T) {
	t.Parallel()

	base := ComponentOccurrence{
		ObjectID:      "extract-sbom:AAA",
		PackageName:   "alpha",
		Version:       "1.0.0",
		PURL:          "pkg:maven/alpha@1.0.0",
		DeliveryPaths: []string{"a/path"},
		EvidencePaths: []string{"a/evidence"},
		FoundBy:       "java-archive-cataloger",
	}

	tests := []struct {
		name string
		a, b ComponentOccurrence
		want int
	}{
		{"equal", base, base, 0},
		{"delivery path less", func() ComponentOccurrence { c := base; c.DeliveryPaths = []string{"a/earlier"}; return c }(), base, -1},
		{"delivery path greater", base, func() ComponentOccurrence { c := base; c.DeliveryPaths = []string{"a/earlier"}; return c }(), 1},
		{"evidence path less", func() ComponentOccurrence { c := base; c.EvidencePaths = []string{"a/a"}; return c }(), func() ComponentOccurrence { c := base; c.EvidencePaths = []string{"a/z"}; return c }(), -1},
		{"package name less", func() ComponentOccurrence { c := base; c.PackageName = "aaa"; return c }(), func() ComponentOccurrence { c := base; c.PackageName = "zzz"; return c }(), -1},
		{"version less", func() ComponentOccurrence { c := base; c.Version = "1.0.0"; return c }(), func() ComponentOccurrence { c := base; c.Version = "2.0.0"; return c }(), -1},
		{"purl less", func() ComponentOccurrence { c := base; c.PURL = "pkg:a"; return c }(), func() ComponentOccurrence { c := base; c.PURL = "pkg:z"; return c }(), -1},
		{"foundby less", func() ComponentOccurrence { c := base; c.FoundBy = "aaa"; return c }(), func() ComponentOccurrence { c := base; c.FoundBy = "zzz"; return c }(), -1},
		{"objectid less", func() ComponentOccurrence { c := base; c.ObjectID = "extract-sbom:AAA"; return c }(), func() ComponentOccurrence { c := base; c.ObjectID = "extract-sbom:ZZZ"; return c }(), -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareOccurrence(tt.a, tt.b)
			if (tt.want < 0 && got >= 0) || (tt.want > 0 && got <= 0) || (tt.want == 0 && got != 0) {
				t.Fatalf("compareOccurrence() = %d, want sign %d", got, tt.want)
			}
		})
	}
}

func TestFirstStringEmpty(t *testing.T) {
	t.Parallel()
	if got := firstString(nil); got != "" {
		t.Fatalf("firstString(nil) = %q, want empty", got)
	}
}

func TestFirstStringNonEmpty(t *testing.T) {
	t.Parallel()
	if got := firstString([]string{"a", "b"}); got != "a" {
		t.Fatalf("firstString = %q, want a", got)
	}
}

func TestBuildPackageOccurrenceGroupsSortByDeliveryPath(t *testing.T) {
	t.Parallel()

	groups := BuildPackageOccurrenceGroups([]ComponentOccurrence{
		{
			ObjectID:       "extract-sbom:ZZZ",
			PackageName:    "zlib",
			Version:        "1.2.13",
			DeliveryPaths:  []string{"z/path/zlib.jar"},
			EvidencePaths:  []string{"z/path/zlib.jar/META-INF/MANIFEST.MF"},
			EvidenceSource: "manifest",
		},
		{
			ObjectID:       "extract-sbom:AAA",
			PackageName:    "alpha",
			Version:        "1.0.0",
			DeliveryPaths:  []string{"a/path/alpha.jar"},
			EvidencePaths:  []string{"a/path/alpha.jar/META-INF/MANIFEST.MF"},
			EvidenceSource: "manifest",
		},
	})

	if len(groups) != 2 {
		t.Fatalf("package group count = %d, want 2", len(groups))
	}
	if groups[0].PackageName != "alpha" || groups[1].PackageName != "zlib" {
		t.Fatalf("package groups not sorted by delivery path: first=%q second=%q", groups[0].PackageName, groups[1].PackageName)
	}
}
