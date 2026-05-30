package domain

import (
	"reflect"
	"testing"
)

func TestPreferredRefs(t *testing.T) {
	t.Parallel()

	if got := PreferredRefs([]string{"a"}, []string{"b"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("PreferredRefs primary = %v, want [a]", got)
	}
	if got := PreferredRefs(nil, []string{"b"}); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("PreferredRefs fallback = %v, want [b]", got)
	}
}

func TestNormalizeProjectionRefs(t *testing.T) {
	t.Parallel()

	if got := NormalizeProjectionRefs([]string{"x"}); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("NormalizeProjectionRefs passthrough = %v, want [x]", got)
	}
	if got := NormalizeProjectionRefs(nil); got == nil || len(got) != 0 {
		t.Fatalf("NormalizeProjectionRefs nil = %v, want empty non-nil slice", got)
	}
}

func TestFirstNonEmptyRefs(t *testing.T) {
	t.Parallel()

	if got := FirstNonEmptyRefs(nil, []string{"a", "b"}, []string{"c"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("FirstNonEmptyRefs = %v, want [a]", got)
	}
	if got := FirstNonEmptyRefs(nil, nil); got != nil {
		t.Fatalf("FirstNonEmptyRefs empty = %v, want nil", got)
	}
}

func TestSortedUniqueStrings(t *testing.T) {
	t.Parallel()

	in := []string{"b", "a", "b", "c", "a"}
	if got := SortedUniqueStrings(in); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("SortedUniqueStrings = %v, want [a b c]", got)
	}
	if !reflect.DeepEqual(in, []string{"b", "a", "b", "c", "a"}) {
		t.Fatalf("SortedUniqueStrings modified input: %v", in)
	}
}

func TestSortedUniqueNonEmptyStrings(t *testing.T) {
	t.Parallel()

	in := []string{"b", "", "a", "b", "", "c", "a"}
	if got := SortedUniqueNonEmptyStrings(in); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("SortedUniqueNonEmptyStrings = %v, want [a b c]", got)
	}
	if !reflect.DeepEqual(in, []string{"b", "", "a", "b", "", "c", "a"}) {
		t.Fatalf("SortedUniqueNonEmptyStrings modified input: %v", in)
	}

	if got := SortedUniqueNonEmptyStrings([]string{"", ""}); got != nil {
		t.Fatalf("SortedUniqueNonEmptyStrings empty-only = %v, want nil", got)
	}
}
