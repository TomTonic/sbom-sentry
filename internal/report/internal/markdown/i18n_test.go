package markdown

import (
	"reflect"
	"testing"
)

// TestTranslationBundlesHaveNoEmptyFields verifies that every string field
// in the translations struct is non-empty for all supported languages.
// This catches forgotten translations when new fields are added.
func TestTranslationBundlesHaveNoEmptyFields(t *testing.T) {
	t.Parallel()

	for _, lang := range []string{"en", "de"} {
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			tr := getTranslations(lang)
			v := reflect.ValueOf(tr)
			ty := v.Type()

			for i := range v.NumField() {
				field := ty.Field(i)
				val := v.Field(i)

				if field.Type.Kind() != reflect.String {
					continue
				}

				if val.String() == "" {
					t.Errorf("translations[%s].%s is empty", lang, field.Name)
				}
			}
		})
	}
}

// TestTranslationBundlesHaveSameFields verifies that EN and DE bundles
// are structurally identical.
func TestTranslationBundlesHaveSameFields(t *testing.T) {
	t.Parallel()

	en := getTranslations("en")
	de := getTranslations("de")

	enV := reflect.ValueOf(en)
	deV := reflect.ValueOf(de)
	ty := enV.Type()

	for i := range enV.NumField() {
		field := ty.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}

		enEmpty := enV.Field(i).String() == ""
		deEmpty := deV.Field(i).String() == ""

		if enEmpty && !deEmpty {
			t.Errorf("field %s: empty in EN but populated in DE", field.Name)
		}
		if !enEmpty && deEmpty {
			t.Errorf("field %s: populated in EN but empty in DE", field.Name)
		}
	}
}

// TestUnknownLanguageFallsBackToEnglish verifies that an unsupported
// language code produces the English bundle rather than an empty struct.
func TestUnknownLanguageFallsBackToEnglish(t *testing.T) {
	t.Parallel()

	en := getTranslations("en")
	fallback := getTranslations("fr")

	if !reflect.DeepEqual(en, fallback) {
		t.Error("unknown language code did not fall back to English bundle")
	}
}
