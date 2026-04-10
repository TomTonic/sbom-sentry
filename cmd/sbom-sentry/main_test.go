package main

import (
	"testing"
)

// TestParseKeyValue verifies key=value parsing for root properties.
func TestParseKeyValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
		wantOK  bool
	}{
		// Valid cases
		{
			name:    "simple key=value",
			input:   "foo=bar",
			wantKey: "foo",
			wantVal: "bar",
			wantOK:  true,
		},
		{
			name:    "key with multiple equals signs",
			input:   "key=value=with=equals",
			wantKey: "key",
			wantVal: "value=with=equals",
			wantOK:  true,
		},
		{
			name:    "empty value is valid",
			input:   "key=",
			wantKey: "key",
			wantVal: "",
			wantOK:  true,
		},
		{
			name:    "alphanumeric key and value",
			input:   "my_key123=my_value456",
			wantKey: "my_key123",
			wantVal: "my_value456",
			wantOK:  true,
		},
		{
			name:    "value with special characters",
			input:   "key=value-with_special.chars@123",
			wantKey: "key",
			wantVal: "value-with_special.chars@123",
			wantOK:  true,
		},

		// Invalid cases
		{
			name:    "no equals sign",
			input:   "foobar",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "equals sign at start",
			input:   "=value",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "only equals sign",
			input:   "=",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
		{
			name:    "empty string",
			input:   "",
			wantKey: "",
			wantVal: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotVal, gotOK := parseKeyValue(tt.input)
			if gotKey != tt.wantKey || gotVal != tt.wantVal || gotOK != tt.wantOK {
				t.Errorf("parseKeyValue(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.input, gotKey, gotVal, gotOK, tt.wantKey, tt.wantVal, tt.wantOK)
			}
		})
	}
}

// TestRootCmdStructure verifies that rootCmd returns a properly configured cobra.Command.
func TestRootCmdStructure(t *testing.T) {
	t.Parallel()

	cmd := rootCmd()

	tests := []struct {
		name      string
		condition bool
		message   string
	}{
		{"has Use", cmd.Use != "", "rootCmd should have Use"},
		{"has Short", cmd.Short != "", "rootCmd should have Short description"},
		{"has Long", cmd.Long != "", "rootCmd should have Long description"},
		{"has RunE", cmd.RunE != nil, "rootCmd should have RunE callback"},
		{"requires args", cmd.Args != nil, "rootCmd should specify argument requirements"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.condition {
				t.Error(tt.message)
			}
		})
	}
}

// TestRootCmdFlagsExist verifies that all expected flags are registered.
func TestRootCmdFlagsExist(t *testing.T) {
	t.Parallel()

	cmd := rootCmd()
	flags := cmd.Flags()

	expectedFlags := []string{
		"config",
		"output-dir",
		"work-dir",
		"format",
		"policy",
		"mode",
		"report",
		"language",
		"root-manufacturer",
		"root-name",
		"root-version",
		"root-delivery-date",
		"root-property",
		"unsafe",
		"max-depth",
		"max-files",
		"max-size",
		"max-entry-size",
		"max-ratio",
		"timeout",
	}

	for _, flagName := range expectedFlags {
		t.Run(flagName, func(t *testing.T) {
			flag := flags.Lookup(flagName)
			if flag == nil {
				t.Errorf("flag %q not found", flagName)
			}
		})
	}
}
