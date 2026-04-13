package extract

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadMSIMetadataReturnsErrorForNonOLEFile verifies that reading MSI
// metadata from a non-OLE file produces a clear error rather than panicking.
func TestReadMSIMetadataReturnsErrorForNonOLEFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fakePath := filepath.Join(dir, "fake.msi")
	if err := os.WriteFile(fakePath, []byte("not an MSI file"), 0o600); err != nil {
		t.Fatal(err)
	}

	meta, err := ReadMSIMetadata(fakePath, 1024)
	if err == nil {
		t.Error("expected error for non-OLE file, got nil")
	}
	if meta != nil {
		t.Error("expected nil metadata for non-OLE file")
	}
}

// TestReadMSIMetadataReturnsErrorForMissingFile verifies that a missing
// file produces a clear error.
func TestReadMSIMetadataReturnsErrorForMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ReadMSIMetadata("/nonexistent/file.msi", 1024)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestDecodeMSIStreamNamePassthrough verifies that plain ASCII names
// pass through unchanged.
func TestDecodeMSIStreamNamePassthrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"_StringPool", "_StringPool"},
		{"!_StringData", "!_StringData"},
		{"Property", "Property"},
		{"SummaryInformation", "SummaryInformation"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := decodeMSIStreamName(tt.input)
			if got != tt.want {
				t.Errorf("decodeMSIStreamName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDecodeMSIStreamNameEncoded verifies that MSI-encoded OLE stream names
// are correctly decoded. These encoded names are produced by msitools/wixl
// using the standard MSI database encoding (two-char packed in U+3800..U+47FF,
// single-char in U+4800..U+483F, table prefix U+4840).
func TestDecodeMSIStreamNameEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "StringPool",
			input: "\u4840\u3F3F\u4577\u446C\u3E6A\u44B2\u482F",
			want:  "!_StringPool",
		},
		{
			name:  "StringData",
			input: "\u4840\u3F3F\u4577\u446C\u3B6A\u45E4\u4824",
			want:  "!_StringData",
		},
		{
			name:  "Property",
			input: "\u4840\u4559\u44F2\u4568\u4737",
			want:  "!Property",
		},
		{
			name:  "File",
			input: "\u4840\u430F\u422F",
			want:  "!File",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := decodeMSIStreamName(tt.input)
			if got != tt.want {
				t.Errorf("decodeMSIStreamName(encoded %s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// TestParseMSIStringPoolEmptyInput verifies that an empty or minimal
// string pool is handled gracefully.
func TestParseMSIStringPoolEmptyInput(t *testing.T) {
	t.Parallel()

	// Pool with just the 4-byte header, no strings.
	poolData := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00})
	stringData := bytes.NewReader([]byte{})

	result, err := parseMSIStringPool(poolData, stringData, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 strings, got %d", len(result))
	}
}

// TestParseMSIStringPoolTooSmall verifies that a string pool smaller
// than the header is rejected.
func TestParseMSIStringPoolTooSmall(t *testing.T) {
	t.Parallel()

	poolData := bytes.NewReader([]byte{0x00, 0x00})
	stringData := bytes.NewReader([]byte{})

	_, err := parseMSIStringPool(poolData, stringData, 1024)
	if err == nil {
		t.Error("expected error for pool too small, got nil")
	}
}

// TestParseMSIStringPoolRejectsOversizedStreams verifies that metadata parsing
// enforces a hard byte limit per MSI stream to avoid unbounded memory use.
func TestParseMSIStringPoolRejectsOversizedStreams(t *testing.T) {
	t.Parallel()

	poolData := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00})
	stringData := bytes.NewReader([]byte("A"))

	if _, err := parseMSIStringPool(poolData, stringData, 4); err == nil {
		t.Fatal("expected oversized _StringPool stream to be rejected")
	}
}

// TestParseMSIPropertyTableRejectsOversizedStream verifies that Property table
// parsing is bounded by the configured stream limit.
func TestParseMSIPropertyTableRejectsOversizedStream(t *testing.T) {
	t.Parallel()

	tableData := bytes.NewReader([]byte{0x01, 0x00, 0x02, 0x00})
	if _, err := parseMSIPropertyTable(tableData, []string{"Name", "Value"}, 2); err == nil {
		t.Fatal("expected oversized Property stream to be rejected")
	}
}

// TestMSIPropertyNamesContainsRequiredKeys verifies that all
// design-specified MSI properties are in the lookup map.
func TestMSIPropertyNamesContainsRequiredKeys(t *testing.T) {
	t.Parallel()

	required := []string{
		"Manufacturer",
		"ProductName",
		"ProductVersion",
		"ProductCode",
		"UpgradeCode",
		"ProductLanguage",
	}

	for _, key := range required {
		if !msiPropertyNames[key] {
			t.Errorf("msiPropertyNames missing required key %q", key)
		}
	}
}

// TestIsStreamNameMatchesDirectAndEncoded verifies that stream name
// matching works for both direct names and encoded variants.
func TestIsStreamNameMatchesDirectAndEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"_StringPool", "_StringPool", true},
		{"!_StringPool", "_StringPool", true},
		{"_StringData", "_StringData", true},
		{"Other", "_StringPool", false},
		// Encoded stream names from wixl/msitools (two-char packed encoding).
		{"\u4840\u3F3F\u4577\u446C\u3E6A\u44B2\u482F", "_StringPool", true},
		{"\u4840\u3F3F\u4577\u446C\u3B6A\u45E4\u4824", "_StringData", true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"->"+tt.target, func(t *testing.T) {
			t.Parallel()
			got := isStreamName(tt.name, tt.target)
			if got != tt.want {
				t.Errorf("isStreamName(%q, %q) = %v, want %v", tt.name, tt.target, got, tt.want)
			}
		})
	}
}

// TestParseMSIStringPoolWithStrings verifies that a well-formed string pool
// correctly extracts strings with proper offsets.
func TestParseMSIStringPoolWithStrings(t *testing.T) {
	t.Parallel()

	// Header: 4 bytes (codepage, ignored)
	// Entry 0: length=5, refcount=1 → "Hello"
	// Entry 1: length=5, refcount=1 → "World"
	pool := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x05, 0x00, 0x01, 0x00, // entry 0: length=5, refcount=1
		0x05, 0x00, 0x01, 0x00, // entry 1: length=5, refcount=1
	}
	data := []byte("HelloWorld")

	result, err := parseMSIStringPool(
		bytes.NewReader(pool),
		bytes.NewReader(data),
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d strings, want 2", len(result))
	}
	if result[0] != "Hello" {
		t.Errorf("string[0] = %q, want %q", result[0], "Hello")
	}
	if result[1] != "World" {
		t.Errorf("string[1] = %q, want %q", result[1], "World")
	}
}

// TestParseMSIStringPoolTruncatedData verifies that truncated string data
// results in empty strings rather than a panic.
func TestParseMSIStringPoolTruncatedData(t *testing.T) {
	t.Parallel()

	pool := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x0A, 0x00, 0x01, 0x00, // entry 0: length=10 but data only has 3 bytes
	}
	data := []byte("abc")

	result, err := parseMSIStringPool(
		bytes.NewReader(pool),
		bytes.NewReader(data),
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d strings, want 1", len(result))
	}
	if result[0] != "" {
		t.Errorf("truncated entry should be empty, got %q", result[0])
	}
}

// TestParseMSIPropertyTableWithValidData verifies end-to-end parsing of a
// minimal Property table.
func TestParseMSIPropertyTableWithValidData(t *testing.T) {
	t.Parallel()

	// String pool (1-based index): 1="Manufacturer", 2="Acme Corp",
	// 3="ProductName", 4="Widget"
	pool := []string{"", "Manufacturer", "Acme Corp", "ProductName", "Widget"}

	// Two rows, colWidth=2, column-major: [name₀, name₁ | value₀, value₁]
	data := []byte{
		0x02, 0x00, // name₀ = 2 → pool[1] = "Manufacturer"
		0x04, 0x00, // name₁ = 4 → pool[3] = "ProductName"
		0x03, 0x00, // value₀ = 3 → pool[2] = "Acme Corp"
		0x05, 0x00, // value₁ = 5 → pool[4] = "Widget"
	}

	result, err := parseMSIPropertyTable(
		bytes.NewReader(data),
		pool,
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["Manufacturer"] != "Acme Corp" {
		t.Errorf("Manufacturer = %q, want %q", result["Manufacturer"], "Acme Corp")
	}
	if result["ProductName"] != "Widget" {
		t.Errorf("ProductName = %q, want %q", result["ProductName"], "Widget")
	}
}

// TestParseMSIPropertyTableEmpty verifies that an empty Property table
// returns an empty map without error.
func TestParseMSIPropertyTableEmpty(t *testing.T) {
	t.Parallel()

	result, err := parseMSIPropertyTable(
		bytes.NewReader([]byte{}),
		[]string{""},
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

// TestParseMSIPropertyTableOutOfBoundsIndices verifies that property rows
// with out-of-bounds string indices are silently skipped.
func TestParseMSIPropertyTableOutOfBoundsIndices(t *testing.T) {
	t.Parallel()

	pool := []string{"", "Manufacturer", "Acme"}

	// One row where value index is out of bounds.
	data := []byte{
		0x02, 0x00, // name = 2 → pool[1] = "Manufacturer"
		0xFF, 0x00, // value = 255 → out of bounds
	}

	result, err := parseMSIPropertyTable(
		bytes.NewReader(data),
		pool,
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result["Manufacturer"]; ok {
		t.Error("expected out-of-bounds row to be skipped")
	}
}

// TestIsPropertyTableStreamVariants verifies all known Property table name variants.
func TestIsPropertyTableStreamVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{"Property", true},
		{"!Property", true},
		{"_Property", true},
		{"!_Property", true},
		{"Other", false},
		{"", false},
		{"\u4840\u4559\u44F2\u4568\u4737", true}, // encoded "!Property"
	}

	for _, tt := range tests {
		got := isPropertyTableStream(tt.name)
		if got != tt.want {
			t.Errorf("isPropertyTableStream(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestDecodeMSICharAllRanges verifies decodeMSIChar covers all value ranges.
func TestDecodeMSICharAllRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input rune
		want  rune
	}{
		{0, '0'},
		{9, '9'},
		{10, 'A'},
		{35, 'Z'},
		{36, 'a'},
		{61, 'z'},
		{62, '.'},
		{63, '_'},
		{100, '_'},
	}

	for _, tt := range tests {
		got := decodeMSIChar(tt.input)
		if got != tt.want {
			t.Errorf("decodeMSIChar(%d) = %c, want %c", tt.input, got, tt.want)
		}
	}
}

// TestReadAllLimitedInvalidLimit verifies that a zero or negative limit
// returns an error.
func TestReadAllLimitedInvalidLimit(t *testing.T) {
	t.Parallel()

	_, err := readAllLimited(bytes.NewReader([]byte("data")), 0, "test")
	if err == nil {
		t.Error("expected error for zero limit")
	}

	_, err = readAllLimited(bytes.NewReader([]byte("data")), -1, "test")
	if err == nil {
		t.Error("expected error for negative limit")
	}
}

// TestReadAllLimitedAcceptsExactSize verifies that data exactly at the
// limit is accepted.
func TestReadAllLimitedAcceptsExactSize(t *testing.T) {
	t.Parallel()

	data, err := readAllLimited(bytes.NewReader([]byte("abcd")), 4, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "abcd" {
		t.Errorf("data = %q, want %q", string(data), "abcd")
	}
}
