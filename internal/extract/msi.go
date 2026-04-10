package extract

// This file implements MSI metadata extraction: reading the Property table
// from Microsoft Installer (OLE compound document) files to extract product
// metadata (Manufacturer, ProductName, ProductVersion, ProductCode,
// UpgradeCode, ProductLanguage) for SBOM enrichment and CPE generation.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/richardlehane/mscfb"
)

// msiPropertyNames lists the MSI Property table keys we extract for SBOM enrichment.
var msiPropertyNames = map[string]bool{
	"Manufacturer":    true,
	"ProductName":     true,
	"ProductVersion":  true,
	"ProductCode":     true,
	"UpgradeCode":     true,
	"ProductLanguage": true,
}

// ReadMSIMetadata reads the MSI Property table from an OLE compound document
// and returns the extracted metadata. It does not depend on 7-Zip and can be
// called even when payload extraction is unavailable.
//
// Parameters:
//   - path: filesystem path to the MSI file
//   - maxStreamSize: maximum number of bytes to read from each metadata stream
//
// Returns a ContainerMetadata populated with available properties, or an error
// if the file cannot be read or does not contain a valid MSI database.
func ReadMSIMetadata(path string, maxStreamSize int64) (*ContainerMetadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("msi: open %s: %w", path, err)
	}
	defer f.Close()

	doc, err := mscfb.New(f)
	if err != nil {
		return nil, fmt.Errorf("msi: open OLE document %s: %w", path, err)
	}

	// Locate the string pool and string data streams.
	stringPool, stringData, propertyTable, err := findMSIStreams(doc)
	if err != nil {
		return nil, err
	}

	// Parse the string pool.
	strings, err := parseMSIStringPool(stringPool, stringData, maxStreamSize)
	if err != nil {
		return nil, fmt.Errorf("msi: parse string pool: %w", err)
	}

	// Parse the Property table.
	props, err := parseMSIPropertyTable(propertyTable, strings, maxStreamSize)
	if err != nil {
		return nil, fmt.Errorf("msi: parse property table: %w", err)
	}

	meta := &ContainerMetadata{
		Manufacturer:   props["Manufacturer"],
		ProductName:    props["ProductName"],
		ProductVersion: props["ProductVersion"],
		ProductCode:    props["ProductCode"],
		UpgradeCode:    props["UpgradeCode"],
		Language:       props["ProductLanguage"],
	}

	return meta, nil
}

// findMSIStreams locates the required OLE streams for MSI metadata extraction.
func findMSIStreams(doc *mscfb.Reader) (stringPool io.Reader, stringData io.Reader, propertyTable io.Reader, err error) {
	var spoolEntry, sdataEntry, propEntry *mscfb.File

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		name := entry.Name
		switch {
		case isStreamName(name, "_StringPool"):
			spoolEntry = entry
		case isStreamName(name, "_StringData"):
			sdataEntry = entry
		case isStreamName(name, "_Property") || isPropertyTableStream(name):
			propEntry = entry
		}
	}

	if spoolEntry == nil {
		return nil, nil, nil, fmt.Errorf("msi: _StringPool stream not found")
	}
	if sdataEntry == nil {
		return nil, nil, nil, fmt.Errorf("msi: _StringData stream not found")
	}
	if propEntry == nil {
		return nil, nil, nil, fmt.Errorf("msi: Property table stream not found")
	}

	return spoolEntry, sdataEntry, propEntry, nil
}

// isStreamName checks if an OLE entry name matches a target MSI stream name.
// MSI stream names use a specific encoding where characters >= 0x3800 are
// used for base-64 encoding, and "!" prefix denotes special tables.
func isStreamName(name, target string) bool {
	// Direct match (some implementations use plain names).
	if name == target || name == "!"+target {
		return true
	}
	// Try decoding the MSI-encoded name.
	decoded := decodeMSIStreamName(name)
	return decoded == target || decoded == "!"+target
}

// isPropertyTableStream checks if a stream name corresponds to the Property table.
func isPropertyTableStream(name string) bool {
	decoded := decodeMSIStreamName(name)
	return decoded == "Property" || decoded == "!Property" ||
		decoded == "_Property" || decoded == "!_Property"
}

// decodeMSIStreamName decodes an MSI-encoded OLE stream name.
// MSI uses a custom encoding for table names in OLE streams where
// characters are mapped through a specific encoding scheme.
func decodeMSIStreamName(name string) string {
	if name == "" {
		return name
	}

	var result strings.Builder
	for _, r := range name {
		switch {
		case r >= 0x3800 && r < 0x4800:
			// MSI base-64 encoded character.
			decoded := r - 0x3800
			if decoded < 0x3F {
				switch {
				case decoded <= 0x09:
					result.WriteRune('0' + decoded)
				case decoded <= 0x23:
					result.WriteRune('A' + decoded - 0x0A)
				case decoded <= 0x3D:
					result.WriteRune('a' + decoded - 0x24)
				case decoded == 0x3E:
					result.WriteRune('_')
				}
			}
		case r >= 0x4800 && r < 0x4840:
			// Two-character encoding — fallback: keep as-is.
			result.WriteRune(r)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// parseMSIStringPool reads the MSI string pool from the _StringPool and
// _StringData streams. The string pool stores all strings referenced by
// table columns in the MSI database.
//
// _StringPool format: pairs of (uint16 length, uint16 refcount) for each string.
// _StringData format: concatenated UTF-8 string data, lengths from _StringPool.
func parseMSIStringPool(poolReader, dataReader io.Reader, maxStreamSize int64) ([]string, error) {
	poolData, err := readAllLimited(poolReader, maxStreamSize, "_StringPool")
	if err != nil {
		return nil, fmt.Errorf("read string pool: %w", err)
	}

	stringData, err := readAllLimited(dataReader, maxStreamSize, "_StringData")
	if err != nil {
		return nil, fmt.Errorf("read string data: %w", err)
	}

	if len(poolData) < 4 {
		return nil, fmt.Errorf("string pool too small: %d bytes", len(poolData))
	}

	// First 4 bytes are the string pool header (codepage info).
	// Skip them.
	poolData = poolData[4:]

	numStrings := len(poolData) / 4
	result := make([]string, 0, numStrings)
	offset := 0

	for i := 0; i < numStrings; i++ {
		if i*4+3 >= len(poolData) {
			break
		}
		strLen := int(binary.LittleEndian.Uint16(poolData[i*4 : i*4+2]))
		// refcount is at poolData[i*4+2 : i*4+4], we don't need it.

		if offset+strLen > len(stringData) {
			// Truncated data, add empty string.
			result = append(result, "")
			continue
		}

		s := string(stringData[offset : offset+strLen])
		result = append(result, s)
		offset += strLen
	}

	return result, nil
}

// parseMSIPropertyTable reads the Property table stream and returns a map
// of property name to value. The Property table has two columns, both
// string references (indices into the string pool).
func parseMSIPropertyTable(tableReader io.Reader, stringPool []string, maxStreamSize int64) (map[string]string, error) {
	data, err := readAllLimited(tableReader, maxStreamSize, "Property")
	if err != nil {
		return nil, fmt.Errorf("read property table: %w", err)
	}

	result := make(map[string]string)
	poolSize := len(stringPool)

	// Determine column width based on string pool size.
	// If the string pool has <= 0xFFFF entries, each column is 2 bytes.
	// Otherwise, each column is 4 bytes (long string indices).
	colWidth := 2
	if poolSize > 0xFFFF {
		colWidth = 4
	}

	rowSize := colWidth * 2

	if len(data) < rowSize {
		return result, nil
	}

	numRows := len(data) / rowSize

	for i := 0; i < numRows; i++ {
		rowOff := i * rowSize

		var nameIdx, valueIdx int
		if colWidth == 2 {
			nameIdx = int(binary.LittleEndian.Uint16(data[rowOff : rowOff+2]))
			valueIdx = int(binary.LittleEndian.Uint16(data[rowOff+2 : rowOff+4]))
		} else {
			nameIdx = int(binary.LittleEndian.Uint32(data[rowOff : rowOff+4]))
			valueIdx = int(binary.LittleEndian.Uint32(data[rowOff+4 : rowOff+8]))
		}

		// String indices are 1-based in MSI format.
		nameIdx--
		valueIdx--

		if nameIdx < 0 || nameIdx >= poolSize {
			continue
		}
		if valueIdx < 0 || valueIdx >= poolSize {
			continue
		}

		name := stringPool[nameIdx]
		value := stringPool[valueIdx]

		if msiPropertyNames[name] {
			result[name] = value
		}
	}

	return result, nil
}

func readAllLimited(reader io.Reader, maxBytes int64, streamName string) ([]byte, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("invalid read limit %d for stream %s", maxBytes, streamName)
	}

	limited := io.LimitReader(reader, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("stream %s exceeds limit of %d bytes", streamName, maxBytes)
	}

	return data, nil
}
