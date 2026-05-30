package json

import "sort"

const (
	// MarkdownRootMetadataSourceDerived marks derived metadata values.
	MarkdownRootMetadataSourceDerived = "derived"
	// MarkdownRootMetadataSourceSupplied marks user-supplied metadata values.
	MarkdownRootMetadataSourceSupplied = "supplied"
)

// MarkdownRootMetadataRow is one root-metadata table row for markdown rendering.
type MarkdownRootMetadataRow struct {
	FieldKey   string
	FieldValue string
	SourceCode string
}

// BuildMarkdownRootMetadataRows returns deterministic root metadata rows.
func BuildMarkdownRootMetadataRows(data ReportData) []MarkdownRootMetadataRow {
	rm := data.Config.RootMetadata
	rows := make([]MarkdownRootMetadataRow, 0, 4+len(rm.Properties))

	nameSource := MarkdownRootMetadataSourceDerived
	name := rm.Name
	if name == "" {
		name = data.Input.Filename
	} else {
		nameSource = MarkdownRootMetadataSourceSupplied
	}
	rows = append(rows, MarkdownRootMetadataRow{FieldKey: "name", FieldValue: name, SourceCode: nameSource})

	if rm.Manufacturer != "" {
		rows = append(rows, MarkdownRootMetadataRow{FieldKey: "manufacturer", FieldValue: rm.Manufacturer, SourceCode: MarkdownRootMetadataSourceSupplied})
	}
	if rm.Version != "" {
		rows = append(rows, MarkdownRootMetadataRow{FieldKey: "version", FieldValue: rm.Version, SourceCode: MarkdownRootMetadataSourceSupplied})
	}
	if rm.DeliveryDate != "" {
		rows = append(rows, MarkdownRootMetadataRow{FieldKey: "deliveryDate", FieldValue: rm.DeliveryDate, SourceCode: MarkdownRootMetadataSourceSupplied})
	}

	propertyKeys := make([]string, 0, len(rm.Properties))
	for key := range rm.Properties {
		propertyKeys = append(propertyKeys, key)
	}
	sort.Strings(propertyKeys)
	for i := range propertyKeys {
		rows = append(rows, MarkdownRootMetadataRow{FieldKey: propertyKeys[i], FieldValue: rm.Properties[propertyKeys[i]], SourceCode: MarkdownRootMetadataSourceSupplied})
	}

	return rows
}
