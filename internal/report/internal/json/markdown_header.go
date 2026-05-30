package json

import (
	"runtime/debug"
	"strings"
	"time"
)

// MarkdownHeaderData contains precomputed, renderer-ready header metadata.
type MarkdownHeaderData struct {
	GeneratorDate string
	LinkedVersion string
	SyftVersion   string
	ToolParts     []string
}

// BuildMarkdownHeaderData prepares deterministic markdown header metadata.
func BuildMarkdownHeaderData(data ReportData, now time.Time) MarkdownHeaderData {
	syftVersion := syftVersionFromBuildInfo()
	if syftVersion == "" {
		syftVersion = "github.com/anchore/syft (unknown version)"
	}

	return MarkdownHeaderData{
		GeneratorDate: now.Format("2006-01-02 15:04:05"),
		LinkedVersion: "[" + data.Generator.Version + "](" + generatorGitHubURL(data.Generator.Version) + ")",
		SyftVersion:   syftVersion,
		ToolParts:     markdownToolParts(data),
	}
}

func markdownToolParts(data ReportData) []string {
	var toolParts []string
	if data.ToolVersions.Grype != "" {
		entry := data.ToolVersions.Grype
		if data.ToolVersions.GrypeDB != "" {
			entry += " (" + data.ToolVersions.GrypeDB + ")"
		}
		toolParts = append(toolParts, entry)
	}
	if data.ToolVersions.SevenZip != "" {
		toolParts = append(toolParts, data.ToolVersions.SevenZip)
	}
	if data.ToolVersions.Unshield != "" {
		toolParts = append(toolParts, data.ToolVersions.Unshield)
	}
	if data.ToolVersions.Unsquashfs != "" {
		toolParts = append(toolParts, data.ToolVersions.Unsquashfs)
	}
	return toolParts
}

func generatorGitHubURL(version string) string {
	const repoBase = "https://github.com/TomTonic/extract-sbom"
	v := strings.TrimSuffix(version, "+dirty")
	if idx := strings.LastIndex(v, "-"); idx != -1 {
		hash := v[idx+1:]
		if len(hash) >= 12 {
			return repoBase + "/commit/" + hash
		}
	}
	if strings.HasPrefix(v, "v") {
		return repoBase + "/releases/tag/" + v
	}
	return repoBase
}

func syftVersionFromBuildInfo() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return ""
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/anchore/syft" {
			return dep.Path + " " + dep.Version
		}
	}
	return ""
}
