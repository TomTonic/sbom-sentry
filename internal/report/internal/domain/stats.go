package domain

import (
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// ExtractionStats summarizes extraction outcomes and relevant paths.
type ExtractionStats struct {
	Total                  int
	Extracted              int
	TotalFileEntries       int
	SyftNative             int
	Failed                 int
	Skipped                int
	ToolMissing            int
	SecurityBlocked        int
	Pending                int
	Other                  int
	ExtensionFiltered      int
	ExtensionFilteredPaths []string
	FailedPaths            []string
	ToolMissingPaths       []string
	SecurityBlockedPaths   []string
}

// ScanStats summarizes per-node scan outcomes and coverage gaps.
type ScanStats struct {
	Total            int
	Successful       int
	Errors           int
	TotalComponents  int
	NoComponentTasks int
	ErrorPaths       []string
	NoComponentPaths []string
}

// PolicyStats aggregates policy decisions for summary reporting.
type PolicyStats struct {
	Total    int
	Continue int
	Skip     int
	Abort    int
}

// CollectExtractionStats walks the extraction tree and aggregates status and
// path counters used by summary and residual-risk sections.
func CollectExtractionStats(node *extract.ExtractionNode) ExtractionStats {
	stats := ExtractionStats{}

	var walk func(n *extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}

		stats.Total++
		switch n.Status {
		case extract.StatusExtracted:
			stats.Extracted++
			stats.TotalFileEntries += n.EntriesCount
		case extract.StatusSyftNative:
			stats.SyftNative++
		case extract.StatusFailed:
			stats.Failed++
			stats.FailedPaths = append(stats.FailedPaths, n.Path)
		case extract.StatusSkipped:
			stats.Skipped++
		case extract.StatusToolMissing:
			stats.ToolMissing++
			stats.ToolMissingPaths = append(stats.ToolMissingPaths, n.Path)
		case extract.StatusSecurityBlocked:
			stats.SecurityBlocked++
			stats.SecurityBlockedPaths = append(stats.SecurityBlockedPaths, n.Path)
		case extract.StatusPending:
			stats.Pending++
		default:
			stats.Other++
		}

		stats.ExtensionFiltered += len(n.ExtensionFilteredPaths)
		stats.ExtensionFilteredPaths = append(stats.ExtensionFilteredPaths, n.ExtensionFilteredPaths...)

		for _, child := range n.Children {
			walk(child)
		}
	}

	walk(node)
	return stats
}

// CollectScanStats aggregates scan success/error counters and coverage hints.
func CollectScanStats(scans []scan.ScanResult) ScanStats {
	stats := ScanStats{Total: len(scans)}
	for _, sr := range scans {
		if sr.Error != nil {
			stats.Errors++
			stats.ErrorPaths = append(stats.ErrorPaths, sr.NodePath)
			continue
		}
		stats.Successful++
		componentCount := 0
		if sr.BOM != nil && sr.BOM.Components != nil {
			componentCount = len(*sr.BOM.Components)
			stats.TotalComponents += componentCount
		}
		if componentCount == 0 {
			stats.NoComponentTasks++
			stats.NoComponentPaths = append(stats.NoComponentPaths, sr.NodePath)
		}
	}
	return stats
}

// CollectPolicyStats aggregates policy-action counters for summary reporting.
func CollectPolicyStats(decisions []policy.Decision) PolicyStats {
	stats := PolicyStats{Total: len(decisions)}
	for _, d := range decisions {
		switch d.Action {
		case policy.ActionContinue:
			stats.Continue++
		case policy.ActionSkip:
			stats.Skip++
		case policy.ActionAbort:
			stats.Abort++
		}
	}
	return stats
}
