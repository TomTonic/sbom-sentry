package domain

import "github.com/TomTonic/extract-sbom/internal/assembly"

// SuppressionStats groups suppression records by reason.
type SuppressionStats struct {
	FSArtifacts   int
	LowValueFiles int
	WeakDuplicate int
	PURLDuplicate int
}

// CollectSuppressionStats groups suppression records by suppression reason.
func CollectSuppressionStats(suppressions []assembly.SuppressionRecord) SuppressionStats {
	stats := SuppressionStats{}
	for i := range suppressions {
		switch suppressions[i].Reason {
		case assembly.SuppressionFSArtifact:
			stats.FSArtifacts++
		case assembly.SuppressionLowValueFile:
			stats.LowValueFiles++
		case assembly.SuppressionWeakDuplicate:
			stats.WeakDuplicate++
		case assembly.SuppressionPURLDuplicate:
			stats.PURLDuplicate++
		}
	}
	return stats
}
