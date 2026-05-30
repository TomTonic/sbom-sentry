package markdown

import (
	"testing"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
)

func TestCollectSuppressionStats(t *testing.T) {
	t.Parallel()

	records := []assembly.SuppressionRecord{
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionLowValueFile},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionPURLDuplicate},
	}

	stats := domain.CollectSuppressionStats(records)
	if stats.FSArtifacts != 2 {
		t.Errorf("FSArtifacts = %d, want 2", stats.FSArtifacts)
	}
	if stats.LowValueFiles != 1 {
		t.Errorf("LowValueFiles = %d, want 1", stats.LowValueFiles)
	}
	if stats.WeakDuplicate != 3 {
		t.Errorf("WeakDuplicate = %d, want 3", stats.WeakDuplicate)
	}
	if stats.PURLDuplicate != 1 {
		t.Errorf("PURLDuplicate = %d, want 1", stats.PURLDuplicate)
	}
}

func TestCollectSuppressionStatsEmpty(t *testing.T) {
	t.Parallel()
	stats := domain.CollectSuppressionStats(nil)
	if stats.FSArtifacts != 0 || stats.LowValueFiles != 0 || stats.WeakDuplicate != 0 || stats.PURLDuplicate != 0 {
		t.Fatal("empty input should produce zero stats")
	}
}
