package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
)

// scanTask identifies one result slot to be processed by a worker.
type scanTask struct {
	resultIndex int
	ordinal     int
}

const (
	scanNativeProgressInterval         = 2 * time.Second
	scanNativeVerboseCompletionMinimum = 2 * time.Second
)

// scanProgressTracker aggregates native scan completion updates to avoid log
// flooding while still exposing progress over long-running deliveries.
type scanProgressTracker struct {
	mu                     sync.Mutex
	completed              int
	totalComponents        int
	lastReportedComponents int
	nextUpdate             time.Time
}

// newScanProgressTracker creates a tracker only for native scan batches.
func newScanProgressTracker(label string) *scanProgressTracker {
	if label != "scan-native" {
		return nil
	}

	return &scanProgressTracker{nextUpdate: time.Now().Add(scanNativeProgressInterval)}
}

// markCompleted records completion of one task and emits aggregated progress
// updates at bounded intervals.
func (tracker *scanProgressTracker) markCompleted(cfg config.Config, total int, components int) {
	if tracker == nil || total < 1 {
		return
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.completed++
	tracker.totalComponents += components
	now := time.Now()
	if tracker.completed < total && now.Before(tracker.nextUpdate) {
		return
	}

	delta := tracker.totalComponents - tracker.lastReportedComponents
	tracker.lastReportedComponents = tracker.totalComponents
	cfg.EmitProgress(config.ProgressNormal, "[scan-native] completed %d/%d tasks -> %s", tracker.completed, total, FormatComponentCount(delta))
	tracker.nextUpdate = now.Add(scanNativeProgressInterval)
}

// shouldLogScanCompletion controls per-task completion verbosity.
func shouldLogScanCompletion(label string, duration time.Duration) bool {
	return label != "scan-native" || duration >= scanNativeVerboseCompletionMinimum
}

// FormatComponentCount formats a component count for terminal output:
// 0 -> plain "0 components", 1 -> bold "1 component", N -> bold "N components".
func FormatComponentCount(n int) string {
	switch n {
	case 0:
		return "0 components"
	case 1:
		return "\033[1m1 component\033[0m"
	default:
		return fmt.Sprintf("\033[1m%d components\033[0m", n)
	}
}

// CountScannedComponents returns the total number of components found across
// all scan results. Results with errors contribute zero.
func CountScannedComponents(scans []ScanResult) int {
	total := 0
	for _, sr := range scans {
		if sr.BOM != nil && sr.BOM.Components != nil {
			total += len(*sr.BOM.Components)
		}
	}
	return total
}

// parallelScanIndices executes scanNode across a fixed index subset while
// preserving result-slot ownership.
func parallelScanIndices(ctx context.Context, root *extract.ExtractionNode, results []ScanResult, indices []int, numWorkers int, cfg config.Config, label string) {
	workQueue := make(chan scanTask, len(indices))
	var wg sync.WaitGroup
	progressTracker := newScanProgressTracker(label)

	for worker := 0; worker < numWorkers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-workQueue:
					if !ok {
						return
					}

					nodePath := results[task.resultIndex].NodePath

					start := time.Now()
					done := make(chan struct{})
					if cfg.ProgressLevel >= config.ProgressNormal {
						go func(ordinal int, total int, currentNodePath string) {
							ticker := time.NewTicker(15 * time.Second)
							defer ticker.Stop()
							for {
								select {
								case <-done:
									return
								case <-ctx.Done():
									return
								case <-ticker.C:
									cfg.EmitProgress(config.ProgressNormal, "[%s] task %d/%d still running: %s", label, ordinal, total, currentNodePath)
								}
							}
						}(task.ordinal, len(indices), nodePath)
					}

					scanNode(ctx, &results[task.resultIndex], root)
					close(done)

					duration := time.Since(start).Round(time.Millisecond)
					componentCount := 0
					if results[task.resultIndex].Error == nil && results[task.resultIndex].BOM != nil && results[task.resultIndex].BOM.Components != nil {
						componentCount = len(*results[task.resultIndex].BOM.Components)
					}
					progressTracker.markCompleted(cfg, len(indices), componentCount)
					if results[task.resultIndex].Error != nil {
						cfg.EmitProgress(config.ProgressNormal, "[%s] task %d/%d failed after %s: %s (%v)", label, task.ordinal, len(indices), duration, nodePath, results[task.resultIndex].Error)
						continue
					}
					if shouldLogScanCompletion(label, duration) {
						cfg.EmitProgress(config.ProgressVerbose, "[%s] task %d/%d done in %s: %s -> %s", label, task.ordinal, len(indices), duration, nodePath, FormatComponentCount(componentCount))
					}
				}
			}
		}()
	}

	for ordinal, idx := range indices {
		workQueue <- scanTask{resultIndex: idx, ordinal: ordinal + 1}
	}
	close(workQueue)

	wg.Wait()
}
