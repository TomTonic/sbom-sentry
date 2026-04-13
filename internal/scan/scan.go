// Package scan invokes Syft in library mode to catalog software components.
//
// It operates on two node classes from the extraction tree:
// - syft-native leaves: Syft scans the original file path
// - extracted containers: Syft scans the extraction output directory
//
// Implementation files are responsibility-focused:
// - types.go: result model and package-level shared state
// - scan_flow.go: target discovery and phase orchestration
// - scan_parallel.go: worker execution and progress reporting
// - scan_reuse.go: package attribution and native-result reuse
// - scan_syft.go: Syft invocation and CycloneDX conversion
// - evidence.go: deterministic evidence-path derivation helpers
package scan
