package scan

import (
	"runtime/debug"
	"sync"
)

const defaultSyftVersion = "dev"

// Version reports the Syft library version used by extract-sbom.
// It is surfaced in assembly metadata as the generator tool version.
var Version = detectSyftVersion()

// syftGetSourceMu serializes syft.GetSource() calls to avoid races in
// upstream stereoscope temp-dir generator initialization under parallel scans.
var syftGetSourceMu sync.Mutex

func detectSyftVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return defaultSyftVersion
	}

	for _, dep := range buildInfo.Deps {
		if dep.Path != "github.com/anchore/syft" {
			continue
		}

		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		if dep.Version != "" {
			return dep.Version
		}
	}

	return defaultSyftVersion
}
