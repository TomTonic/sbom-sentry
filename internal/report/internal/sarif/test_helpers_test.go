package sarif

import (
	"time"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func makeTestReportData() ReportData {
	return ReportData{
		Input: model.InputSummary{
			Filename: "test.zip",
			Size:     1024,
			SHA256:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			SHA512:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Generator: buildinfo.Info{
			Version:  "v1.2.3",
			Revision: "0123456789abcdef",
			Time:     "2026-04-11T12:34:56Z",
			Modified: true,
		},
		Config: config.DefaultConfig(),
		Tree: &extract.ExtractionNode{
			Path:   "test.zip",
			Status: extract.StatusExtracted,
			Format: identify.FormatInfo{Format: identify.ZIP},
		},
		Scans:           []scan.ScanResult{},
		PolicyDecisions: []policy.Decision{},
		SandboxInfo: model.SandboxSummary{
			Name:      "passthrough",
			Available: true,
			UnsafeOvr: false,
		},
		StartTime: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2025, 1, 15, 10, 0, 5, 0, time.UTC),
		SBOMPath:  "/output/test.cdx.json",
	}
}
