// Package probe serves the feasibility fixture, not the production app API.
package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/srelens/extension-trivy/internal/scanner"
	"github.com/srelens/srelens/sdk/go/sidecar"
)

func New() *sidecar.Sidecar {
	s := sidecar.New("trivy-feasibility", "0.1.0")
	var once sync.Once
	var tempErr error
	scan := func(ctx context.Context, _ struct{}) (map[string]any, error) {
		data := sidecar.DataDir(ctx)
		if data == "" {
			return nil, fmt.Errorf("the host supplied no app data directory")
		}
		once.Do(func() {
			// Windows's default TEMP belongs to the AppContainer, rather than
			// the budgeted data root. Initialize Trivy's temp root explicitly.
			for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
				if err := os.Setenv(key, data); err != nil {
					tempErr = err
					return
				}
			}
		})
		if tempErr != nil {
			return nil, tempErr
		}
		report, err := scanner.ScanArchive(ctx, filepath.Join(data, "image.tar"), data)
		if err != nil {
			return nil, err
		}
		findings := []map[string]string{}
		for _, result := range report.Results {
			for _, finding := range result.Vulnerabilities {
				if len(findings) >= 100 {
					return nil, fmt.Errorf("the proof fixture exceeds its finding bound")
				}
				findings = append(findings, map[string]string{
					"target": result.Target, "id": finding.VulnerabilityID,
					"package": finding.PkgName, "installedVersion": finding.InstalledVersion,
					"fixedVersion": finding.FixedVersion, "severity": finding.Severity,
				})
			}
		}
		return map[string]any{
			"state": "completed", "engineVersion": report.Trivy.Version,
			"source":  "pinned-fixture",
			"imageId": report.Metadata.ImageID, "architecture": report.Metadata.ImageConfig.Architecture,
			"os": report.Metadata.ImageConfig.OS, "findings": findings,
		}, nil
	}
	// The existing installed-app tool interface serves ordinary requests. This
	// local preview accepts no image reference; production scans remain pending.
	sidecar.Operation(s, "scan-fixture", scan)
	sidecar.Stream(s, "scan", func(ctx context.Context, in struct{}, frames *sidecar.Frames) error {
		if err := frames.Send(map[string]string{"state": "scanning"}); err != nil {
			return err
		}
		report, err := scan(ctx, in)
		if err != nil {
			return err
		}
		return frames.Send(report)
	})
	return s
}
