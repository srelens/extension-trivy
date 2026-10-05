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
	sidecar.Stream(s, "scan", func(ctx context.Context, _ struct{}, frames *sidecar.Frames) error {
		data := sidecar.DataDir(ctx)
		if data == "" {
			return fmt.Errorf("the host supplied no app data directory")
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
			return tempErr
		}
		if err := frames.Send(map[string]string{"state": "scanning"}); err != nil {
			return err
		}
		report, err := scanner.ScanArchive(ctx, filepath.Join(data, "image.tar"), data)
		if err != nil {
			return err
		}
		findings := []map[string]string{}
		for _, result := range report.Results {
			for _, finding := range result.Vulnerabilities {
				if len(findings) >= 100 {
					return fmt.Errorf("the proof fixture exceeds its finding bound")
				}
				findings = append(findings, map[string]string{
					"target": result.Target, "id": finding.VulnerabilityID,
					"package": finding.PkgName, "installedVersion": finding.InstalledVersion,
					"fixedVersion": finding.FixedVersion, "severity": finding.Severity,
				})
			}
		}
		return frames.Send(map[string]any{
			"state": "completed", "engineVersion": report.Trivy.Version,
			"imageId": report.Metadata.ImageID, "architecture": report.Metadata.ImageConfig.Architecture,
			"os": report.Metadata.ImageConfig.OS, "findings": findings,
		})
	})
	return s
}
