// Package scanner is the offline, in-process Trivy adapter.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	ErrUnsupported = errors.New("the image has no supported package inventory")
	ErrOutsideData = errors.New("the artifact is outside the app data directory or is a symlink")
)

const Version = "0.75.0+srelens.2"

// Trivy's vulnerability DB is process-global. Only one runner may own it.
var scanSlot = make(chan struct{}, 1)

// ScanArchive scans a broker-prepared Docker image archive using a DB already
// present in dbDir/db. dbDir is the app's private data root. The launcher must
// also point the process's temporary directory at this root. This function
// never fetches artifacts or starts another program.
func ScanArchive(ctx context.Context, archivePath, dbDir string) (types.Report, error) {
	if err := ctx.Err(); err != nil {
		return types.Report{}, err
	}
	select {
	case scanSlot <- struct{}{}:
		defer func() { <-scanSlot }()
	case <-ctx.Done():
		return types.Report{}, ctx.Err()
	}
	root, err := filepath.EvalSymlinks(dbDir)
	if err != nil {
		return types.Report{}, fmt.Errorf("open app data: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return types.Report{}, err
	}
	archive, err := scopedFile(dbDir, archivePath)
	if err != nil {
		return types.Report{}, err
	}
	for _, file := range []string{"db/trivy.db", "db/metadata.json"} {
		if _, err := scopedFile(root, filepath.Join(root, file)); err != nil {
			return types.Report{}, fmt.Errorf("open vulnerability database: %w", err)
		}
	}
	// A fresh empty directory prevents loading modules from the data root.
	modules, err := os.MkdirTemp(root, "scanner-modules-")
	if err != nil {
		return types.Report{}, err
	}
	defer os.RemoveAll(modules)
	opts := flag.Options{
		AppVersion:           Version,
		GlobalOptions:        flag.GlobalOptions{CacheDir: root, Quiet: true, Timeout: 5 * time.Minute},
		CacheOptions:         flag.CacheOptions{CacheBackend: "fs"},
		DBOptions:            flag.DBOptions{SkipDBUpdate: true, SkipJavaDBUpdate: true, NoProgress: true},
		ImageOptions:         flag.ImageOptions{Input: archive},
		ModuleOptions:        flag.ModuleOptions{ModuleDir: modules},
		VulnerabilityOptions: flag.VulnerabilityOptions{VulnSeveritySources: []dbtypes.SourceID{"auto"}},
		PackageOptions:       flag.PackageOptions{PkgTypes: types.PkgTypes, PkgRelationships: ftypes.Relationships},
		ScanOptions: flag.ScanOptions{
			Scanners:    types.Scanners{types.VulnerabilityScanner},
			OfflineScan: true, Parallel: 1, SkipVersionCheck: true, DisableTelemetry: true,
		},
	}
	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetContainerImage)
	if err != nil {
		return types.Report{}, fmt.Errorf("initialize offline scanner: %w", err)
	}
	defer runner.Close(ctx)
	report, err := runner.ScanImage(ctx, opts)
	if err != nil {
		return types.Report{}, fmt.Errorf("scan image archive: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return types.Report{}, err
	}
	var inventory, osInventory bool
	for _, result := range report.Results {
		if len(result.Packages) > 0 {
			inventory = true
			if result.Class == types.ClassOSPkg {
				osInventory = true
			}
		}
	}
	if !inventory || (report.Metadata.OS != nil && report.Metadata.OS.Family.HasOSPackages() && !osInventory) {
		return types.Report{}, ErrUnsupported
	}
	// The imported library defaults to "dev" outside its own CLI build.
	report.Trivy.Version = Version
	return report, nil
}

func scopedFile(root, filename string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	filename, err = filepath.Abs(filename)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, filename)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", ErrOutsideData
	}
	path := root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", ErrOutsideData
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", ErrOutsideData
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return "", ErrOutsideData
		}
	}
	// Resolve only the trusted root's system aliases after checking every
	// app-relative component. The production broker must also freeze inputs;
	// the OS sandbox remains the enforcement against concurrent replacement.
	return filepath.EvalSymlinks(filename)
}
