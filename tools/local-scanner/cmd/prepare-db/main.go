// Command prepare-db builds the development fixture DB. Never packaged.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: prepare-db <fixture-directory>")
		os.Exit(2)
	}
	if err := prepare(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepare(root string) error {
	dbDir := filepath.Join(root, "runtime", "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		return err
	}
	// Recreate this generated fixture rather than advancing Bolt transaction
	// IDs on each preparation; the binary DB digest is reproducible.
	if err := os.Remove(trivydb.Path(dbDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	loader, err := fixtures.New(trivydb.Path(dbDir), []string{
		filepath.Join(root, "db-source", "alpine.yaml"), filepath.Join(root, "db-source", "vulnerability.yaml"),
		filepath.Join(root, "db-source", "debian.yaml"),
	})
	if err != nil {
		return err
	}
	if err := loader.Load(); err != nil {
		loader.Close()
		return err
	}
	if err := loader.Close(); err != nil {
		return err
	}
	when := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return metadata.NewClient(dbDir).Update(metadata.Metadata{Version: 2, UpdatedAt: when, DownloadedAt: when, NextUpdate: when.Add(24 * time.Hour)})
}
