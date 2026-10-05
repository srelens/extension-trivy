package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

var testDataRoot string

func TestMain(m *testing.M) {
	var err error
	testDataRoot, err = os.MkdirTemp("", "trivy-test-app-")
	if err != nil {
		panic(err)
	}
	// Trivy caches its temp directory once per process, just as one sidecar
	// process owns one app data directory for its entire lifetime.
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		if err := os.Setenv(key, testDataRoot); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	if err := os.RemoveAll(testDataRoot); err != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

func TestScanArchiveOffline(t *testing.T) {
	data, archive := fixture(t)
	report, err := ScanArchive(context.Background(), archive, data)
	if err != nil {
		t.Fatal(err)
	}
	if report.Trivy.Version != "0.75.0+srelens.2" || report.Metadata.ImageID != "sha256:055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1" {
		t.Fatalf("scanner/image identity missing or wrong: %#v, %s", report.Trivy, report.Metadata.ImageID)
	}
	// A CVE can affect multiple packages. Neither occurrence may disappear.
	packages := map[string]bool{}
	for _, result := range report.Results {
		for _, finding := range result.Vulnerabilities {
			if finding.VulnerabilityID == "CVE-2019-1549" && finding.InstalledVersion == "1.1.1b-r1" && finding.FixedVersion == "1.1.1d-r0" {
				packages[finding.PkgName] = true
			}
		}
	}
	if !packages["libcrypto1.1"] || !packages["libssl1.1"] {
		t.Fatalf("known vulnerable package occurrences missing: %v", packages)
	}
	meta, err := metadata.NewClient(filepath.Join(data, "db")).Get()
	if err != nil || meta.Version != 2 || meta.UpdatedAt.IsZero() {
		t.Fatalf("DB identity missing: %#v, %v", meta, err)
	}
}

func TestUnsupportedIsNotClean(t *testing.T) {
	data, _ := fixture(t)
	archive := filepath.Join(data, "unsupported.tar")
	tag, err := name.NewTag("example.invalid/empty:fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(archive, tag, empty.Image); err != nil {
		t.Fatal(err)
	}
	report, err := ScanArchive(context.Background(), archive, data)
	if !errors.Is(err, ErrUnsupported) || len(report.Results) != 0 {
		t.Fatalf("empty/unsupported image was treated as a clean scan: %#v, %v", report.Results, err)
	}
}

func TestUnsupportedOSWithoutPackagesIsNotClean(t *testing.T) {
	data, _ := fixture(t)
	archive := smallAlpine(t, data, false)
	report, err := ScanArchive(context.Background(), archive, data)
	if !errors.Is(err, ErrUnsupported) || len(report.Results) != 0 {
		t.Fatalf("a detected OS without package inventory was treated as clean: %#v, %v", report.Results, err)
	}
}

func TestScanArchiveSupportedZeroFindings(t *testing.T) {
	data, _ := fixture(t)
	archive := smallAlpine(t, data, true)
	report, err := ScanArchive(context.Background(), archive, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 || len(report.Results[0].Packages) == 0 {
		t.Fatal("supported package inventory disappeared")
	}
	for _, result := range report.Results {
		if len(result.Vulnerabilities) != 0 {
			t.Fatalf("benign package fixture has findings: %#v", result.Vulnerabilities)
		}
	}
}

func smallAlpine(t *testing.T, data string, inventory bool) string {
	t.Helper()
	files := map[string]string{"etc/os-release": "ID=alpine\nVERSION_ID=3.9.4\n", "etc/alpine-release": "3.9.4\n"}
	if inventory {
		files["lib/apk/db/installed"] = "P:fixture-package\nV:1.0-r0\nA:x86_64\no:fixture-package\nL:MIT\n\n"
	}
	var contents bytes.Buffer
	tw := tar.NewWriter(&contents)
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: path, Size: int64(len(content)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(&contents)
	if err != nil {
		t.Fatal(err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag("example.invalid/alpine:fixture")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(data, "small-alpine.tar")
	if err := tarball.WriteToFile(archive, tag, image); err != nil {
		t.Fatal(err)
	}
	return archive
}

func TestCancelledScanStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	report, err := ScanArchive(ctx, "missing.tar", t.TempDir())
	if !errors.Is(err, context.Canceled) || len(report.Results) != 0 {
		t.Fatalf("cancelled scan produced a result: %#v, %v", report.Results, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("pre-cancelled scan did not stop promptly")
	}
}

func TestScanArchiveRefusesOutsideAndSymlink(t *testing.T) {
	data := t.TempDir()
	outside := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(outside, []byte("not an image"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("outside", func(t *testing.T) {
		_, err := ScanArchive(context.Background(), outside, data)
		if !errors.Is(err, ErrOutsideData) {
			t.Fatalf("outside path not refused: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(data, "image.tar")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		_, err := ScanArchive(context.Background(), link, data)
		if !errors.Is(err, ErrOutsideData) {
			t.Fatalf("symlink escape not refused: %v", err)
		}
	})
	t.Run("symlink parent inside data", func(t *testing.T) {
		actual := filepath.Join(data, "actual")
		if err := os.Mkdir(actual, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(actual, "image.tar"), []byte("not an image"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(data, "linked")
		if err := os.Symlink(actual, link); err != nil {
			t.Fatal(err)
		}
		_, err := ScanArchive(context.Background(), filepath.Join(link, "image.tar"), data)
		if !errors.Is(err, ErrOutsideData) {
			t.Fatalf("symlink parent not refused: %v", err)
		}
	})
}

func fixture(t *testing.T) (string, string) {
	t.Helper()
	source := filepath.Join("..", "..", ".fixtures")
	for file, digest := range map[string]string{
		"alpine-39.tar":                "24e9cea338601b1ed9422f3a6e9bfe2235a45588d53c34f2c9606098bcf5b1a5",
		"db-source/alpine.yaml":        "e8454df110f7d75d368e5b4d2c9581eb3ee5c6c3118fc698d6fd824ec2573a34",
		"db-source/vulnerability.yaml": "b8167a98a187774a3944c9f63e77685bd9f38f1ec2c75c48cb00eead4707cdc4",
	} {
		bytes, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(file)))
		if err != nil {
			t.Fatalf("prepare offline fixtures first (scripts/prepare_fixtures.py): %v", err)
		}
		sum := sha256.Sum256(bytes)
		if hex.EncodeToString(sum[:]) != digest {
			t.Fatalf("fixture %s has the wrong SHA-256", file)
		}
	}
	data := testDataRoot
	dbDir := filepath.Join(data, "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	loader, err := fixtures.New(trivydb.Path(dbDir), []string{filepath.Join(source, "db-source", "alpine.yaml"), filepath.Join(source, "db-source", "vulnerability.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	if err := loader.Close(); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := metadata.NewClient(dbDir).Update(metadata.Metadata{Version: 2, UpdatedAt: when, DownloadedAt: when, NextUpdate: when.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(data, "image.tar")
	in, err := os.Open(filepath.Join(source, "alpine-39.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return data, archive
}
