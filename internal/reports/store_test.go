package reports

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reportFor(n int, cluster string) Report {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s/%d", cluster, n))))
	return Report{Metadata: Metadata{ID: id, ClusterID: cluster, Source: "app", State: "completed", Category: "vulnerabilities", Namespace: "default", Freshness: "current", FindingCount: 205}, Findings: make([]Finding, 205)}
}

func TestStoredReportsPinOwnershipAndPaginateOccurrences(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, err := NewStore(root, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	r := reportFor(1, "production")
	for i := range r.Findings {
		r.Findings[i] = Finding{ID: "CVE-same", Target: fmt.Sprint(i), FixedVersion: "2.0"}
	}
	if err = s.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	page, err := s.Findings(ctx, "production", r.Metadata.ID, "", 100)
	if err != nil || len(page.Items) != 100 || page.NextCursor == "" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	second, err := s.Findings(ctx, "production", r.Metadata.ID, page.NextCursor, 100)
	if err != nil || second.Items[0].Target != "100" {
		t.Fatalf("second page: %+v %v", second, err)
	}
	last, err := s.Findings(ctx, "production", r.Metadata.ID, second.NextCursor, 100)
	if err != nil || len(last.Items) != 5 || last.NextCursor != "" {
		t.Fatalf("last page: %+v %v", last, err)
	}
	for _, limit := range []int{0, -1, 101} {
		if _, err = s.Findings(ctx, "production", r.Metadata.ID, "", limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
	if _, err = s.Findings(ctx, "staging", r.Metadata.ID, "", 100); err == nil {
		t.Fatal("cross-cluster report read")
	}
	other := reportFor(2, "production")
	if err = s.Save(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Findings(ctx, "production", other.Metadata.ID, page.NextCursor, 100); err == nil {
		t.Fatal("cross-report cursor")
	}
	if _, err = s.Findings(ctx, "production", "../outside", "", 100); err == nil {
		t.Fatal("path traversal")
	}
	rows, err := s.List(ctx, "production", nil, "")
	if err != nil || len(rows) != 2 {
		t.Fatalf("list: %v %v", rows, err)
	}
	ns := "another"
	rows, err = s.List(ctx, "production", &ns, "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("namespace: %v %v", rows, err)
	}
}

func TestRetentionBudgetAndCancellationPreserveExistingReports(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 11; i++ {
		if err = s.Save(ctx, reportFor(i, "prod")); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.List(ctx, "prod", nil, "")
	if err != nil || len(rows) != 10 {
		t.Fatalf("retention: %d %v", len(rows), err)
	}
	previous := rows[0].ID
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err = s.Save(cancelled, reportFor(20, "prod")); err == nil {
		t.Fatal("saved cancelled request")
	}
	r := reportFor(21, "prod")
	r.Metadata.State = "failed"
	if err = s.Save(ctx, r); err == nil {
		t.Fatal("saved failure as completed")
	}
	if err = os.WriteFile(filepath.Join(root, "other-cache"), make([]byte, 1024*1024), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(ctx, reportFor(22, "prod")); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("budget: %v", err)
	}
	if _, err = s.Findings(ctx, "prod", previous, "", 100); err != nil {
		t.Fatalf("lost previous report: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".partial-") {
			t.Fatal("leaked partial")
		}
	}
}

func TestStoreRefusesSymlinksAndIncompleteCounts(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "reports")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root, 1024*1024); err == nil {
		t.Fatal("followed reports symlink")
	}
	s, err := NewStore(t.TempDir(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	r := reportFor(1, "prod")
	r.Metadata.FindingCount = 0
	if err = s.Save(context.Background(), r); err == nil {
		t.Fatal("saved incomplete finding inventory")
	}
}

func TestStartupRecoversInterruptedReportWrites(t *testing.T) {
	root := t.TempDir()
	partial := filepath.Join(root, "reports", ".partial-interrupted")
	if err := os.MkdirAll(partial, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "findings.jsonl"), []byte("unfinished"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root, 1024*1024); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("interrupted write retained: %v", err)
	}
}

func TestListRefusesLinkedMetadataEvenWhenItNamesAnotherCluster(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	r := reportFor(1, "other")
	if err = s.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "metadata.json")
	encoded, _ := json.Marshal(r.Metadata)
	if err = os.WriteFile(outside, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(root, "reports", r.Metadata.ID, "metadata.json")
	if err = os.Remove(meta); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, meta); err != nil {
		t.Fatal(err)
	}
	if _, err = s.List(context.Background(), "current", nil, ""); err == nil {
		t.Fatal("followed another cluster's linked metadata")
	}
}

func TestStoredReportFreshnessIsRecalculatedWhenRead(t *testing.T) {
	s, err := NewStore(t.TempDir(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	r := reportFor(1, "cluster")
	r.Metadata.ReportedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	r.Metadata.Freshness = "current"
	if err = s.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	page, err := s.Findings(context.Background(), "cluster", r.Metadata.ID, "", 100)
	if err != nil || page.Metadata.Freshness != "stale" {
		t.Fatalf("cached freshness: %s %v", page.Metadata.Freshness, err)
	}
	rows, err := s.List(context.Background(), "cluster", nil, "")
	if err != nil || len(rows) != 1 || rows[0].Freshness != "stale" {
		t.Fatalf("list freshness: %+v %v", rows, err)
	}
}
