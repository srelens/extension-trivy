package reports

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxReportBytes = 8 * 1024 * 1024

var reportID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Store struct {
	root   string
	budget int64
	mu     sync.Mutex
}
type FindingPage struct {
	Metadata   Metadata  `json:"metadata"`
	Items      []Finding `json:"items"`
	NextCursor string    `json:"nextCursor,omitempty"`
}
type cursor struct {
	Cluster string `json:"cluster"`
	Report  string `json:"report"`
	Offset  int    `json:"offset"`
}

func NewStore(root string, budget int64) (*Store, error) {
	if !filepath.IsAbs(root) || budget <= 0 {
		return nil, fmt.Errorf("invalid app report directory or disk budget")
	}
	// The host can name macOS's /var alias. Resolve that supplied root once;
	// links created inside the app's storage are still refused.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	root = resolved
	dir := filepath.Join(root, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if _, err := diskUsage(root); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	// A sidecar has one store, opened at startup. Remove writes interrupted
	// before their atomic rename; completed reports keep their identity.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".partial-") {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return nil, err
			}
		}
	}
	return &Store{root: root, budget: budget}, nil
}

// Save publishes a completed inventory atomically. A failed or cancelled write
// leaves previous reports intact; acquisition and scan caches count in the budget.
func (s *Store) Save(ctx context.Context, r Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !reportID.MatchString(r.Metadata.ID) || r.Metadata.ClusterID == "" || r.Metadata.State != "completed" || r.Metadata.FindingCount != len(r.Findings) || len(r.Findings) > 20000 {
		return fmt.Errorf("invalid or incomplete completed report")
	}
	meta, err := json.Marshal(r.Metadata)
	if err != nil {
		return err
	}
	var lines []byte
	for _, finding := range r.Findings {
		b, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		lines = append(lines, b...)
		lines = append(lines, '\n')
		if len(lines)+len(meta) > maxReportBytes {
			return fmt.Errorf("report exceeds its storage bound")
		}
	}
	used, err := diskUsage(s.root)
	if err != nil {
		return err
	}
	destination := filepath.Join(s.root, "reports", r.Metadata.ID)
	if old, err := s.metadata(r.Metadata.ClusterID, r.Metadata.ID); err == nil {
		if old.State == "completed" {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if used+int64(len(meta)+len(lines)) > s.budget {
		return fmt.Errorf("app disk budget has insufficient space for this report")
	}
	partial, err := os.MkdirTemp(filepath.Join(s.root, "reports"), ".partial-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(partial)
	if err = os.WriteFile(filepath.Join(partial, "metadata.json"), meta, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(partial, "findings.jsonl"), lines, 0600); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Rename(partial, destination); err != nil {
		return err
	}
	rows, err := s.entries()
	if err != nil {
		return err
	}
	for _, row := range rows[min(10, len(rows)):] {
		if err = os.RemoveAll(filepath.Join(s.root, "reports", row.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) entries() ([]fs.FileInfo, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "reports"))
	if err != nil {
		return nil, err
	}
	rows := []fs.FileInfo{}
	for _, entry := range entries {
		if !reportID.MatchString(entry.Name()) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, fmt.Errorf("invalid stored report directory")
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		rows = append(rows, info)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ModTime().Equal(rows[j].ModTime()) {
			return rows[i].Name() > rows[j].Name()
		}
		return rows[i].ModTime().After(rows[j].ModTime())
	})
	return rows, nil
}

func (s *Store) metadata(cluster, id string) (Metadata, error) {
	meta, err := s.readMetadata(id)
	if err == nil && meta.ClusterID != cluster {
		err = fmt.Errorf("the report does not belong to this cluster")
	}
	return meta, err
}

func (s *Store) readMetadata(id string) (Metadata, error) {
	var meta Metadata
	if !reportID.MatchString(id) {
		return meta, fmt.Errorf("invalid report identifier")
	}
	path := filepath.Join(s.root, "reports", id, "metadata.json")
	if err := regularFile(path); err != nil {
		return meta, err
	}
	file, err := os.Open(path)
	if err != nil {
		return meta, err
	}
	defer file.Close()
	if err = json.NewDecoder(io.LimitReader(file, 64*1024)).Decode(&meta); err != nil {
		return meta, err
	}
	if meta.ClusterID == "" || meta.ID != id || meta.State != "completed" {
		return meta, fmt.Errorf("the report does not belong to this cluster or is incomplete")
	}
	meta.Freshness = FreshnessAt(meta.ReportedAt, time.Now())
	return meta, nil
}

func (s *Store) List(ctx context.Context, cluster string, namespace *string, source string) ([]Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.entries()
	if err != nil {
		return nil, err
	}
	out := []Metadata{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta, err := s.readMetadata(row.Name())
		if err != nil {
			return nil, err
		}
		if meta.ClusterID != cluster {
			continue
		}
		if source != "" && meta.Source != source {
			continue
		}
		if namespace != nil && meta.Namespace != "" && meta.Namespace != *namespace {
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}

func (s *Store) Findings(ctx context.Context, cluster, id, token string, limit int) (FindingPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out FindingPage
	if limit < 1 || limit > 100 {
		return out, fmt.Errorf("finding page size must be 1–100")
	}
	offset := 0
	if token != "" {
		data, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(data) > 8192 {
			return out, fmt.Errorf("invalid findings cursor")
		}
		var c cursor
		if json.Unmarshal(data, &c) != nil || c.Cluster != cluster || c.Report != id || c.Offset < 0 {
			return out, fmt.Errorf("cursor belongs to another report or cluster")
		}
		offset = c.Offset
	}
	meta, err := s.metadata(cluster, id)
	if err != nil {
		return out, err
	}
	if offset > meta.FindingCount {
		return out, fmt.Errorf("cursor is past the report")
	}
	path := filepath.Join(s.root, "reports", id, "findings.jsonl")
	if err = regularFile(path); err != nil {
		return out, err
	}
	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()
	out.Metadata = meta
	out.Items = []Finding{}
	scanner := bufio.NewScanner(io.LimitReader(file, maxReportBytes+1))
	scanner.Buffer(make([]byte, 4096), maxReportBytes)
	index := 0
	bytes := 0
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return FindingPage{}, err
		}
		if index >= offset && len(out.Items) < limit {
			var row Finding
			if err = json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return FindingPage{}, err
			}
			bytes += len(scanner.Bytes())
			if bytes > 3*1024*1024 {
				return FindingPage{}, fmt.Errorf("findings page exceeds the response bound; use a smaller page")
			}
			out.Items = append(out.Items, row)
		}
		index++
	}
	if err = scanner.Err(); err != nil {
		return FindingPage{}, err
	}
	if index != meta.FindingCount {
		return FindingPage{}, fmt.Errorf("stored findings inventory is incomplete")
	}
	if next := offset + len(out.Items); next < meta.FindingCount {
		data, _ := json.Marshal(cursor{cluster, id, next})
		out.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return out, nil
}

func regularFile(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("app storage contains a symlink")
		}
		if p == path && !info.Mode().IsRegular() {
			return fmt.Errorf("stored report is not a regular file")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func diskUsage(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("app storage contains a symlink")
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("app storage contains a special file")
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
}
