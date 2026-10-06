package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srelens/extension-trivy/internal/operator"
	"github.com/srelens/extension-trivy/internal/reports"
	"github.com/srelens/srelens/sdk/go/sidecar"
)

type fakeBroker struct {
	states       map[string]string
	dir, binding string
	calls        int
	wait         bool
	entered      chan struct{}
}

func (b *fakeBroker) BindingAvailability(_ context.Context, _ sidecar.CallContext, names []string) (json.RawMessage, error) {
	rows := []operator.BindingStatus{}
	for _, name := range names {
		state := b.states[name]
		if state == "" {
			state = "absent"
		}
		rows = append(rows, operator.BindingStatus{Binding: name, State: state, Reason: "discovery refused"})
	}
	return json.Marshal(map[string]any{"bindings": rows})
}
func (b *fakeBroker) Read(context.Context, sidecar.CallContext, string) (json.RawMessage, error) {
	return json.RawMessage(`{"items":[]}`), nil
}
func (b *fakeBroker) Resource(context.Context, sidecar.CallContext, string, string) (json.RawMessage, error) {
	return nil, errors.New("unexpected resource read")
}
func (b *fakeBroker) RunJob(ctx context.Context, cc sidecar.CallContext, name string, inputs map[string]string) (json.RawMessage, error) {
	b.calls++
	b.binding = name
	if cc.Namespace == nil || *cc.Namespace != "team" {
		return nil, errors.New("wrong namespace")
	}
	if b.wait {
		close(b.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	path := "job-result-0123456789abcdef0123456789abcdef.json"
	raw := `{"Resources":[]}`
	if name == "image-job" {
		raw = imageJSON
	}
	if err := os.WriteFile(filepath.Join(b.dir, path), []byte(raw), 0600); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"path": path, "job": "scanner", "uid": "uid", "namespace": "team", "image": "pinned", "bytes": len(raw), "finishedAt": "2026-10-06T12:00:00Z"})
}
func TestNamespaceScanSelectsOnlyMissingOperatorCategories(t *testing.T) {
	for _, c := range []struct{ vuln, config, binding string }{{"absent", "absent", "namespace-job"}, {"served", "absent", "namespace-config-job"}, {"absent", "served", "namespace-vulnerability-job"}, {"served", "served", ""}, {"unknown", "absent", "error"}} {
		t.Run(c.vuln+"-"+c.config, func(t *testing.T) {
			dir := t.TempDir()
			store, _ := reports.NewStore(dir, 1<<30)
			b := &fakeBroker{dir: dir, states: map[string]string{"vulnerability-reports": c.vuln, "config-audit-reports": c.config}}
			r := Runner{Broker: b, Store: store, Dir: dir}
			frames := []map[string]any{}
			err := r.Run(context.Background(), Scope{"cluster", "team"}, "", func(frame map[string]any) error { frames = append(frames, frame); return nil })
			if c.binding == "error" {
				if err == nil || b.calls != 0 {
					t.Fatal("discovery failure became absence")
				}
				return
			}
			if err != nil || b.binding != c.binding || frames[len(frames)-1]["state"] != "completed" {
				t.Fatalf("run: %s %+v %v", b.binding, frames, err)
			}
			rows, err := store.List(context.Background(), "cluster", nil, "app")
			expected := 1
			if c.binding == "" {
				expected = 0
			}
			if err != nil || len(rows) != expected {
				t.Fatalf("saved: %+v %v", rows, err)
			}
			matches, _ := filepath.Glob(filepath.Join(dir, "job-result-*"))
			if len(matches) != 0 {
				t.Fatal("raw result retained")
			}
		})
	}
}
func TestScanCancellationAndSingleActiveRunLeavePriorReports(t *testing.T) {
	dir := t.TempDir()
	store, _ := reports.NewStore(dir, 1<<30)
	prior, _ := Normalize([]byte(imageJSON), Scope{"cluster", "team"}, "image", "prior", time.Now())
	if err := store.Save(context.Background(), prior); err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{dir: dir, wait: true, entered: make(chan struct{})}
	r := Runner{Broker: b, Store: store, Dir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, Scope{"cluster", "team"}, "alpine:3.10", func(map[string]any) error { return nil })
	}()
	<-b.entered
	if err := r.Run(context.Background(), Scope{"cluster", "team"}, "alpine:3.10", func(map[string]any) error { return nil }); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatal(err)
	}
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("cancel swallowed")
	}
	rows, _ := store.List(context.Background(), "cluster", nil, "app")
	if len(rows) != 1 || rows[0].ID != prior.Metadata.ID {
		t.Fatal("previous report lost")
	}
	if err := r.Run(context.Background(), Scope{"cluster", ""}, "alpine", func(map[string]any) error { return nil }); err == nil {
		t.Fatal("all namespace scan accepted")
	}
}
