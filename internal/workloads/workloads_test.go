package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/srelens/srelens/sdk/go/sidecar"
	"testing"
)

type largeReader struct{ calls int }

func (r *largeReader) ReadPage(_ context.Context, cc sidecar.CallContext, binding, cursor string) (json.RawMessage, error) {
	r.calls++
	if binding != "deployment-images" {
		return json.RawMessage(`{"items":[],"nextCursor":""}`), nil
	}
	offset := 0
	if cursor == "second" {
		offset = 600
	}
	if cursor == "third" {
		offset = 1200
	}
	rows := []map[string]any{}
	for i := offset; i < offset+600; i++ {
		rows = append(rows, map[string]any{"kind": "Deployment", "namespace": "team", "name": fmt.Sprintf("web-%d", i), "uid": fmt.Sprint(i), "resourceVersion": "7", "containers": []map[string]any{{"name": "app", "type": "regular", "image": "alpine:3.10"}}})
	}
	next := "second"
	if offset == 600 {
		next = "third"
	}
	if offset == 1200 {
		next = ""
	}
	raw, _ := json.Marshal(map[string]any{"items": rows, "nextCursor": next})
	return raw, nil
}

func TestLargeInventoryPagesWithoutDiscardingImagesOrLosingScope(t *testing.T) {
	r := &largeReader{}
	ns := "team"
	cursor := ""
	total := 0
	for {
		page, err := ListImagePage(context.Background(), r, "cluster-a", &ns, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 1000 {
			t.Fatal("unbounded page")
		}
		total += len(page.Items)
		if page.NextCursor == "" {
			break
		}
		if _, err := ListImagePage(context.Background(), r, "other-cluster", &ns, page.NextCursor); err == nil {
			t.Fatal("accepted another cluster cursor")
		}
		cursor = page.NextCursor
	}
	if total != 1800 {
		t.Fatalf("lost images: %d", total)
	}
}

type reader struct {
	calls    []string
	contexts []sidecar.CallContext
	err      error
}

func (r *reader) Read(_ context.Context, cc sidecar.CallContext, binding string) (json.RawMessage, error) {
	r.calls = append(r.calls, binding)
	r.contexts = append(r.contexts, cc)
	if r.err != nil {
		return nil, r.err
	}
	return json.RawMessage(`{"items":[{"kind":"Deployment","namespace":"team","name":"web","uid":"u","resourceVersion":"7","containers":[{"name":"main","type":"regular","image":"alpine:3.9"},{"name":"setup","type":"init","image":"alpine:3.9"}]}]}`), nil
}
func (r *reader) ReadPage(ctx context.Context, cc sidecar.CallContext, binding, cursor string) (json.RawMessage, error) {
	return r.Read(ctx, cc, binding)
}
func listAllImages(ctx context.Context, r Reader, cluster string, namespace *string) ([]Image, error) {
	rows := []Image{}
	cursor := ""
	for {
		page, err := ListImagePage(ctx, r, cluster, namespace, cursor)
		if err != nil {
			return nil, err
		}
		rows = append(rows, page.Items...)
		if page.NextCursor == "" {
			return rows, nil
		}
		cursor = page.NextCursor
	}
}
func TestListsThreeBindingsWithPinnedScopeAndContainerIdentity(t *testing.T) {
	r := &reader{}
	ns := "team"
	rows, err := listAllImages(context.Background(), r, "cluster-a", &ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 || rows[0].ContainerType != "regular" || rows[1].ContainerType != "init" || rows[0].UID != "u" || rows[0].ResourceVersion != "7" {
		t.Fatalf("wrong images: %+v", rows)
	}
	if len(r.calls) != 3 || r.calls[0] != "deployment-images" || r.calls[1] != "statefulset-images" || r.calls[2] != "daemonset-images" {
		t.Fatalf("wrong readers: %v", r.calls)
	}
	for _, cc := range r.contexts {
		if cc.ClusterID != "cluster-a" || cc.Namespace == nil || *cc.Namespace != "team" {
			t.Fatalf("scope: %+v", cc)
		}
	}
}
func TestReadFailuresAreNotEmptyImages(t *testing.T) {
	r := &reader{err: errors.New("Forbidden")}
	_, err := listAllImages(context.Background(), r, "cluster-a", nil)
	if err == nil {
		t.Fatal("hid reader failure")
	}
	if len(r.calls) != 1 {
		t.Fatal("continued discovery after failure")
	}
}
