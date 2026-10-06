package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/srelens/srelens/sdk/go/sidecar"
	"testing"
)

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
func TestListsThreeBindingsWithPinnedScopeAndContainerIdentity(t *testing.T) {
	r := &reader{}
	ns := "team"
	rows, err := ListImages(context.Background(), r, "cluster-a", &ns)
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
	_, err := ListImages(context.Background(), r, "cluster-a", nil)
	if err == nil {
		t.Fatal("hid reader failure")
	}
	if len(r.calls) != 1 {
		t.Fatal("continued discovery after failure")
	}
}
