package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/srelens/srelens/sdk/go/sidecar"
	"strings"
	"testing"
)

type broker struct {
	states           map[string]string
	reads, resources int
	readError        bool
}

func (b *broker) BindingAvailability(_ context.Context, cc sidecar.CallContext, names []string) (json.RawMessage, error) {
	if cc.ClusterID != "cluster" || len(names) != 12 {
		return nil, fmt.Errorf("wrong discovery scope")
	}
	rows := []BindingStatus{}
	for _, name := range names {
		state := b.states[name]
		if state == "" {
			state = "absent"
		}
		rows = append(rows, BindingStatus{Binding: name, State: state, Reason: map[string]string{"unknown": "Forbidden"}[state]})
	}
	return json.Marshal(map[string]any{"bindings": rows})
}
func (b *broker) Read(_ context.Context, cc sidecar.CallContext, name string) (json.RawMessage, error) {
	b.reads++
	if name != "vulnerability-reports" {
		return nil, fmt.Errorf("read an unserved API")
	}
	if b.readError {
		return nil, fmt.Errorf("report list forbidden")
	}
	return json.RawMessage(`{"items":[{"name":"web-main","namespace":"team","columns":["uid","7","2026-10-06T10:00:00Z","0.75.0","library/alpine","sha256:abc","0","2","0","0","0"]}]}`), nil
}
func (b *broker) Resource(_ context.Context, cc sidecar.CallContext, binding, name string) (json.RawMessage, error) {
	b.resources++
	return json.RawMessage(`{"resource":{"kind":"VulnerabilityReport","metadata":{"name":"web-main","namespace":"team","uid":"uid","resourceVersion":"7"},"report":{"summary":{"highCount":2},"vulnerabilities":[{"vulnerabilityID":"CVE-one","severity":"HIGH"},{"vulnerabilityID":"CVE-two","severity":"HIGH"}]}}}`), nil
}
func TestSourceChoiceDistinguishesAbsenceFromUnknownAndReadsOnlyServed(t *testing.T) {
	for _, c := range []struct{ state, source string }{{"absent", "app"}, {"unknown", "unknown"}, {"served", "operator"}} {
		t.Run(c.state, func(t *testing.T) {
			b := &broker{states: map[string]string{"vulnerability-reports": c.state}}
			status, err := SourceStatus(context.Background(), b, "cluster", nil)
			if err != nil || status.Source != c.source {
				t.Fatalf("source: %+v %v", status, err)
			}
			rows, err := ListReports(context.Background(), b, "cluster", nil)
			if c.state == "unknown" {
				if err == nil || !strings.Contains(err.Error(), "Forbidden") {
					t.Fatalf("unknown swallowed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.state == "absent" {
				if b.reads != 0 || len(rows) != 0 {
					t.Fatal("absence read reports")
				}
				return
			}
			if b.reads != 1 || b.resources != 0 || len(rows) != 1 || rows[0].EngineVersion != "0.75.0" || rows[0].FindingCount != 2 {
				t.Fatalf("metadata: %+v reads=%d resources=%d", rows, b.reads, b.resources)
			}
			report, err := ReadReport(context.Background(), b, "cluster", rows[0])
			if err != nil || len(report.Findings) != 2 {
				t.Fatalf("details: %+v %v", report, err)
			}
		})
	}
}
func TestReportReadErrorsAreNotEmptyResults(t *testing.T) {
	b := &broker{states: map[string]string{"vulnerability-reports": "served"}, readError: true}
	if _, err := ListReports(context.Background(), b, "cluster", nil); err == nil {
		t.Fatal("read denial hidden")
	}
}

func TestSourceStatusExplainsExplicitContainerScanning(t *testing.T) {
	status, err := SourceStatus(context.Background(), &broker{states: map[string]string{}}, "cluster", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.Scope, "Scan namespace") {
		t.Fatalf("misleading local scan scope: %s", status.Scope)
	}
}

func TestAvailabilityPreservesOnlyKnownNamespaceScope(t *testing.T) {
	// These are the host's wire payloads: absent/unknown have no scope;
	// a served cluster-wide report explicitly carries false.
	for _, raw := range []string{
		`{"binding":"vulnerability-reports","state":"absent"}`,
		`{"binding":"vulnerability-reports","state":"unknown","reason":"Forbidden"}`,
		`{"binding":"cluster-vulnerability-reports","state":"served","version":"v1alpha1","namespaced":false}`,
		`{"binding":"vulnerability-reports","state":"served","version":"v1alpha1","namespaced":true}`,
	} {
		var row BindingStatus
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		var got, want map[string]any
		json.Unmarshal(encoded, &got)
		json.Unmarshal([]byte(raw), &want)
		if got["namespaced"] != want["namespaced"] {
			t.Fatalf("scope invented or lost for %s: %s", raw, encoded)
		}
	}
}
