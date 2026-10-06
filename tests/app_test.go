package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/srelens/extension-trivy/internal/app"
	"io"
	"testing"
	"time"
)

func TestRealAppUsesCheckedBrokerAndShowsLiveSourceState(t *testing.T) {
	in, input := io.Pipe()
	output, out := io.Pipe()
	defer input.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() { done <- app.New().Run(context.Background(), in, out) }()
	lines := make(chan map[string]json.RawMessage, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			var line map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &line) != nil {
				lines <- nil
				return
			}
			lines <- line
		}
	}()
	send := func(id any, method string, params any) {
		t.Helper()
		if err := json.NewEncoder(input).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string]json.RawMessage {
		t.Helper()
		select {
		case line := <-lines:
			if line == nil {
				t.Fatal("non-protocol output or EOF")
			}
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("app did not answer")
			return nil
		}
	}
	send(1, "initialize", map[string]any{"apiVersions": []string{"0.1.0", "0.2.0"}, "host": map[string]string{"name": "srelens", "version": "0.15.0"}, "dataDirectory": t.TempDir(), "limits": map[string]any{"requestTimeoutMs": 30000, "maxConcurrentRequests": 8, "maxStreams": 5, "memoryBytes": 268435456, "cpus": 1, "dataBytes": 1073741824, "dataEntries": 100000}})
	if line := read(); line["error"] != nil {
		t.Fatal(line)
	}
	send(2, "activate", map[string]any{})
	if line := read(); line["error"] != nil {
		t.Fatal(line)
	}
	send(3, "source-status", map[string]any{"clusterId": "cluster"})
	callback := read()
	if string(callback["method"]) != `"host/bindingAvailability"` {
		t.Fatalf("wrong broker call: %v", callback)
	}
	var params struct {
		Context  struct{ ClusterID string }
		Bindings []string
	}
	if json.Unmarshal(callback["params"], &params) != nil || params.Context.ClusterID != "cluster" || len(params.Bindings) != 12 {
		t.Fatalf("scope: %s", callback["params"])
	}
	rows := []map[string]string{}
	for _, name := range params.Bindings {
		rows = append(rows, map[string]string{"binding": name, "state": "absent"})
	}
	var callbackID any
	json.Unmarshal(callback["id"], &callbackID)
	if err := json.NewEncoder(input).Encode(map[string]any{"jsonrpc": "2.0", "id": callbackID, "result": map[string]any{"bindings": rows}}); err != nil {
		t.Fatal(err)
	}
	answer := read()
	var result struct{ Source, ClusterID string }
	if answer["error"] != nil || json.Unmarshal(answer["result"], &result) != nil || result.Source != "app" || result.ClusterID != "cluster" {
		t.Fatalf("source: %s %s", answer["result"], answer["error"])
	}
	send(4, "health", map[string]any{})
	if line := read(); line["error"] != nil {
		t.Fatal(line)
	}
	input.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session failed to end")
	}
}
