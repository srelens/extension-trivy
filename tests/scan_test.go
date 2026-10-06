package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/srelens/extension-trivy/internal/app"
)

func TestNamespaceStreamCallsScopedJobAndPersistsCompletedReport(t *testing.T) {
	dir := t.TempDir()
	in, input := io.Pipe()
	output, out := io.Pipe()
	defer input.Close()
	defer output.Close()
	go app.New().Run(context.Background(), in, out)
	lines := make(chan map[string]json.RawMessage, 32)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			var line map[string]json.RawMessage
			json.Unmarshal(scanner.Bytes(), &line)
			lines <- line
		}
	}()
	send := func(value any) {
		t.Helper()
		if err := json.NewEncoder(input).Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string]json.RawMessage {
		t.Helper()
		select {
		case line := <-lines:
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("stream stalled")
			return nil
		}
	}
	call := func(id int, method string, params any) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	}
	call(1, "initialize", map[string]any{"apiVersions": []string{"0.2.0"}, "host": map[string]string{"name": "srelens", "version": "0.15.0"}, "dataDirectory": dir, "limits": map[string]any{"requestTimeoutMs": 30000, "maxConcurrentRequests": 8, "maxStreams": 5, "memoryBytes": 268435456, "cpus": 1, "dataBytes": 1073741824, "dataEntries": 100000}})
	if line := read(); line["error"] != nil {
		t.Fatal(string(line["error"]))
	}
	call(2, "activate", map[string]any{})
	read()
	call(3, "stream/open", map[string]any{"stream": 1, "method": "scan-namespace", "params": map[string]any{"clusterId": "cluster", "namespace": "team"}})
	ack := read()
	if ack["error"] != nil {
		t.Fatal("Scan namespace is missing: " + string(ack["error"]))
	}
	jobCalled := false
	reportID := ""
	for reportID == "" {
		line := read()
		var method string
		json.Unmarshal(line["method"], &method)
		switch method {
		case "host/bindingAvailability":
			var p struct{ Bindings []string }
			json.Unmarshal(line["params"], &p)
			rows := []map[string]string{}
			for _, name := range p.Bindings {
				rows = append(rows, map[string]string{"binding": name, "state": "absent"})
			}
			send(map[string]any{"jsonrpc": "2.0", "id": line["id"], "result": map[string]any{"bindings": rows}})
		case "host/runJob":
			jobCalled = true
			var p struct {
				Context    struct{ ClusterID, Namespace string }
				Capability string
				Inputs     map[string]string
			}
			json.Unmarshal(line["params"], &p)
			if p.Context.ClusterID != "cluster" || p.Context.Namespace != "team" || p.Capability != "namespace-job" || len(p.Inputs) != 1 || p.Inputs["namespace"] != "team" {
				t.Fatal(string(line["params"]))
			}
			path := "job-result-0123456789abcdef0123456789abcdef.json"
			raw := `{"Resources":[]}`
			os.WriteFile(filepath.Join(dir, path), []byte(raw), 0600)
			send(map[string]any{"jsonrpc": "2.0", "id": line["id"], "result": map[string]any{"path": path, "job": "scanner", "uid": "uid", "namespace": "team", "image": "pinned", "bytes": len(raw), "finishedAt": "2026-10-06T12:00:00Z"}})
		case "stream/data":
			var p struct {
				Data struct {
					State string
					Items []struct{ ReportID string }
				}
			}
			json.Unmarshal(line["params"], &p)
			if p.Data.State == "completed" && len(p.Data.Items) > 0 {
				reportID = p.Data.Items[0].ReportID
			}
		case "stream/error":
			t.Fatal(string(line["params"]))
		}
	}
	if !jobCalled {
		t.Fatal("scan never reached checked host runner")
	}
	if line := read(); string(line["method"]) != `"stream/close"` {
		t.Fatal("no terminal stream close")
	}
	call(4, "findings", map[string]any{"clusterId": "cluster", "namespace": "team", "reportId": reportID})
	line := read()
	if line["error"] != nil {
		t.Fatal(string(line["error"]))
	}
	var result struct {
		Metadata struct{ State, Namespace string }
	}
	json.Unmarshal(line["result"], &result)
	if result.Metadata.State != "completed" || result.Metadata.Namespace != "team" {
		t.Fatal(string(line["result"]))
	}
}
