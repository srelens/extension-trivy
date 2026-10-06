package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/srelens/extension-trivy/internal/probe"
)

// The desktop exposes ordinary sidecar operations as installed-app tools.
// A stream-only probe cannot be invoked through that existing app interface.
func TestLocalPreviewFixtureOperation(t *testing.T) {
	for _, populated := range []bool{true, false} {
		t.Run(map[bool]string{true: "findings", false: "missing artifacts"}[populated], func(t *testing.T) {
			// A real sidecar owns the whole process; this in-process SDK harness
			// must restore its temp environment before the next app session.
			for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(key, os.Getenv(key))
			}
			data := t.TempDir()
			if populated {
				if err := os.CopyFS(data, os.DirFS(filepath.Join("..", "..", "..", ".fixtures", "runtime"))); err != nil {
					t.Fatal(err)
				}
			}
			in, input := io.Pipe()
			output, out := io.Pipe()
			done := make(chan error, 1)
			go func() { done <- probe.New().Run(context.Background(), in, out) }()
			t.Cleanup(func() { input.Close(); output.Close() })
			lines := make(chan map[string]json.RawMessage, 8)
			go func() {
				defer close(lines)
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					var line map[string]json.RawMessage
					if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
						return
					}
					lines <- line
				}
			}()
			call := func(id int, method string, params any) map[string]json.RawMessage {
				t.Helper()
				if err := json.NewEncoder(input).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
					t.Fatal(err)
				}
				select {
				case line := <-lines:
					if line == nil || string(line["id"]) != strconv.Itoa(id) {
						t.Fatalf("unexpected reply to %s: %v", method, line)
					}
					return line
				case <-time.After(5 * time.Second):
					t.Fatalf("%s did not answer", method)
					return nil
				}
			}
			initialized := call(1, "initialize", map[string]any{
				"apiVersions": []string{"0.1.0"}, "host": map[string]string{"name": "srelens", "version": "0.15.0"},
				"dataDirectory": data,
				"limits":        map[string]any{"requestTimeoutMs": 30000, "maxConcurrentRequests": 8, "maxStreams": 5, "memoryBytes": 268435456, "cpus": 1, "dataBytes": 1073741824, "dataEntries": 100000},
			})
			if initialized["error"] != nil || call(2, "activate", map[string]any{})["error"] != nil {
				t.Fatal("app did not initialize")
			}
			line := call(3, "scan-fixture", map[string]any{})
			if populated {
				var result struct {
					State, Source, EngineVersion, ImageID string
					Findings                              []map[string]string
				}
				if line["error"] != nil || json.Unmarshal(line["result"], &result) != nil {
					t.Fatalf("fixture operation failed: %v", line)
				}
				if result.State != "completed" || result.Source != "pinned-fixture" || result.EngineVersion != "0.75.0+srelens.2" || result.ImageID != "sha256:055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1" || len(result.Findings) != 6 {
					t.Fatalf("wrong fixture identity or findings: %+v", result)
				}
			} else if line["error"] == nil || line["result"] != nil {
				t.Fatalf("missing artifacts became a successful scan: %v", line)
			}
			if line := call(4, "health", map[string]any{}); line["error"] != nil {
				t.Fatalf("app stopped answering: %v", line)
			}
			input.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
