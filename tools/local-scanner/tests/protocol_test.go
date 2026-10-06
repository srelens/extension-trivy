package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/srelens/extension-trivy/internal/probe"
)

// Exercise the actual SDK session, including the app's stream registration.
// The real supervised scan is in tests/sandbox; this case checks that missing
// artifacts become a stream failure while lifecycle calls remain responsive.
func TestProtocolScanFailureAndHealth(t *testing.T) {
	in, input := io.Pipe()
	output, out := io.Pipe()
	done := make(chan error, 1)
	lines := make(chan map[string]json.RawMessage, 16)
	go func() { done <- probe.New().Run(context.Background(), in, out) }()
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			var line map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &line) != nil || string(line["jsonrpc"]) != `"2.0"` {
				lines <- nil
				return
			}
			lines <- line
		}
	}()
	t.Cleanup(func() { input.Close(); output.Close() })
	send := func(id int, method string, params any) {
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
				t.Fatal("stdout contained non-protocol data or ended unexpectedly")
			}
			return line
		case <-time.After(5 * time.Second):
			t.Fatal("the SDK stopped answering")
			return nil
		}
	}
	send(1, "initialize", map[string]any{
		"apiVersions": []string{"0.1.0"}, "host": map[string]string{"name": "srelens", "version": "0.15.0"},
		"dataDirectory": t.TempDir(),
		"limits":        map[string]any{"requestTimeoutMs": 30000, "maxConcurrentRequests": 8, "maxStreams": 5, "memoryBytes": 268435456, "cpus": 1, "dataBytes": 1073741824, "dataEntries": 100000},
	})
	if line := read(); line["error"] != nil || string(line["id"]) != "1" {
		t.Fatalf("initialize: %v", line)
	}
	send(2, "activate", map[string]any{})
	if line := read(); line["error"] != nil || string(line["id"]) != "2" {
		t.Fatalf("activate: %v", line)
	}
	send(3, "stream/open", map[string]any{"stream": 1, "method": "scan", "params": map[string]any{}})
	if line := read(); line["error"] != nil || string(line["id"]) != "3" {
		t.Fatalf("scan did not open: %v", line)
	}
	send(4, "health", map[string]any{})
	var healthy, failed bool
	for !healthy || !failed {
		line := read()
		if string(line["id"]) == "4" {
			if line["error"] != nil {
				t.Fatalf("health failed: %v", line)
			}
			healthy = true
		}
		if string(line["method"]) == `"stream/error"` {
			failed = true
		}
		if string(line["method"]) == `"stream/close"` {
			t.Fatal("missing artifact was treated as a successful scan")
		}
	}
	input.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not stop")
	}
}
