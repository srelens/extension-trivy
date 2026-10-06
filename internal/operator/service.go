package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/srelens/extension-trivy/internal/reports"
	"github.com/srelens/srelens/sdk/go/sidecar"
	"strconv"
	"time"
)

type Broker interface {
	BindingAvailability(context.Context, sidecar.CallContext, []string) (json.RawMessage, error)
	Read(context.Context, sidecar.CallContext, string) (json.RawMessage, error)
	Resource(context.Context, sidecar.CallContext, string, string) (json.RawMessage, error)
}
type BindingStatus struct {
	Binding    string `json:"binding"`
	State      string `json:"state"`
	Version    string `json:"version,omitempty"`
	Namespaced bool   `json:"namespaced"`
	Reason     string `json:"reason,omitempty"`
}
type Status struct {
	Source    string          `json:"source"`
	ClusterID string          `json:"clusterId"`
	Scope     string          `json:"scope"`
	Bindings  []BindingStatus `json:"bindings"`
}

func SourceStatus(ctx context.Context, b Broker, cluster string, namespace *string) (Status, error) {
	cc, err := sidecar.NewCallContext(cluster, namespace)
	if err != nil {
		return Status{}, err
	}
	names := []string{}
	for _, kind := range Kinds {
		names = append(names, kind.Binding)
	}
	raw, err := b.BindingAvailability(ctx, cc, names)
	if err != nil {
		return Status{}, fmt.Errorf("Operator discovery failed: %w", err)
	}
	var result Status
	if json.Unmarshal(raw, &result) != nil || len(result.Bindings) != len(names) {
		return Status{}, fmt.Errorf("Operator discovery returned incomplete availability")
	}
	result.Source = "app"
	result.ClusterID = cluster
	result.Scope = "No Operator report APIs are served. Workload images can be inspected; local image scanning is not available in this build."
	seen := map[string]bool{}
	served, unknown := false, false
	for _, row := range result.Bindings {
		if seen[row.Binding] {
			return Status{}, fmt.Errorf("duplicate Operator discovery result")
		}
		seen[row.Binding] = true
		switch row.State {
		case "served":
			served = true
		case "unknown":
			unknown = true
		case "absent":
		default:
			return Status{}, fmt.Errorf("invalid Operator availability")
		}
	}
	for _, name := range names {
		if !seen[name] {
			return Status{}, fmt.Errorf("Operator discovery omitted %s", name)
		}
	}
	if unknown {
		result.Source = "unknown"
		result.Scope = "Operator discovery failed for one or more report APIs; retry before selecting a report source."
	}
	if served {
		result.Source = "operator"
		result.Scope = "Available Operator categories; missing report kinds remain unavailable. Local image scanning is not available in this build."
	}
	return result, nil
}
func identity(cluster, kind, namespace, name, uid, revision string) string {
	data, _ := json.Marshal([]string{cluster, kind, namespace, name, uid, revision})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ListReports fetches narrow metadata columns, leaving SBOM and other large
// finding payloads for a selected report. No registry or database calls occur.
func ListReports(ctx context.Context, b Broker, cluster string, namespace *string) ([]reports.Metadata, error) {
	status, err := SourceStatus(ctx, b, cluster, namespace)
	if err != nil {
		return nil, err
	}
	out := []reports.Metadata{}
	for _, availability := range status.Bindings {
		if availability.State == "absent" {
			continue
		}
		if availability.State == "unknown" {
			return nil, fmt.Errorf("%s discovery failed: %s", availability.Binding, availability.Reason)
		}
		var kind Kind
		for _, candidate := range Kinds {
			if candidate.Binding == availability.Binding {
				kind = candidate
				break
			}
		}
		ns := namespace
		if !kind.Namespaced {
			ns = nil
		}
		cc, err := sidecar.NewCallContext(cluster, ns)
		if err != nil {
			return nil, err
		}
		raw, err := b.Read(ctx, cc, kind.Binding)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", kind.Binding, err)
		}
		var list struct {
			Items []struct {
				Name, Namespace string
				Columns         []string
			}
			Truncated bool
		}
		if len(raw) > 4*1024*1024 || json.Unmarshal(raw, &list) != nil || list.Items == nil || list.Truncated {
			return nil, fmt.Errorf("%s returned an invalid or truncated list; narrow the namespace", kind.Binding)
		}
		for _, row := range list.Items {
			if len(row.Columns) != 11 || row.Name == "" || row.Columns[0] == "" || row.Columns[0] == "-" || row.Columns[1] == "" || row.Columns[1] == "-" {
				return nil, fmt.Errorf("%s returned incomplete report metadata", kind.Binding)
			}
			c := row.Columns
			meta := reports.Metadata{ID: identity(cluster, kind.Name, row.Namespace, row.Name, c[0], c[1]), Source: "operator", State: "available", Category: kind.Category, ClusterID: cluster, Namespace: row.Namespace, Binding: kind.Binding, ResourceName: row.Name, ResourceUID: c[0], ResourceVersion: c[1], Subject: reports.Subject{Kind: kind.Name, Name: row.Name, Namespace: row.Namespace}, Freshness: "unknown", FindingCount: -1}
			text := func(v string) string {
				if v == "-" || v == "<none>" {
					return ""
				}
				return v
			}
			meta.ReportedAt = text(c[2])
			meta.EngineVersion = text(c[3])
			meta.Image = text(c[4])
			meta.ImageDigest = text(c[5])
			if timestamp, err := time.Parse(time.RFC3339, meta.ReportedAt); err == nil {
				age := time.Since(timestamp)
				if age >= -5*time.Minute {
					meta.Freshness = "current"
					if age > 24*time.Hour {
						meta.Freshness = "stale"
					}
				}
			}
			if kind.Category == "vulnerabilities" || kind.Category == "exposed-secrets" {
				meta.Summary = map[string]int{}
				total := 0
				complete := true
				for i, key := range []string{"criticalCount", "highCount", "mediumCount", "lowCount", "unknownCount"} {
					value, err := strconv.Atoi(c[6+i])
					if err != nil || value < 0 {
						complete = false
						continue
					}
					meta.Summary[key] = value
					total += value
				}
				if complete {
					meta.FindingCount = total
				}
			}
			out = append(out, meta)
			if len(out) > 1000 {
				return nil, fmt.Errorf("more than 1,000 Operator reports; narrow the namespace")
			}
		}
	}
	return out, nil
}
func ReadReport(ctx context.Context, b Broker, cluster string, meta reports.Metadata) (reports.Report, error) {
	if meta.ClusterID != cluster || meta.Source != "operator" {
		return reports.Report{}, fmt.Errorf("report belongs to another cluster or source")
	}
	var kind *Kind
	for i := range Kinds {
		if Kinds[i].Binding == meta.Binding {
			kind = &Kinds[i]
			break
		}
	}
	if kind == nil {
		return reports.Report{}, fmt.Errorf("undeclared report category")
	}
	var ns *string
	if kind.Namespaced {
		if meta.Namespace == "" {
			return reports.Report{}, fmt.Errorf("a namespaced report requires its namespace")
		}
		ns = &meta.Namespace
	}
	cc, err := sidecar.NewCallContext(cluster, ns)
	if err != nil {
		return reports.Report{}, err
	}
	raw, err := b.Resource(ctx, cc, meta.Binding, meta.ResourceName)
	if err != nil {
		return reports.Report{}, fmt.Errorf("reading report details: %w", err)
	}
	var response struct {
		Resource json.RawMessage `json:"resource"`
	}
	if len(raw) > 4*1024*1024 || json.Unmarshal(raw, &response) != nil {
		return reports.Report{}, fmt.Errorf("invalid report details")
	}
	report, err := Normalize(response.Resource, cluster, time.Now())
	if err != nil {
		return reports.Report{}, err
	}
	if report.Metadata.ID != meta.ID {
		return reports.Report{}, fmt.Errorf("this Operator report changed; refresh Reports before opening its details")
	}
	return report, nil
}
