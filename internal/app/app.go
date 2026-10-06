// Package app registers the native Trivy executable's broker-backed operations.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/srelens/extension-trivy/internal/jobs"
	"github.com/srelens/extension-trivy/internal/operator"
	"github.com/srelens/extension-trivy/internal/reports"
	"github.com/srelens/extension-trivy/internal/workloads"
	"github.com/srelens/srelens/sdk/go/sidecar"
	"io/fs"
	"sync"
)

type Scope struct {
	ClusterID string  `json:"clusterId"`
	Namespace *string `json:"namespace,omitempty"`
}
type listInput struct {
	Scope
	Cursor string `json:"cursor,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
}
type findingsInput struct {
	listInput
	ReportID string `json:"reportId"`
}
type reportCursor struct {
	Cluster   string
	Namespace *string
	Snapshot  string
	Offset    int
}

func New() *sidecar.Sidecar {
	s := sidecar.New("trivy", "0.2.0")
	var once sync.Once
	var store *reports.Store
	var storeErr error
	getStore := func(ctx context.Context) (*reports.Store, error) {
		once.Do(func() { store, storeErr = reports.NewStore(sidecar.DataDir(ctx), int64(sidecar.Limits(ctx).DataBytes)) })
		return store, storeErr
	}
	sidecar.Operation(s, "source-status", func(ctx context.Context, in Scope) (operator.Status, error) {
		return operator.SourceStatus(ctx, sidecar.HostFrom(ctx), in.ClusterID, in.Namespace)
	})
	sidecar.Operation(s, "list-images", func(ctx context.Context, in Scope) (map[string]any, error) {
		rows, err := workloads.ListImages(ctx, sidecar.HostFrom(ctx), in.ClusterID, in.Namespace)
		if err != nil {
			return nil, err
		}
		return map[string]any{"clusterId": in.ClusterID, "source": "workload templates", "scope": "Deployments, StatefulSets and DaemonSets; regular and init containers", "items": rows}, nil
	})
	allReports := func(ctx context.Context, in Scope) ([]reports.Metadata, error) {
		rows, err := operator.ListReports(ctx, sidecar.HostFrom(ctx), in.ClusterID, in.Namespace)
		if err != nil {
			return nil, err
		}
		store, err := getStore(ctx)
		if err != nil {
			return nil, err
		}
		cached, err := store.List(ctx, in.ClusterID, in.Namespace, "app")
		if err != nil {
			return nil, err
		}
		return append(rows, cached...), nil
	}
	sidecar.Operation(s, "list-reports", func(ctx context.Context, in listInput) (map[string]any, error) {
		limit, err := pageSize(in.Limit)
		if err != nil {
			return nil, sidecar.InvalidParams(err.Error())
		}
		rows, err := allReports(ctx, in.Scope)
		if err != nil {
			return nil, err
		}
		ids := []string{}
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		encoded, _ := json.Marshal(ids)
		snapshot := fmt.Sprintf("%x", sha256.Sum256(encoded))
		offset := 0
		if in.Cursor != "" {
			raw, err := base64.RawURLEncoding.DecodeString(in.Cursor)
			if err != nil || len(raw) > 8192 {
				return nil, sidecar.InvalidParams("Invalid report cursor")
			}
			var c reportCursor
			if json.Unmarshal(raw, &c) != nil || c.Cluster != in.ClusterID || c.Snapshot != snapshot || c.Offset < 0 || c.Offset > len(rows) || !sameNamespace(c.Namespace, in.Namespace) {
				return nil, sidecar.InvalidParams("Reports changed or this cursor belongs to another cluster or namespace; refresh Reports")
			}
			offset = c.Offset
		}
		end := min(offset+limit, len(rows))
		next := ""
		if end < len(rows) {
			raw, _ := json.Marshal(reportCursor{in.ClusterID, in.Namespace, snapshot, end})
			next = base64.RawURLEncoding.EncodeToString(raw)
		}
		items := []map[string]any{}
		for _, row := range rows[offset:end] {
			var count any = "Details not loaded"
			if row.FindingCount >= 0 {
				count = row.FindingCount
			}
			items = append(items, map[string]any{"reportId": row.ID, "source": row.Source, "category": row.Category, "namespace": row.Namespace, "subject": row.Subject.Name, "image": row.Image, "imageDigest": row.ImageDigest, "engineVersion": row.EngineVersion, "reportedAt": row.ReportedAt, "freshness": row.Freshness, "findings": count, "summary": row.Summary})
		}
		return map[string]any{"clusterId": in.ClusterID, "items": items, "nextCursor": next, "totalReports": len(rows), "scope": "Operator reports and retained app scans; counts stay separate by source"}, nil
	})
	sidecar.Operation(s, "findings", func(ctx context.Context, in findingsInput) (reports.FindingPage, error) {
		limit, err := pageSize(in.Limit)
		if err != nil {
			return reports.FindingPage{}, sidecar.InvalidParams(err.Error())
		}
		if _, err := sidecar.NewCallContext(in.ClusterID, in.Namespace); err != nil {
			return reports.FindingPage{}, err
		}
		store, err := getStore(ctx)
		if err != nil {
			return reports.FindingPage{}, err
		}
		page, err := store.Findings(ctx, in.ClusterID, in.ReportID, in.Cursor, limit)
		if errors.Is(err, fs.ErrNotExist) {
			rows, listErr := operator.ListReports(ctx, sidecar.HostFrom(ctx), in.ClusterID, in.Namespace)
			if listErr != nil {
				return page, listErr
			}
			found := false
			for _, row := range rows {
				if row.ID != in.ReportID {
					continue
				}
				found = true
				report, err := operator.ReadReport(ctx, sidecar.HostFrom(ctx), in.ClusterID, row)
				if err != nil {
					return page, err
				}
				if err = store.Save(ctx, report); err != nil {
					return page, err
				}
				break
			}
			if !found {
				return page, fmt.Errorf("This report was removed or does not belong to this cluster; refresh Reports")
			}
			page, err = store.Findings(ctx, in.ClusterID, in.ReportID, in.Cursor, limit)
		}
		if err == nil && in.Namespace != nil && page.Metadata.Namespace != "" && page.Metadata.Namespace != *in.Namespace {
			return reports.FindingPage{}, sidecar.InvalidParams("Report belongs to another namespace")
		}
		return page, err
	})

	var runnerOnce sync.Once
	var runner *jobs.Runner
	getRunner := func(ctx context.Context) (*jobs.Runner, error) {
		store, err := getStore(ctx)
		if err != nil {
			return nil, err
		}
		runnerOnce.Do(func() { runner = &jobs.Runner{Broker: sidecar.HostFrom(ctx), Store: store, Dir: sidecar.DataDir(ctx)} })
		return runner, nil
	}
	sidecar.Stream(s, "scan-namespace", func(ctx context.Context, in Scope, frames *sidecar.Frames) error {
		if in.Namespace == nil || *in.Namespace == "" {
			return sidecar.InvalidParams("Choose one namespace before running a scan")
		}
		runner, err := getRunner(ctx)
		if err != nil {
			return err
		}
		return runner.Run(ctx, jobs.Scope{ClusterID: in.ClusterID, Namespace: *in.Namespace}, "", func(frame map[string]any) error { return frames.Send(frame) })
	})
	sidecar.Stream(s, "scan-image", func(ctx context.Context, in struct {
		Scope
		Image string `json:"image"`
	}, frames *sidecar.Frames) error {
		if in.Namespace == nil || *in.Namespace == "" || in.Image == "" {
			return sidecar.InvalidParams("Choose a namespace and image before running a scan")
		}
		runner, err := getRunner(ctx)
		if err != nil {
			return err
		}
		return runner.Run(ctx, jobs.Scope{ClusterID: in.ClusterID, Namespace: *in.Namespace}, in.Image, func(frame map[string]any) error { return frames.Send(frame) })
	})
	return s
}
func pageSize(value *int) (int, error) {
	if value == nil {
		return 100, nil
	}
	if *value < 1 || *value > 100 {
		return 0, fmt.Errorf("Page size must be 1–100")
	}
	return *value, nil
}
func sameNamespace(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
