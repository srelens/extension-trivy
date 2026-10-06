package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/srelens/extension-trivy/internal/operator"
	"github.com/srelens/extension-trivy/internal/reports"
	"github.com/srelens/srelens/sdk/go/sidecar"
)

type Broker interface {
	operator.Broker
	RunJob(context.Context, sidecar.CallContext, string, map[string]string) (json.RawMessage, error)
}
type Runner struct {
	Broker Broker
	Store  *reports.Store
	Dir    string
	active atomic.Bool
}

var resultPath = regexp.MustCompile(`^job-result-[0-9a-f]{32}\.json$`)

func (r *Runner) Run(ctx context.Context, scope Scope, image string, send func(map[string]any) error) error {
	if scope.Namespace == "" {
		return sidecar.InvalidParams("Choose one namespace before running a scan")
	}
	cc, err := sidecar.NewCallContext(scope.ClusterID, &scope.Namespace)
	if err != nil {
		return err
	}
	if len(image) > 512 || strings.TrimSpace(image) != image || strings.ContainsAny(image, " \t\r\n") || strings.HasPrefix(image, "-") {
		return sidecar.InvalidParams("Enter a valid container image reference")
	}
	if !r.active.CompareAndSwap(false, true) {
		return fmt.Errorf("A scan is already active; wait or cancel it first")
	}
	defer r.active.Store(false)
	frame := func(phase, message string) error {
		return send(map[string]any{"state": "running", "phase": phase, "message": message, "namespace": scope.Namespace})
	}
	binding := "image-job"
	kind := "image"
	inputs := map[string]string{"image": image}
	coverage := []string{"image vulnerabilities"}
	if image == "" {
		kind = "namespace"
		inputs = map[string]string{"namespace": scope.Namespace}
		if err = frame("Discovering", "Checking Operator report APIs for this namespace…"); err != nil {
			return err
		}
		status, e := operator.SourceStatus(ctx, r.Broker, scope.ClusterID, &scope.Namespace)
		if e != nil {
			return e
		}
		states := map[string]string{}
		for _, row := range status.Bindings {
			states[row.Binding] = row.State
		}
		vuln, config := states["vulnerability-reports"], states["config-audit-reports"]
		if vuln == "unknown" || config == "unknown" {
			return fmt.Errorf("Operator discovery failed; retry before selecting a scan source")
		}
		coverage = []string{}
		if vuln == "absent" {
			coverage = append(coverage, "image vulnerabilities")
		}
		if config == "absent" {
			coverage = append(coverage, "namespace configuration")
		}
		switch {
		case vuln == "served" && config == "served":
			rows, warnings, e := operator.ListReportInventory(ctx, r.Broker, scope.ClusterID, &scope.Namespace)
			if e != nil {
				return e
			}
			items := []map[string]any{}
			for _, row := range rows {
				items = append(items, map[string]any{"reportId": row.ID, "source": row.Source, "category": row.Category, "namespace": row.Namespace, "subject": row.Subject.Name, "findings": row.FindingCount})
			}
			return send(map[string]any{"state": "completed", "source": "operator", "namespace": scope.Namespace, "warnings": warnings, "message": "Using published Operator reports. An empty list means no reports have been published, not a clean namespace.", "items": items})
		case vuln == "served":
			binding = "namespace-config-job"
		case config == "served":
			binding = "namespace-vulnerability-job"
		default:
			binding = "namespace-job"
		}
	}
	if err = frame("Scanning", "Waiting for confirmation or running the temporary scan Job. Database downloads can take several minutes."); err != nil {
		return err
	}
	raw, e := r.Broker.RunJob(ctx, cc, binding, inputs)
	if e != nil {
		return fmt.Errorf("Container scan failed: %w", e)
	}
	var result struct {
		Path, Job, UID, Namespace, Image, FinishedAt, State, Error string
		Bytes                                                      int
	}
	if json.Unmarshal(raw, &result) != nil || !resultPath.MatchString(result.Path) || result.Namespace != scope.Namespace || result.Job == "" || result.UID == "" || result.Bytes < 1 || result.Bytes > MaxBytes {
		return fmt.Errorf("Host returned invalid scan result metadata")
	}
	root, e := os.OpenRoot(r.Dir)
	if e != nil {
		return e
	}
	defer root.Close()
	defer root.Remove(result.Path)
	file, e := root.Open(result.Path)
	if e != nil {
		return fmt.Errorf("Cannot open the scan result: %w", e)
	}
	data, e := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	file.Close()
	if e != nil || len(data) != result.Bytes {
		return fmt.Errorf("Scan result is unreadable, truncated or oversized; no report saved")
	}
	if result.State == "failed" {
		return fmt.Errorf("Container scan failed: %s", ScanFailure(string(data), result.Error))
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = frame("Saving", "Validating and saving findings…"); err != nil {
		return err
	}
	finished, e := time.Parse(time.RFC3339Nano, result.FinishedAt)
	if e != nil {
		return fmt.Errorf("Scan completion time is invalid")
	}
	report, e := Normalize(data, scope, kind, result.Job, finished)
	if e != nil {
		return e
	}
	report.Metadata.Coverage = coverage
	report.Metadata.ScannerImage = result.Image
	if e = r.Store.Save(ctx, report); e != nil {
		return fmt.Errorf("Cannot save the report; previous reports remain available: %w", e)
	}
	return send(map[string]any{"state": "completed", "source": "app", "namespace": scope.Namespace, "scope": "Image vulnerabilities and namespace configuration only. Namespace images use Trivy's default image platform; image scans use the Job's node architecture. See platform evidence in finding details. No node, compliance, SBOM or secret scan.", "coverage": coverage, "items": []any{map[string]any{"reportId": report.Metadata.ID, "namespace": scope.Namespace, "source": "app", "category": kind, "subject": report.Metadata.Subject.Name, "findings": report.Metadata.FindingCount, "summary": report.Metadata.Summary}}})
}
