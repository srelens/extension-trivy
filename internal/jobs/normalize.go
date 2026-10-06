// Package jobs collects bounded reports from the host's scoped container runner.
package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/srelens/extension-trivy/internal/reports"
)

const MaxBytes = 8 * 1024 * 1024

type Scope struct{ ClusterID, Namespace string }
type imageMetadata struct {
	RepoDigests []string
	ImageConfig struct{ Architecture, OS string }
}
type result struct {
	Target, Class   string
	Vulnerabilities []struct {
		VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, SeveritySource, Title, Description, PrimaryURL string
		References                                                                                                         []string
		DataSource                                                                                                         json.RawMessage
	}
	MisconfSummary    *struct{ Failures int }
	Misconfigurations []struct {
		ID, Severity, Title, Description, Message, Resolution, Status string
		References                                                    []string
	}
	Secrets []json.RawMessage
}
type resource struct {
	Kind, Name, Namespace, Error string
	Metadata                     imageMetadata
	Results                      []result
}

// Normalize accepts only complete JSON from a successful worker. Unknown DB
// provenance stays unknown; image environment and source snippets are discarded.
func Normalize(raw []byte, scope Scope, kind, job string, now time.Time) (reports.Report, error) {
	var out reports.Report
	if len(raw) == 0 || len(raw) > MaxBytes || scope.ClusterID == "" || scope.Namespace == "" {
		return out, fmt.Errorf("scan result or scope is invalid")
	}
	var document struct {
		SchemaVersion int
		ArtifactName  string
		Metadata      imageMetadata
		Results       []result
		Resources     []resource
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return out, fmt.Errorf("scan returned invalid or truncated JSON; no report saved")
	}
	resources := document.Resources
	meta := reports.Metadata{Source: "app", State: "completed", Category: kind, ClusterID: scope.ClusterID, Namespace: scope.Namespace, Subject: reports.Subject{Kind: "Namespace", Name: scope.Namespace, Namespace: scope.Namespace}, ReportedAt: now.UTC().Format(time.RFC3339Nano), Freshness: "current", EngineVersion: "0.75.0", Summary: map[string]int{}}
	if kind == "image" {
		if document.SchemaVersion != 2 || document.ArtifactName == "" || document.Results == nil {
			return out, fmt.Errorf("image scan is incomplete; no report saved")
		}
		meta.Subject = reports.Subject{Kind: "Image", Name: document.ArtifactName, Namespace: scope.Namespace}
		meta.Image = document.ArtifactName
		if len(document.Metadata.RepoDigests) > 0 {
			meta.ImageDigest = document.Metadata.RepoDigests[0]
		}
		if document.Metadata.ImageConfig.OS != "" && document.Metadata.ImageConfig.Architecture != "" {
			meta.Platform = document.Metadata.ImageConfig.OS + "/" + document.Metadata.ImageConfig.Architecture
		}
		resources = []resource{{Kind: "Image", Name: document.ArtifactName, Namespace: scope.Namespace, Results: document.Results}}
	} else if kind != "namespace" || resources == nil {
		return out, fmt.Errorf("namespace scan is incomplete; no report saved")
	}
	out.Metadata = meta
	out.Findings = []reports.Finding{}
	appendFinding := func(f reports.Finding) error {
		if len(out.Findings) >= 20000 {
			return fmt.Errorf("scan exceeds 20,000 findings; no partial report saved")
		}
		f.Severity = strings.ToUpper(f.Severity)
		switch f.Severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
		default:
			f.Severity = "UNKNOWN"
		}
		out.Metadata.Summary[f.Severity]++
		out.Findings = append(out.Findings, f)
		return nil
	}
	for _, res := range resources {
		if res.Kind == "Job" && res.Name == job {
			continue
		}
		if res.Kind == "" || res.Name == "" || res.Namespace != scope.Namespace || res.Error != "" || res.Results == nil {
			return reports.Report{}, fmt.Errorf("a resource scan failed or returned incomplete data; no report saved")
		}
		for _, result := range res.Results {
			if result.Class != "os-pkgs" && result.Class != "lang-pkgs" && result.Class != "config" {
				return reports.Report{}, fmt.Errorf("unsupported scan result class; no report saved")
			}
			if result.MisconfSummary != nil {
				failures := 0
				for _, m := range result.Misconfigurations {
					if m.Status == "FAIL" {
						failures++
					}
				}
				if result.MisconfSummary.Failures != failures {
					return reports.Report{}, fmt.Errorf("configuration results are incomplete; no report saved")
				}
			}
			for _, v := range result.Vulnerabilities {
				if v.VulnerabilityID == "" || v.PkgName == "" {
					return reports.Report{}, fmt.Errorf("vulnerability data is incomplete")
				}
				details, _ := json.Marshal(map[string]any{"resource": res.Kind + "/" + res.Name, "namespace": res.Namespace, "severitySource": v.SeveritySource, "dataSource": v.DataSource})
				if res.Metadata.ImageConfig.OS != "" && res.Metadata.ImageConfig.Architecture != "" {
					details, _ = json.Marshal(map[string]any{"resource": res.Kind + "/" + res.Name, "namespace": res.Namespace, "severitySource": v.SeveritySource, "dataSource": v.DataSource, "platform": res.Metadata.ImageConfig.OS + "/" + res.Metadata.ImageConfig.Architecture, "imageDigests": res.Metadata.RepoDigests})
				}
				refs := v.References
				if len(refs) == 0 && v.PrimaryURL != "" {
					refs = []string{v.PrimaryURL}
				}
				if err := appendFinding(reports.Finding{ID: v.VulnerabilityID, Severity: v.Severity, Target: result.Target, Package: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, Title: v.Title, Description: v.Description, References: refs, Details: details}); err != nil {
					return reports.Report{}, err
				}
			}
			for _, m := range result.Misconfigurations {
				if m.Status != "FAIL" {
					continue
				}
				if m.ID == "" {
					return reports.Report{}, fmt.Errorf("configuration data is incomplete")
				}
				details, _ := json.Marshal(map[string]any{"resource": res.Kind + "/" + res.Name, "namespace": res.Namespace})
				if err := appendFinding(reports.Finding{ID: m.ID, Severity: m.Severity, Target: result.Target, Title: m.Title, Description: m.Description, Messages: []string{m.Message}, Remediation: m.Resolution, References: m.References, Details: details}); err != nil {
					return reports.Report{}, err
				}
			}
			// Secret scanning is disabled in every binding. Never retain an
			// unexpected scanner secret match as a normal finding.
			if len(result.Secrets) > 0 { /* discarded: no secret plaintext enters the store */
			}
		}
	}
	identity, _ := json.Marshal([]string{scope.ClusterID, scope.Namespace, kind, job, meta.ReportedAt})
	hash := sha256.Sum256(identity)
	out.Metadata.ID = hex.EncodeToString(hash[:])
	out.Metadata.FindingCount = len(out.Findings)
	return out, nil
}
