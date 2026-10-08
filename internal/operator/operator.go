// Package operator normalizes the declared Trivy Operator report APIs.
package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/srelens/extension-trivy/internal/reports"
	"strings"
	"time"
)

type Kind struct {
	Binding, Name, Plural, Category string
	Namespaced                      bool
}

var Kinds = []Kind{
	{"vulnerability-reports", "VulnerabilityReport", "vulnerabilityreports", "vulnerabilities", true},
	{"cluster-vulnerability-reports", "ClusterVulnerabilityReport", "clustervulnerabilityreports", "vulnerabilities", false},
	{"config-audit-reports", "ConfigAuditReport", "configauditreports", "configuration", true},
	{"cluster-config-audit-reports", "ClusterConfigAuditReport", "clusterconfigauditreports", "configuration", false},
	{"rbac-assessment-reports", "RbacAssessmentReport", "rbacassessmentreports", "rbac", true},
	{"cluster-rbac-assessment-reports", "ClusterRbacAssessmentReport", "clusterrbacassessmentreports", "rbac", false},
	{"infra-assessment-reports", "InfraAssessmentReport", "infraassessmentreports", "infrastructure", true},
	{"cluster-infra-assessment-reports", "ClusterInfraAssessmentReport", "clusterinfraassessmentreports", "infrastructure", false},
	{"sbom-reports", "SbomReport", "sbomreports", "sbom", true},
	{"cluster-sbom-reports", "ClusterSbomReport", "clustersbomreports", "sbom", false},
	{"compliance-reports", "ClusterComplianceReport", "clustercompliancereports", "compliance", false},
	{"exposed-secret-reports", "ExposedSecretReport", "exposedsecretreports", "exposed-secrets", true},
}

type document struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Owners          []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Report json.RawMessage `json:"report"`
	Status json.RawMessage `json:"status"`
}

// Normalize never keeps raw Secret matches or guesses unknown provenance.
func Normalize(data []byte, cluster string, now time.Time) (reports.Report, error) {
	var out reports.Report
	if len(data) > 4*1024*1024 || strings.TrimSpace(cluster) == "" {
		return out, fmt.Errorf("invalid report size or cluster")
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return out, fmt.Errorf("invalid Operator report: %w", err)
	}
	var kind *Kind
	for i := range Kinds {
		if Kinds[i].Name == doc.Kind {
			kind = &Kinds[i]
			break
		}
	}
	if kind == nil {
		return out, fmt.Errorf("unsupported Operator report kind %q", doc.Kind)
	}
	payload := doc.Report
	if kind.Category == "compliance" {
		payload = doc.Status
	}
	var body map[string]json.RawMessage
	if len(payload) == 0 || json.Unmarshal(payload, &body) != nil || body == nil {
		return out, fmt.Errorf("the Operator report has no completed details")
	}
	identity, _ := json.Marshal([]string{cluster, doc.Kind, doc.Metadata.Namespace, doc.Metadata.Name, doc.Metadata.UID, doc.Metadata.ResourceVersion})
	digest := sha256.Sum256(identity)
	meta := reports.Metadata{ID: hex.EncodeToString(digest[:]), Source: "operator", State: "completed", Category: kind.Category, ClusterID: cluster, Namespace: doc.Metadata.Namespace,
		Binding: kind.Binding, ResourceName: doc.Metadata.Name, ResourceUID: doc.Metadata.UID, ResourceVersion: doc.Metadata.ResourceVersion, Freshness: "unknown",
		Subject: reports.Subject{Kind: doc.Kind, Name: doc.Metadata.Name, Namespace: doc.Metadata.Namespace, Container: doc.Metadata.Labels["trivy-operator.container.name"]}}
	if len(doc.Metadata.Owners) == 1 {
		owner := doc.Metadata.Owners[0]
		meta.Subject.Kind = owner.Kind
		meta.Subject.Name = owner.Name
		meta.Subject.UID = owner.UID
	}
	var timestamp string
	_ = json.Unmarshal(body["updateTimestamp"], &timestamp)
	if updated, err := time.Parse(time.RFC3339, timestamp); err == nil {
		meta.ReportedAt = timestamp
		age := now.Sub(updated)
		if age >= -5*time.Minute {
			meta.Freshness = "current"
			if age > 24*time.Hour {
				meta.Freshness = "stale"
			}
		}
	}
	var scanner struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body["scanner"], &scanner)
	meta.EngineVersion = scanner.Version
	var artifact struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
	}
	_ = json.Unmarshal(body["artifact"], &artifact)
	meta.ImageDigest = artifact.Digest
	meta.Image = artifact.Repository
	if artifact.Tag != "" {
		meta.Image += ":" + artifact.Tag
	}
	_ = json.Unmarshal(body["summary"], &meta.Summary)
	var rows []json.RawMessage
	var secrets []string
	readRows := func(key string) error {
		raw, ok := body[key]
		if !ok {
			return fmt.Errorf("the Operator report has no %s details", key)
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return fmt.Errorf("invalid %s details", key)
		}
		if rows == nil {
			return fmt.Errorf("the Operator report has incomplete %s details", key)
		}
		if kind.Category == "vulnerabilities" || kind.Category == "exposed-secrets" {
			total := 0
			for _, key := range []string{"criticalCount", "highCount", "mediumCount", "lowCount", "unknownCount"} {
				total += meta.Summary[key]
			}
			if total > len(rows) {
				return fmt.Errorf("the Operator summary exceeds its available finding details")
			}
		}
		return nil
	}
	switch kind.Category {
	case "vulnerabilities":
		if err := readRows("vulnerabilities"); err != nil {
			return out, err
		}
	case "exposed-secrets":
		if err := readRows("secrets"); err != nil {
			return out, err
		}
	case "sbom":
		var bom struct {
			Components   []json.RawMessage `json:"components"`
			Dependencies []json.RawMessage `json:"dependencies"`
		}
		if len(body["components"]) == 0 || json.Unmarshal(body["components"], &bom) != nil {
			return out, fmt.Errorf("the Operator report has no SBOM details")
		}
		var counts struct {
			Components   *int `json:"componentsCount"`
			Dependencies *int `json:"dependenciesCount"`
		}
		if json.Unmarshal(body["summary"], &counts) != nil || counts.Components == nil || counts.Dependencies == nil || *counts.Components < 0 || *counts.Dependencies < 0 || *counts.Components != len(bom.Components) || *counts.Dependencies != len(bom.Dependencies) {
			return out, fmt.Errorf("the SBOM summary and available components or dependencies disagree")
		}
		rows = bom.Components
		for _, row := range rows {
			var item struct {
				ID      string `json:"bom-ref"`
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := json.Unmarshal(row, &item); err != nil {
				return out, err
			}
			out.Findings = append(out.Findings, reports.Finding{ID: item.ID, Package: item.Name, InstalledVersion: item.Version, Title: "SBOM component", Details: row})
		}
		for _, row := range bom.Dependencies {
			var item struct {
				Ref string `json:"ref"`
			}
			if err := json.Unmarshal(row, &item); err != nil {
				return out, err
			}
			out.Findings = append(out.Findings, reports.Finding{ID: item.Ref, Title: "SBOM dependencies", Details: row})
		}
		rows = nil
	case "compliance":
		if raw, ok := body["detailReport"]; ok && string(raw) != "null" {
			var detail struct {
				Results []struct {
					ID, Name, Severity string
					Checks             []json.RawMessage `json:"checks"`
				} `json:"results"`
			}
			if err := json.Unmarshal(raw, &detail); err != nil {
				return out, err
			}
			if detail.Results == nil {
				return out, fmt.Errorf("the compliance report has no completed control inventory")
			}
			for _, control := range detail.Results {
				if control.ID == "" || control.Checks == nil {
					return out, fmt.Errorf("the compliance control has incomplete details")
				}
				for _, raw := range control.Checks {
					var check map[string]json.RawMessage
					if json.Unmarshal(raw, &check) != nil || check == nil {
						return out, fmt.Errorf("invalid compliance check")
					}
					var id string
					var success bool
					_ = json.Unmarshal(check["checkID"], &id)
					_ = json.Unmarshal(check["success"], &success)
					if id == "" && success {
						check["checkID"], _ = json.Marshal(control.ID)
						check["title"], _ = json.Marshal(control.Name)
						check["severity"], _ = json.Marshal(control.Severity)
					}
					check["controlId"], _ = json.Marshal(control.ID)
					check["controlName"], _ = json.Marshal(control.Name)
					encoded, _ := json.Marshal(check)
					rows = append(rows, encoded)
				}
			}
		} else if raw, ok := body["summaryReport"]; ok && string(raw) != "null" {
			var summary struct {
				Controls []json.RawMessage `json:"controlCheck"`
			}
			if err := json.Unmarshal(raw, &summary); err != nil {
				return out, err
			}
			if summary.Controls == nil {
				return out, fmt.Errorf("the compliance report has no completed control inventory")
			}
			for _, row := range summary.Controls {
				var item struct{ ID, Name, Severity string }
				if err := json.Unmarshal(row, &item); err != nil {
					return out, err
				}
				out.Findings = append(out.Findings, reports.Finding{ID: item.ID, Title: item.Name, Severity: item.Severity, Details: row})
			}
		} else {
			return out, fmt.Errorf("the Operator compliance report has no result details")
		}
	default:
		if err := readRows("checks"); err != nil {
			return out, err
		}
	}
	for _, row := range rows {
		var item struct {
			VulnerabilityID  string   `json:"vulnerabilityID"`
			CheckID          string   `json:"checkID"`
			RuleID           string   `json:"ruleID"`
			Resource         string   `json:"resource"`
			InstalledVersion string   `json:"installedVersion"`
			FixedVersion     string   `json:"fixedVersion"`
			Severity         string   `json:"severity"`
			Target           string   `json:"target"`
			Title            string   `json:"title"`
			Description      string   `json:"description"`
			Links            []string `json:"links"`
			Messages         []string `json:"messages"`
			Remediation      string   `json:"remediation"`
			Success          *bool    `json:"success"`
			Match            string   `json:"match"`
		}
		if err := json.Unmarshal(row, &item); err != nil {
			return out, fmt.Errorf("invalid finding details: %w", err)
		}
		id := item.VulnerabilityID
		if id == "" {
			id = item.CheckID
		}
		if id == "" {
			id = item.RuleID
		}
		if id == "" {
			return out, fmt.Errorf("an Operator finding has no identifier")
		}
		finding := reports.Finding{ID: id, Severity: item.Severity, Target: item.Target, Package: item.Resource, InstalledVersion: item.InstalledVersion, FixedVersion: item.FixedVersion,
			Title: item.Title, Description: item.Description, References: item.Links, Messages: item.Messages, Remediation: item.Remediation, Success: item.Success}
		if kind.Category == "exposed-secrets" {
			if item.Match != "" {
				secrets = append(secrets, item.Match)
			}
		} else {
			finding.Details = row
		}
		out.Findings = append(out.Findings, finding)
	}
	if len(out.Findings) > 20000 {
		return out, fmt.Errorf("the Operator report exceeds 20,000 findings; its details cannot be shown as complete")
	}
	if out.Findings == nil {
		out.Findings = []reports.Finding{}
	}
	meta.FindingCount = len(out.Findings)
	out.Metadata = meta
	if len(secrets) > 0 {
		// Scrub values throughout the normalized record, including a match
		// repeated in a title. Map keys and structural field names stay intact.
		encoded, _ := json.Marshal(out)
		var value any
		_ = json.Unmarshal(encoded, &value)
		encoded, _ = json.Marshal(scrub(value, secrets))
		if err := json.Unmarshal(encoded, &out); err != nil {
			return reports.Report{}, err
		}
		// This digest is an opaque hash, not matched source text. Retain the
		// lookup identity when an unusual short match also occurs in its hash.
		out.Metadata.ID = meta.ID
		// The cluster identity is supplied by the caller, not secret-report text.
		out.Metadata.ClusterID = cluster
	}
	return out, nil
}

func scrub(value any, secrets []string) any {
	switch v := value.(type) {
	case string:
		for _, secret := range secrets {
			v = strings.ReplaceAll(v, secret, "[redacted]")
		}
		return v
	case map[string]any:
		for key, value := range v {
			v[key] = scrub(value, secrets)
		}
	case []any:
		for i, value := range v {
			v[i] = scrub(value, secrets)
		}
	}
	return value
}
