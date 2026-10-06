// Package reports holds normalized, bounded app and Operator scan results.
package reports

import (
	"encoding/json"
	"time"
)

type Subject struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
	Container string `json:"container,omitempty"`
}

type Metadata struct {
	ID                string         `json:"reportId"`
	Source            string         `json:"source"`
	State             string         `json:"state"`
	Category          string         `json:"category"`
	ClusterID         string         `json:"clusterId"`
	Namespace         string         `json:"namespace,omitempty"`
	Subject           Subject        `json:"subject"`
	ReportedAt        string         `json:"reportedAt,omitempty"`
	Freshness         string         `json:"freshness"`
	EngineVersion     string         `json:"engineVersion,omitempty"`
	ImageDigest       string         `json:"imageDigest,omitempty"`
	Image             string         `json:"image,omitempty"`
	Platform          string         `json:"platform,omitempty"`
	DatabaseDigest    string         `json:"databaseDigest,omitempty"`
	DatabaseUpdatedAt string         `json:"databaseUpdatedAt,omitempty"`
	Summary           map[string]int `json:"summary,omitempty"`
	FindingCount      int            `json:"findingCount"`
	Binding           string         `json:"binding,omitempty"`
	ResourceName      string         `json:"resourceName,omitempty"`
	ResourceUID       string         `json:"resourceUid,omitempty"`
	ResourceVersion   string         `json:"resourceVersion,omitempty"`
}

type Finding struct {
	ID               string          `json:"id"`
	Severity         string          `json:"severity,omitempty"`
	Target           string          `json:"target,omitempty"`
	Package          string          `json:"package,omitempty"`
	InstalledVersion string          `json:"installedVersion,omitempty"`
	FixedVersion     string          `json:"fixedVersion,omitempty"`
	Title            string          `json:"title,omitempty"`
	Description      string          `json:"description,omitempty"`
	References       []string        `json:"references,omitempty"`
	Messages         []string        `json:"messages,omitempty"`
	Remediation      string          `json:"remediation,omitempty"`
	Success          *bool           `json:"success,omitempty"`
	Details          json.RawMessage `json:"details,omitempty"`
}

type Report struct {
	Metadata Metadata  `json:"metadata"`
	Findings []Finding `json:"findings"`
}

// FreshnessAt derives age from evidence, including on a later cached read.
func FreshnessAt(timestamp string, now time.Time) string {
	updated, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return "unknown"
	}
	age := now.Sub(updated)
	if age < -5*time.Minute {
		return "unknown"
	}
	if age > 24*time.Hour {
		return "stale"
	}
	return "current"
}
