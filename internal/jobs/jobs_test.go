package jobs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const imageJSON = `{"SchemaVersion":2,"ArtifactName":"alpine:3.10","Metadata":{"RepoDigests":["alpine@sha256:123"],"ImageConfig":{"architecture":"arm64","os":"linux","config":{"Env":["TOKEN=private-value"]}}},"Results":[{"Target":"alpine:3.10 (alpine 3.10.9)","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-36159","PkgName":"apk-tools","InstalledVersion":"2.10.6-r0","FixedVersion":"2.10.7-r0","Severity":"CRITICAL","SeveritySource":"nvd","Title":"apk issue","References":["https://example.test/cve"]}]}]}`
const configJSON = `{"Target":"Deployment/team/web","Class":"config","MisconfSummary":{"Failures":1},"Misconfigurations":[{"ID":"KSV-0001","Severity":"MEDIUM","Title":"Privilege escalation","Message":"Container allows escalation","Resolution":"Set allowPrivilegeEscalation false","Status":"FAIL","CauseMetadata":{"Code":{"Lines":[{"Content":"TOKEN=private-value"}]}}}],"Secrets":[{"RuleID":"token","Match":"private-value"}]}`

func TestNormalizeImagePreservesEvidenceAndDropsSecretPayloads(t *testing.T) {
	r, err := Normalize([]byte(imageJSON), Scope{"cluster", "team"}, "image", "scanner", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f := r.Findings[0]
	if f.ID != "CVE-2021-36159" || f.Severity != "CRITICAL" || f.Package != "apk-tools" || f.InstalledVersion != "2.10.6-r0" || f.FixedVersion != "2.10.7-r0" || len(f.References) != 1 {
		t.Fatalf("finding: %+v", f)
	}
	if r.Metadata.Platform != "linux/arm64" || r.Metadata.Image != "alpine:3.10" || r.Metadata.Source != "app" || r.Metadata.State != "completed" || r.Metadata.DatabaseDigest != "" {
		t.Fatalf("metadata: %+v", r.Metadata)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "private-value") || !strings.Contains(string(data), "nvd") {
		t.Fatal(string(data))
	}
}

func TestNormalizeNamespaceKeepsOccurrencesAndExcludesOnlyItsOwnJob(t *testing.T) {
	var image map[string]any
	json.Unmarshal([]byte(imageJSON), &image)
	resource := func(kind, name string, results any) map[string]any {
		return map[string]any{"Kind": kind, "Name": name, "Namespace": "team", "Results": results}
	}
	var config any
	json.Unmarshal([]byte(configJSON), &config)
	raw, _ := json.Marshal(map[string]any{"ClusterName": "worker", "Resources": []any{resource("Deployment", "web", image["Results"]), resource("Deployment", "other", image["Results"]), resource("Deployment", "web", []any{config}), resource("Job", "scanner", image["Results"]), resource("Job", "srelens-user", image["Results"])}})
	r, err := Normalize(raw, Scope{"cluster", "team"}, "namespace", "scanner", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 4 || r.Metadata.Summary["CRITICAL"] != 3 {
		t.Fatalf("occurrences: %+v", r)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "private-value") || !strings.Contains(string(encoded), "other") {
		t.Fatal(string(encoded))
	}
}

func TestIncompleteReportsAreNeverClean(t *testing.T) {
	for _, raw := range []string{`{}`, `{"Resources":null}`, `{"Resources":[{"Kind":"Pod","Name":"web","Namespace":"team","Error":"registry denied"}]}`, `{"Resources":[{"Kind":"Pod","Name":"web","Namespace":"other","Results":[]}]}`, `{"Resources":[{"Kind":"Pod","Name":"web","Namespace":"team","Results":[{"Class":"config","MisconfSummary":{"Failures":2},"Misconfigurations":[]}]}]}`, `{"Resources":[]`, `{"SchemaVersion":2,"ArtifactName":"alpine"}`} {
		kind := "namespace"
		if strings.Contains(raw, "SchemaVersion") {
			kind = "image"
		}
		if _, err := Normalize([]byte(raw), Scope{"cluster", "team"}, kind, "scanner", time.Now()); err == nil {
			t.Errorf("incomplete scan accepted: %s", raw)
		}
	}
	if _, err := Normalize([]byte(`{"Resources":[]}`), Scope{"cluster", "team"}, "namespace", "scanner", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceFindingsPreserveActualPlatform(t *testing.T) {
	var image map[string]any
	json.Unmarshal([]byte(imageJSON), &image)
	raw, _ := json.Marshal(map[string]any{"Resources": []any{map[string]any{"Kind": "Deployment", "Name": "web", "Namespace": "team", "Metadata": image["Metadata"], "Results": image["Results"]}}})
	r, err := Normalize(raw, Scope{"cluster", "team"}, "namespace", "scanner", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Findings[0].Details), "linux/arm64") {
		t.Fatal(string(r.Findings[0].Details))
	}
}
