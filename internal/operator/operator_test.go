package operator

import (
	"context"
	"encoding/json"
	"github.com/srelens/extension-trivy/internal/reports"
	"strings"
	"testing"
	"time"
)

func TestOperatorVulnerabilitiesPreserveOccurrencesAndProvenance(t *testing.T) {
	data := []byte(`{"kind":"VulnerabilityReport","metadata":{"name":"pod-web-app","namespace":"team","uid":"r-1","resourceVersion":"7","labels":{"trivy-operator.container.name":"app"},"ownerReferences":[{"kind":"Pod","name":"web","uid":"pod-1"}]},"report":{"updateTimestamp":"2026-10-05T10:00:00Z","scanner":{"name":"Trivy","version":"0.75.0"},"artifact":{"repository":"library/alpine","digest":"sha256:abc"},"summary":{"highCount":2},"vulnerabilities":[{"vulnerabilityID":"CVE-2019-1549","resource":"libssl1.1","installedVersion":"1.1.1b-r1","fixedVersion":"1.1.1d-r0","severity":"HIGH","target":"first","title":"OpenSSL vulnerability","links":["https://example.invalid/advisory"]},{"vulnerabilityID":"CVE-2019-1549","resource":"libssl1.1","installedVersion":"1.1.1b-r1","fixedVersion":"1.1.1d-r0","severity":"HIGH","target":"second"}]}}`)
	report, err := Normalize(data, "cluster-a", time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.Metadata.Source != "operator" || report.Metadata.ClusterID != "cluster-a" || report.Metadata.Subject.UID != "pod-1" || report.Metadata.Subject.Container != "app" {
		t.Fatalf("wrong provenance: %+v", report.Metadata)
	}
	if len(report.Findings) != 2 || report.Findings[0].ID != "CVE-2019-1549" || report.Findings[0].FixedVersion != "1.1.1d-r0" || report.Findings[1].Target != "second" {
		t.Fatalf("findings lost: %+v", report.Findings)
	}
	if report.Metadata.EngineVersion != "0.75.0" || report.Metadata.Freshness != "current" || report.Metadata.DatabaseDigest != "" {
		t.Fatalf("unknown metadata fabricated: %+v", report.Metadata)
	}
	other, err := Normalize(data, "cluster-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if other.Metadata.ID == report.Metadata.ID {
		t.Fatal("report identity leaked across clusters")
	}
}

func TestOperatorSecretMatchesNeverLeaveNormalization(t *testing.T) {
	data := []byte(`{"kind":"ExposedSecretReport","metadata":{"name":"secret-report","namespace":"team","uid":"u","resourceVersion":"2"},"report":{"summary":{"highCount":1},"secrets":[{"target":"app/config","ruleID":"generic-api-key","title":"API key","category":"General","severity":"HIGH","match":"LEAK_TOKEN_DO_NOT_STORE"}]}}`)
	report, err := Normalize(data, "cluster", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "LEAK_TOKEN") || strings.Contains(string(encoded), `"match"`) {
		t.Fatal("secret match escaped")
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "generic-api-key" || report.Findings[0].Target != "app/config" {
		t.Fatalf("secret finding metadata lost: %+v", report.Findings)
	}
}

func TestOperatorCategoriesNormalizeSBOMComplianceAndChecks(t *testing.T) {
	cases := []struct{ kind, payload, id, category string }{
		{"ConfigAuditReport", `"report":{"checks":[{"checkID":"AVD-KSV-0001","title":"Privileged container","severity":"HIGH","success":false,"messages":["Set privileged to false"],"remediation":"Disable privileged mode"}]}`, "AVD-KSV-0001", "configuration"},
		{"ClusterRbacAssessmentReport", `"report":{"checks":[{"checkID":"RBAC-001","severity":"HIGH","success":false}]}`, "RBAC-001", "rbac"},
		{"ClusterInfraAssessmentReport", `"report":{"checks":[{"checkID":"INFRA-001","severity":"MEDIUM","success":true}]}`, "INFRA-001", "infrastructure"},
		{"ClusterSbomReport", `"report":{"summary":{"componentsCount":1,"dependenciesCount":1},"components":{"components":[{"bom-ref":"openssl@3","name":"openssl","version":"3.0.1","purl":"pkg:apk/alpine/openssl@3.0.1"}],"dependencies":[{"ref":"openssl@3","dependsOn":["libc@1"]}]}}`, "openssl@3", "sbom"},
		{"ClusterComplianceReport", `"status":{"detailReport":{"results":[{"id":"control-1","checks":[{"checkID":"COMPLIANCE-001","severity":"HIGH","success":false,"remediation":"Fix access"}]}]},"summary":{"failCount":1}}`, "COMPLIANCE-001", "compliance"},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			data := []byte(`{"kind":"` + c.kind + `","metadata":{"name":"report","uid":"u","resourceVersion":"1"},` + c.payload + `}`)
			report, err := Normalize(data, "cluster", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if report.Metadata.Category != c.category || len(report.Findings) < 1 || report.Findings[0].ID != c.id {
				t.Fatalf("details missing: %+v", report)
			}
			if report.Metadata.Namespace != "" || report.Metadata.Freshness != "unknown" {
				t.Fatalf("cluster scope or unknown age lost: %+v", report.Metadata)
			}
		})
	}
}

func TestMissingOrUnsupportedReportsNeverNormalizeAsClean(t *testing.T) {
	for _, data := range []string{`{"kind":"VulnerabilityReport","metadata":{"name":"pending"}}`, `{"kind":"UnknownReport","report":{}}`, `not-json`, `{"kind":"VulnerabilityReport","report":{"vulnerabilities":null}}`, `{"kind":"VulnerabilityReport","report":{"summary":{"highCount":2},"vulnerabilities":[]}}`} {
		if _, err := Normalize([]byte(data), "cluster", time.Now()); err == nil {
			t.Fatalf("accepted incomplete report %s", data)
		}
	}
}

func TestSecretRedactionPreservesOpaqueReportIdentity(t *testing.T) {
	data := []byte(`{"kind":"ExposedSecretReport","metadata":{"name":"report","namespace":"team","uid":"u","resourceVersion":"2"},"report":{"secrets":[{"ruleID":"key","title":"Matched 1","match":"1"}]}}`)
	r, err := Normalize(data, "cluster-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Metadata.ClusterID != "cluster-1" {
		t.Fatal("redaction changed the caller-owned cluster identity")
	}
	store, err := reports.NewStore(t.TempDir(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Findings[0].Title, "1") {
		t.Fatal("match left in title")
	}
}

func TestPassingComplianceControlsRetainTheirParentIdentity(t *testing.T) {
	data := []byte(`{"kind":"ClusterComplianceReport","metadata":{"name":"cis","uid":"u","resourceVersion":"1"},"status":{"summary":{"passCount":1},"detailReport":{"results":[{"id":"1.1","name":"Passed control","severity":"HIGH","checks":[{"checkID":"","severity":"","success":true}]}]}}}`)
	r, err := Normalize(data, "cluster", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "1.1" || r.Findings[0].Title != "Passed control" || r.Findings[0].Success == nil || !*r.Findings[0].Success {
		t.Fatalf("lost passed control: %+v", r.Findings)
	}
}
func TestSBOMSummaryCannotHideMissingComponents(t *testing.T) {
	data := []byte(`{"kind":"SbomReport","metadata":{"name":"bom","uid":"u","resourceVersion":"1"},"report":{"summary":{"componentsCount":2,"dependenciesCount":0},"components":{"bomFormat":"CycloneDX","specVersion":"1.6"}}}`)
	if _, err := Normalize(data, "cluster", time.Now()); err == nil {
		t.Fatal("missing components shown as completed empty SBOM")
	}
}
func TestEmptyCompliancePayloadCannotLookCompleted(t *testing.T) {
	for _, payload := range []string{`{"detailReport":{}}`, `{"summaryReport":{}}`} {
		data := []byte(`{"kind":"ClusterComplianceReport","metadata":{"name":"cis","uid":"u","resourceVersion":"1"},"status":` + payload + `}`)
		if _, err := Normalize(data, "cluster", time.Now()); err == nil {
			t.Fatal("missing compliance inventory shown as complete")
		}
	}
}

func TestExplicitlyEmptySBOMRetainsCompletedInventory(t *testing.T) {
	data := []byte(`{"kind":"SbomReport","metadata":{"name":"empty","uid":"u","resourceVersion":"1"},"report":{"summary":{"componentsCount":0,"dependenciesCount":0},"components":{"bomFormat":"CycloneDX","specVersion":"1.6"}}}`)
	r, err := Normalize(data, "cluster", time.Now())
	if err != nil || r.Metadata.State != "completed" || r.Metadata.FindingCount != 0 {
		t.Fatalf("valid empty BOM: %+v %v", r, err)
	}
}
