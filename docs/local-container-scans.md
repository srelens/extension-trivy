# Local container scan acceptance

The signed macOS arm64 controller ran through the production app registry,
supervisor and OS sandbox against `kind-srelens-demo`, namespace
`srelens-trivy-test`. No Operator report APIs were served. The controller uses
only the Go SDK and standard library; scanner execution, image layers and
database downloads stay inside the temporary Kubernetes Job.

- Namespace scan: 17 findings — one critical vulnerability and 16 configuration
  findings. The scanner's own Job was excluded from normalized findings.
- Image scan: `alpine:3.10`, one critical CVE, installed and fixed versions,
  actual image digest/platform and severity source retained.
- Registry refusal: the failed worker's private bounded diagnostics produced
  an actionable access-denied error. No failed report or log plaintext was saved.
- Cancellation: a running namespace Job was cancelled through the production
  stream bridge; its original UID and owned resources disappeared. Four prior
  completed reports remained available.
- Cleanup: no scanner Job, Pod, ServiceAccount, Role, RoleBinding or readiness
  ConfigMap remained after success, failure or cancellation.

The worker's declared image is official Trivy 0.75.0, digest
`sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa`.
It runs without root or extra capabilities, with a read-only root, one CPU,
1 GiB RAM, 16 GiB temporary storage, a 20-minute deadline and no retries.
Namespace scans receive only their declared namespace reads; image scans receive
no Kubernetes service-account token. Neither reads Secrets or starts node collectors.

The namespace JSON parser was corrected using the real container wire shape:
`Resources[].Metadata` is an array. A sanitized captured fixture is committed
under `internal/jobs/testdata`. Unknown discovery, partial reports and truncated
JSON cannot produce a completed report. Available Operator categories and saved
app scans remain listed beside explicit category warnings.

Go race tests, Python preparation/manifest/dependency tests, the Rust workspace,
protocol/SDK checks and frontend coverage pass. The native Overview, Scan namespace,
Reports and Findings components were driven at wide and narrow widths using
captured live results. Scan pages wait for Run; row navigation pins its context.

This is local development acceptance. Windows and other controller-platform
sandbox acceptance, remote repository setup, releases and catalog publication
remain outside this change. Whole-cluster scans and private registry credential
injection are not implemented. Namespace images use Trivy's default platform;
manual image scans select the worker architecture. Platform evidence is retained
without claiming coverage of every running workload architecture.
