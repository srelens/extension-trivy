# Trivy executable app design

Date: 2026-10-05. Status: planning; production implementation has not started.

## Intent and acceptance

Build a meaningful executable Trivy integration in its own `extension-trivy` repository, following the signed-package/catalog conventions of cert-manager. The user's explicit requirements are to prefer Trivy Operator reports when it is installed, and to use app logic to scan when it is absent. Operator installation must remain optional. Preserve TDD, Angular conventional commits, and no co-author trailers.

The primary flow detects available report APIs, uses Operator reports when present, and otherwise lets the user select a workload image or enter an image reference for an app scan. Both sources use native host controls. The fallback requires neither Operator CRDs nor a scanner deployment in the cluster. Direct image scanning also works when workload discovery is unavailable or Kubernetes RBAC denies a workload read; it retains the app's explicit host context without requesting Kubernetes resources.

## Approaches considered

| Approach | Trade-off | Decision |
|---|---|---|
| Go sidecar with Trivy's scanner library in process | Fits the SDK's language and avoids subprocesses; needs brokered OCI artifacts and a sandbox feasibility check | Recommended |
| Sidecar launching the Trivy CLI | Familiar CLI interface, but subprocess execution is forbidden by the existing sandbox | Reject |
| Operator-only app or external scanner server | Less local scanning code, but fails the operator-free requirement | Reject as the sole implementation; reuse Operator reports as the preferred source |

## Facts verified in the existing platform

Inspected host baseline: `d3fd0618239b91ec83aa354bea57beeea41c464a` on `dev`. This is a source baseline, not a claim of tested compatibility.

- Extension API support is 0.3–0.7. Executable apps are packages with per-platform binaries, supervised JSON-RPC lifecycle and MCP operations.
- The Go SDK module is `github.com/srelens/srelens/sdk/go`. It is in the host monorepo and not separately published; development must prepare an exact host checkout and use its SDK.
- `sidecar.HostFrom(ctx).Read(ctx, callContext, binding)` reads granted bindings with an explicit cluster and namespace. The SDK also supplies cancellable stream handlers.
- `network.http` is a fixed GET with no caller inputs and a 4 MiB text/JSON response. It cannot transfer arbitrary OCI layers or the Trivy database as the app needs.
- Workload summary readers are available for Deployments, StatefulSets and DaemonSets, but their current list summaries do not expose container images. `k8s.listPods` is not an app-grantable reader.
- App resource pages require a custom-resource binding. They cannot currently render arbitrary executable scan reports. Sidecar operations are exposed through MCP, not a complete native scan page.
- CRD checking already distinguishes served, absent and unknown internally (`crd::Served`), but the sidecar has no typed binding-availability callback. Reuse that check; do not parse human-readable error strings to select a source.
- Limits are 256 MiB memory, one CPU, 1 GiB scoped data, 100,000 data entries and a 30-second ordinary request deadline. Long scans need a stream with cancellation, not a larger global request timeout.
- Windows and suitable Linux desktops run sidecars. macOS remains refused pending the host's watchdog/Seatbelt validation; the web host refuses executable apps.

Trivy candidate: `v0.75.0`, commit `591e9799316a602e703f0b484f6c6d7b234ec8f3`; its `go.mod` requires Go 1.27.0. Its artifact package exports `NewRunner` and `Runner.ScanImage`. Treat the candidate as unvalidated until the feasibility milestone passes. Trivy's scanner API is pinned implementation detail, not the app's public contract.

## Architecture

1. Host-owned UI pins the cluster, namespace and app revision. A typed availability check discovers declared Operator report bindings without reading a namespace-specific controller Deployment or requiring a fixed installation name.
2. When report APIs are served, declared custom-resource reads/inspections supply Operator findings. The executable adapter normalizes them for native tables, retains source metadata, and does not pull an image or DB merely to display an existing report.
3. When the report APIs are confirmed absent, the user can enter an image or select a workload image. A Go sidecar handles a scan stream, obtains OCI image and database artifacts through the host broker, then scans their local representation with the pinned Trivy library.
4. The host performs registry access, authentication and digest verification. Kubeconfig and registry credentials never enter the sidecar. Artifact paths stay inside this app's data directory; no caller supplies a filesystem path.
5. The sidecar stores a bounded normalized report and emits progress, findings and a terminal state. Native host components render the data. No app JavaScript, iframe or HTML renderer is shipped.

All scanner updates, telemetry, VEX downloads and analyzer network lookups are disabled. Fallback scanning is offline after broker acquisition. Start fallback with OS/package vulnerability scanning; locally running secret, configuration, RBAC, infrastructure, compliance and license scans is out of scope for the first release. Those distinctions do not prevent viewing existing Operator reports for supported categories.

## Operator-first source selection and details

Operator CRD definitions inspected at commit `5171971e35c7b1d8a0e47a94a2326da4d97ff417` identify these report APIs under `aquasecurity.github.io`. Negotiate each binding's served version (currently `v1alpha1`) through the host; check actual availability independently.

| Report category | Namespaced kind | Cluster-scoped kind |
|---|---|---|
| Vulnerabilities | VulnerabilityReport | ClusterVulnerabilityReport |
| Configuration | ConfigAuditReport | ClusterConfigAuditReport |
| RBAC | RbacAssessmentReport | ClusterRbacAssessmentReport |
| Infrastructure | InfraAssessmentReport | ClusterInfraAssessmentReport |
| SBOM | SbomReport | ClusterSbomReport |
| Compliance | — | ClusterComplianceReport |
| Exposed secrets | ExposedSecretReport | — |

Use the exact plural names from the pinned definitions. Preserve workload/container references, severity/check summaries, finding IDs, titles/descriptions, installed/fixed versions when applicable, references, scanner metadata, artifact digest and report timestamp. Exposed-secret finding metadata is shown, but match text is redacted before rendering, normalization persistence, logs or export. Large SBOM/compliance details are paged or fetched on demand; never put an entire unbounded report on the wire.

Source-selection rules:

- Any served Operator report API selects the Operator source for the categories it provides. Do not start a duplicate local scan automatically. CRDs indicate a usable report API, not proof that the controller is currently healthy.
- Only a successful discovery result confirming all relevant report APIs absent selects app scanning automatically.
- Discovery or report-read refusal stays visible as unknown/unreadable with its reason and retry. The user may explicitly choose an app scan; a failure is never relabeled "Operator not installed".
- Empty report lists say "No reports yet"; absent/stale workload coverage says "Not scanned" or carries the report age. Offer an explicit app scan for missing/stale image-vulnerability coverage. Do not silently claim fallback image scanning supplies configuration, RBAC or compliance results.
- Keep each report's `source` (`operator` or `app`) and cluster/namespace/subject identity. Prefer the Operator report for matching coverage; do not sum duplicate Operator and app reports. Preserve older/manual results with their provenance.
- A cluster-scoped report stays cluster scoped when the namespace picker changes. Do not associate a ReplicaSet/Pod report with a Deployment by name guessing; follow proven owner identity or show the reported resource as-is.
- Removing/installing the Operator or changing clusters refreshes availability and source choice without leaking data between contexts.

## Generic host prerequisites

These are proposed extensions to the platform, not APIs that exist today. Their exact contracts are validated by the feasibility task before implementation.

**Binding availability:** expose the existing served/absent/unknown result for declared bindings through checked `extensions.bindingAvailability` and SDK `host/bindingAvailability` calls. Accept an explicit context and at most 16 binding names; return binding, state, served version/scope when known and reason on failure. Check app revision, grant and context first. This is not arbitrary discovery access.

**Workload images:** a read-only, app-grantable `k8s.listWorkloadImages` binding, fixed to one of Deployment, StatefulSet or DaemonSet. Return namespace, kind, name, UID, resourceVersion, container name/type and image reference. Include regular and init containers; exclude environment variables, Secret references and credentials. A direct scan does not call this reader.

**OCI acquisition:** a scoped `network.fetchOciArtifact` binding and `host/fetchOciArtifact` broker method. The manifest fixes allowed registries/repository prefixes; the caller supplies an image/database reference and target platform. The host resolves tags to digests, validates registry authentication endpoints and redirects against the grant, verifies every blob digest and streams a local archive into the app's data directory. Return only an app-relative archive path, canonical digest and byte count. Refuse an artifact that exceeds the remaining 1 GiB data budget. Use atomic files and refuse symlink/path traversal; never add general filesystem access. Anonymous public-registry bearer-token exchanges remain host-owned.

**Executable screens/streams:** generic operation pages and native tables backed by executable operations, plus a checked bridge to SDK scan streams. Validate scalar inputs, app revision and results; pin view context and cancel on view closure, disable or update. Reuse existing table, picker, status, app-stream and error components. Scan progress is a typed data stream, not an ordinary request held past its 30-second deadline.

New manifest-visible behavior requires a new preview API line, expected 0.8 while this baseline is current. Extend the sidecar protocol for the new broker call, preserve old supported contracts, regenerate schemas/Go types and test old clients. Do not claim the current `^0.7` host supports these additions. If API 1.0 lands independently first, follow its additive-version rules instead.

## App behavior and data contract

Production ID: `org.srelens.trivy`. Unsigned local testing uses a nonreserved ID such as `com.example.trivy`. First app version is `0.1.0` preview, published only after acceptance.

- Manual image input accepts an OCI reference of at most 512 bytes and an explicit target platform (`linux/amd64` or `linux/arm64`). A tag is resolved once; reports and reuse keys refer to the resulting digest and platform.
- Workload discovery for fallback scanning includes regular and init-container images for Deployments, StatefulSets and DaemonSets. Fallback scans of Jobs, CronJobs and bare Pods are later additions; existing Operator reports for any supported subject remain viewable.
- One scan runs at a time. Cancel stops acquisition and scanning, removes partial artifacts and preserves any previous completed report with its age shown.
- Native screens: Overview, Images, Reports and Findings. Display source, report category and subject, progress, image digest, scan/report time, scanner version, database digest/age for app scans and Critical/High/Medium/Low/Unknown totals. Each severity carries its name. A field not supplied by an Operator report is unknown, never invented from local scanner metadata.
- Findings expose vulnerability ID, severity, package, installed version, fixed version, target and title. List requests return at most 100 rows with a cursor, not an unbounded JSON result. Do not deduplicate distinct package/target occurrences solely by CVE ID.
- Persist at most 10 completed reports. Evict oldest reports and disposable image artifacts before acquisition; preserve the active database where it fits. Reuse only matching digest, platform, engine version and database digest. A DB older than 24 hours is visibly stale and must not produce an unqualified clean result.
- A failed scan, empty input, unsupported platform, failed read, DB failure, cancellation, timeout or disk/memory refusal has its own state and reason. Only a completed supported scan can report zero vulnerabilities.

Proposed app interface: scan stream `scan {clusterId, namespace?, image, platform}`; ordinary operations `source-status {clusterId, namespace?}`, `list-reports {clusterId, namespace?, cursor?, limit?}`, `list-images {clusterId, namespace?}` and `findings {reportId, cursor?, limit?}`. Default report/finding limit is 100, with 1–100 accepted. These names and limits are held by tests; the host bridge must verify the report belongs to the current app and selected context.

## Repository and distribution

Use a small Go module with `cmd/trivy-sidecar`, `internal/operator`, `internal/scanner`, `internal/reports` and `internal/workloads`, plus `manifest.json`, `compatibility.json`, packaging scripts and CI. Keep platform additions in the host repository. Do not duplicate the JSON-RPC SDK or fork Trivy.

Prepare `.host` at the pinned compatibility revision and use `replace github.com/srelens/srelens/sdk/go => ./.host/sdk/go` for the unpublished SDK. After host prerequisites land, update the recorded revision and repeat compatibility tests. The release packages only actual tested binaries under `bin/<platform>/`, README, license and `icons/icon.svg`; DB/artifact caches are runtime data, not unsupported package payloads.

Initial execution targets: `linux-amd64`, `linux-arm64` and `windows-amd64`. A cross-compiled binary is not proof of sandbox support; test each claimed platform. macOS binaries enter the manifest only after the host's gate and app acceptance pass there. Native host packer/digest verification and the existing `APP_SIGNING_PRIVATE_KEY` publisher workflow produce the signed package; catalog publication follows successful tests.

## Acceptance and sequencing

First prove one real offline scan under existing sandbox limits on Linux and Windows, including filesystem syscall behavior, cancellation and memory measurement. If this fails, record the evidence and revise the scanner integration; do not ship a weakened sandbox or silently substitute an Operator/server dependency.

Pre-release acceptance uses a cluster with no Trivy Operator CRDs or deployment. Install a candidate package through Settings → Apps, scan a pinned known-vulnerable fixture and a supported zero-findings fixture, verify workload discovery and native results, deny RBAC and registry access, cancel a scan, crash/restart the sidecar, and disable/update/remove the app. All nine #521 executable criteria require real-supervisor evidence. Inspect narrow and wide UI panes. Record tested revisions, DB/image digests and platform results before catalog publication. Once publication is requested and completes, repeat installation from the signed catalog before marking the reference-app milestone complete.

Also run acceptance with Trivy Operator installed: available report categories and full finding metadata render from the Operator; no local image/DB pull occurs just to view them. Check empty/stale reports, missing optional kinds, denied discovery/report reads, cluster-scoped resources, provenance/deduplication and install/remove transitions. Exposed-secret matches stay redacted in the UI and stored normalized reports. Missing fallback configuration/compliance coverage remains explicitly unavailable.

## Sources

- [Executable SDK milestone](https://github.com/srelens/srelens/issues/521)
- [Host manifest contract](https://github.com/srelens/srelens/blob/d3fd0618239b91ec83aa354bea57beeea41c464a/docs/extensions/manifest.md)
- [Host sidecar protocol](https://github.com/srelens/srelens/blob/d3fd0618239b91ec83aa354bea57beeea41c464a/docs/extensions/sidecar-protocol.md)
- [Go SDK](https://github.com/srelens/srelens/blob/d3fd0618239b91ec83aa354bea57beeea41c464a/sdk/go/README.md)
- [Trivy scanner source](https://github.com/aquasecurity/trivy/blob/591e9799316a602e703f0b484f6c6d7b234ec8f3/pkg/commands/artifact/run.go)
- [Trivy network/offline requirements](https://github.com/aquasecurity/trivy/blob/591e9799316a602e703f0b484f6c6d7b234ec8f3/docs/guide/advanced/air-gap.md)
- [Trivy Operator report definitions](https://github.com/aquasecurity/trivy-operator/tree/5171971e35c7b1d8a0e47a94a2326da4d97ff417/deploy/helm/crds)
