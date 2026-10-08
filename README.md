# Trivy app for srelens

Executable development app for [srelens/srelens#521](https://github.com/srelens/srelens/issues/521), in a separate repository alongside `extension-cert-manager`.

**Prefer Trivy Operator when it is present; run app scans when it is absent.** The app will discover the cluster's Operator report APIs and use their reports, findings and metadata. Without those APIs, it will create a temporary Kubernetes Job running the official Trivy container and collect its results. Users can scan the selected namespace or an image discovered from a workload. A small controller uses the host broker; scanner execution and database/image downloads happen in the cluster.

## Current status

The current development build has native Overview, Images, Reports and Findings screens, broker-backed workload discovery, all twelve Trivy Operator report readers and bounded private report storage. It selects Operator reports when served and preserves discovery/read errors. Reports retain source, age, cluster, namespace and resource identity; exposed-secret match values are redacted.

**In-cluster Job scanning is implemented with explicit Scan namespace and Scan image operations.** The user selected this fallback on 2026-10-06, superseding the local in-process scanner and OCI acquisition plan. Normal controller packages now use only the SDK and Go standard library. The previous scanner prototype is preserved as an optional nested module in `tools/local-scanner`; it is excluded from normal builds/tests. Local scanner/database storage is no longer required, so the Trivy-only data exception was removed in favor of the ordinary 1 GiB limit.

The controller uses extension API 0.8 and sidecar protocol 0.2.0 from pinned host commit `c72ba93dc456312ccef02f589ca088cd596d733d`. Images use bounded cursor pages across Deployments, StatefulSets and DaemonSets, so all-namespace inventories can exceed 1,000 container images. The signed package read all 1,880 container images across 59 M01 namespaces in 17 pages through the production registry and macOS sandbox. Previous container-scan acceptance is recorded in [Local container scans](docs/local-container-scans.md). The signed macOS controller passed real namespace/image scans, registry failure and cancellation through the production registry and OS sandbox. The test namespace produced 17 findings and the image one critical vulnerability. Workload discovery passed through the production registry and OS sandbox without MCP. The original signed fixture preview remains separate. Windows AppContainer execution and release/catalog acceptance are still pending. No package has been published.

- [Current design](docs/superpowers/specs/2026-10-06-trivy-job-fallback-design.md)
- [Current implementation plan](docs/superpowers/plans/2026-10-06-trivy-job-fallback.md)
- [Feasibility evidence and reproduction](docs/feasibility.md)
- [Container scan acceptance](docs/local-container-scans.md)
- [Large inventory and UI acceptance](docs/local-paged-inventory.md)
- [Historical reader testing and acceptance](docs/local-readers.md)
- [Host contract and proposed scanning additions](docs/host-contract.md)
- [Contributor rules](AGENTS.md)

Prepare the pinned host SDK before running normal Go commands:

```bash
python3 scripts/prepare_host.py
go test -race ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
CGO_ENABLED=0 go build -trimpath -o bin/trivy-sidecar ./cmd/trivy-sidecar
```

The host additions merged into `dev` in [srelens/srelens#842](https://github.com/srelens/srelens/pull/842) on 2026-10-08. The SDK pin and recorded acceptance above still identify the exact host revision tested locally; they do not claim acceptance against a newly released host.
CI fetches the exact SDK revision, runs controller race and contract tests, and
builds all four declared controller platforms. Building a platform does not
establish sandbox acceptance on that platform.
 Trivy source and fixtures are needed only to reproduce the optional historical scanner proof. The controller still requires actual platform sandbox acceptance before claiming release compatibility.

## First release

- Automatically prefer available Trivy Operator reports, showing vulnerabilities, configuration/RBAC/infrastructure checks, SBOM, compliance and exposed-secret finding metadata where the cluster serves those report kinds.
- Keep report source and age visible. Missing reports, denied reads and failed discovery are distinct states; no automatic duplicate scan while Operator reports are the selected source.
- Scan a public container image directly, without workload discovery or Operator CRDs being a prerequisite for the scan itself.
- Discover regular and init-container images from Deployments, StatefulSets and DaemonSets through narrow, paginated broker readers. Use Next page and Previous page to browse large inventories; filtering searches the current page.
- Show native scan progress, severity totals, findings and fixed versions.
- Keep bounded reports in the app's scoped data directory; scanner databases and image layers live only in the temporary cluster Job.
- Ship a signed `.srelens-extension` package with per-platform binaries and the official Trivy logo.

The scanner runs as a Linux container in Kubernetes; controller platform acceptance remains separate. The current macOS reader package has passed supervisor/sandbox and native UI checks. The web host currently refuses executable apps. Private-registry fallback scans are later work. Operator integration is part of the first release, while Operator installation remains optional.

Development uses TDD, Angular conventional commits, and no co-author trailers. The implementation is reviewed in this repository; signed release and catalog publication remain separate follow-up actions.

## Run a namespace check

Open **Apps → Trivy → Scan namespace**, select a namespace and press **Scan namespace**. Approve the host confirmation to create its temporary Job. If the namespace's vulnerability/configuration report APIs are served, the app uses those Operator categories; missing categories run in the Job. Discovery failures are shown and do not select fallback scans.

The page shows discovery, scanning and saving phases. **Cancel** stops the scan and cleans up its owned Job and reader permissions. Open **Findings** on the completed result, or reopen it under **Reports**. Reports retain the last ten successful scans; a failure leaves prior reports available. To scan an individual image, use **Scan image** on an Images row or open the Scan image page.

The digest-pinned Trivy 0.75.0 container scans public images and namespace configuration. Namespace images use Trivy's default image platform (recorded in finding details); image scans use the scan Job's node architecture. Mixed-architecture workload coverage is not inferred. Private registry credentials, node scans, compliance, SBOM and secret scanning are not supplied by fallback. Operator categories remain available where served. The Job uses up to one CPU, 1 GiB memory and 16 GiB temporary storage, with a 20-minute deadline. Its database and image downloads stay in the cluster.
