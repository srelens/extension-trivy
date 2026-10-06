# Trivy app for srelens

Planned executable reference app for [srelens/srelens#521](https://github.com/srelens/srelens/issues/521), in a separate repository alongside `extension-cert-manager`.

**Prefer Trivy Operator when it is present; run app scans when it is absent.** The app will discover the cluster's Operator report APIs and use their reports, findings and metadata. Without those APIs, it will create a temporary Kubernetes Job running the official Trivy container and collect its results. Users can scan the selected namespace or an image discovered from a workload. A small controller uses the host broker; scanner execution and database/image downloads happen in the cluster.

## Current status

The current development build has native Overview, Images, Reports and Findings screens, broker-backed workload discovery, all twelve Trivy Operator report readers and bounded private report storage. It selects Operator reports when served and preserves discovery/read errors. Reports retain source, age, cluster, namespace and resource identity; exposed-secret match values are redacted.

**In-cluster Job scanning is being implemented.** The user selected this fallback on 2026-10-06, superseding the local in-process scanner and OCI acquisition plan. Normal controller packages now use only the SDK and Go standard library. The previous scanner prototype is preserved as an optional nested module in `tools/local-scanner`; it is excluded from normal builds/tests. Local scanner/database storage is no longer required, so the Trivy-only data exception is being removed in favor of the ordinary 1 GiB limit.

The local reader build uses extension API 0.8 and sidecar protocol 0.2.0 from host commit `b1f430b3d2ee1ce2d8a08bd323865861b6ef9d14`. The signed macOS reader package passed real workload discovery through the production registry and OS sandbox without MCP. The original signed fixture preview remains separate. Windows AppContainer execution and release/catalog acceptance are still pending. No package has been published.

- [Current design](docs/superpowers/specs/2026-10-06-trivy-job-fallback-design.md)
- [Current implementation plan](docs/superpowers/plans/2026-10-06-trivy-job-fallback.md)
- [Feasibility evidence and reproduction](docs/feasibility.md)
- [Local reader testing and acceptance](docs/local-readers.md)
- [Host contract and proposed scanning additions](docs/host-contract.md)
- [Contributor rules](AGENTS.md)

Prepare the pinned host SDK with `scripts/prepare_host.py` before running normal Go commands. Trivy source and fixtures are needed only to reproduce the optional historical scanner proof. The controller still requires actual platform sandbox acceptance before claiming release compatibility.

## First release

- Automatically prefer available Trivy Operator reports, showing vulnerabilities, configuration/RBAC/infrastructure checks, SBOM, compliance and exposed-secret finding metadata where the cluster serves those report kinds.
- Keep report source and age visible. Missing reports, denied reads and failed discovery are distinct states; no automatic duplicate scan while Operator reports are the selected source.
- Scan a public container image directly, without workload discovery or Operator CRDs being a prerequisite for the scan itself.
- Discover regular and init-container images from Deployments, StatefulSets and DaemonSets through a narrow broker reader.
- Show native scan progress, severity totals, findings and fixed versions.
- Keep bounded reports in the app's scoped data directory; scanner databases and image layers live only in the temporary cluster Job.
- Ship a signed `.srelens-extension` package with per-platform binaries and the official Trivy logo.

The scanner runs as a Linux container in Kubernetes; controller platform acceptance remains separate. The current macOS reader package has passed supervisor/sandbox and native UI checks. The web host currently refuses executable apps. Private-registry fallback scans are later work. Operator integration is part of the first release, while Operator installation remains optional.

Development uses TDD, Angular conventional commits, and no co-author trailers. Creating a GitHub repository, opening a PR and publishing releases are separate follow-up actions.
