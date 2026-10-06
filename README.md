# Trivy app for srelens

Planned executable reference app for [srelens/srelens#521](https://github.com/srelens/srelens/issues/521), in a separate repository alongside `extension-cert-manager`.

**Prefer Trivy Operator when it is present; run app scans when it is absent.** The app will discover the cluster's Operator report APIs and use their reports, findings and metadata. Without those APIs, it will scan container images using Trivy's Go scanner in a supervised srelens sidecar. Users can enter an image reference or select an image discovered from a workload. Kubernetes access and artifact downloads go through the host broker; the scanner gets no kubeconfig and makes no direct network requests.

## Current status

The current development build has native Overview, Images, Reports and Findings screens, broker-backed workload discovery, all twelve Trivy Operator report readers and bounded private report storage. It selects Operator reports when served and preserves discovery/read errors. Reports retain source, age, cluster, namespace and resource identity; exposed-secret match values are redacted.

**Live app image scanning is not implemented yet.** The in-process scanner has passed pinned offline-fixture checks, but production OCI acquisition, in-flight cancellation and production database memory acceptance remain open. The measured current database is 1,477,152,768 bytes unpacked (1.38 GiB), exceeding the host's 1 GiB app-data budget before image layers or report storage. A Trivy-specific 2 GiB allowance is awaiting the user's decision; global limits have not changed.

The local reader build uses extension API 0.8 and sidecar protocol 0.2.0 from host commit `b1f430b3d2ee1ce2d8a08bd323865861b6ef9d14`. The signed macOS reader package passed real workload discovery through the production registry and OS sandbox without MCP. The original signed fixture preview remains separate. Windows AppContainer execution and release/catalog acceptance are still pending. No package has been published.

- [Design](docs/superpowers/specs/2026-10-05-trivy-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-05-trivy-executable.md)
- [Feasibility evidence and reproduction](docs/feasibility.md)
- [Local reader testing and acceptance](docs/local-readers.md)
- [Host contract and proposed scanning additions](docs/host-contract.md)
- [Contributor rules](AGENTS.md)

The first milestone requires real Linux and Windows sandbox execution and an installable native package. It must fit the host's resource and package limits before production implementation proceeds. Prepare the pinned host SDK and checksum-guarded Trivy compatibility source as described in the feasibility document before running Go commands.

## First release

- Automatically prefer available Trivy Operator reports, showing vulnerabilities, configuration/RBAC/infrastructure checks, SBOM, compliance and exposed-secret finding metadata where the cluster serves those report kinds.
- Keep report source and age visible. Missing reports, denied reads and failed discovery are distinct states; no automatic duplicate scan while Operator reports are the selected source.
- Scan a public container image directly, without workload discovery or Operator CRDs being a prerequisite for the scan itself.
- Discover regular and init-container images from Deployments, StatefulSets and DaemonSets through a narrow broker reader.
- Show native scan progress, severity totals, findings and fixed versions.
- Keep reports and the vulnerability database only in the app's scoped data directory.
- Ship a signed `.srelens-extension` package with per-platform binaries and the official Trivy logo.

Linux and Windows are the initial scanner execution targets. The current macOS reader package has passed a supervisor/sandbox test; production scanning has its own acceptance gates. The web host currently refuses executable apps. Private-registry fallback scans are later work. Operator integration is part of the first release, while Operator installation remains optional.

Development uses TDD, Angular conventional commits, and no co-author trailers. Creating a GitHub repository, opening a PR and publishing releases are separate follow-up actions.
