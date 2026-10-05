# Trivy app for srelens

Planned executable reference app for [srelens/srelens#521](https://github.com/srelens/srelens/issues/521), in a separate repository alongside `extension-cert-manager`.

**Prefer Trivy Operator when it is present; run app scans when it is absent.** The app will discover the cluster's Operator report APIs and use their reports, findings and metadata. Without those APIs, it will scan container images using Trivy's Go scanner in a supervised srelens sidecar. Users can enter an image reference or select an image discovered from a workload. Kubernetes access and artifact downloads go through the host broker; the scanner gets no kubeconfig and makes no direct network requests.

## Current status

This repository contains the design and implementation plan. It does not contain a runnable app, manifest or release yet. The existing host needs generic binding-availability, artifact-transfer and executable-result surfaces, plus a reader that exposes workload images, before this app can provide the complete experience.

- [Design](docs/superpowers/specs/2026-10-05-trivy-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-05-trivy-executable.md)
- [Contributor rules](AGENTS.md)

The first milestone proves an offline Trivy scan under the real Linux and Windows sandboxes. It must fit the host's current resource limits before production implementation proceeds.

## First release

- Automatically prefer available Trivy Operator reports, showing vulnerabilities, configuration/RBAC/infrastructure checks, SBOM, compliance and exposed-secret finding metadata where the cluster serves those report kinds.
- Keep report source and age visible. Missing reports, denied reads and failed discovery are distinct states; no automatic duplicate scan while Operator reports are the selected source.
- Scan a public container image directly, without workload discovery or Operator CRDs being a prerequisite for the scan itself.
- Discover regular and init-container images from Deployments, StatefulSets and DaemonSets through a narrow broker reader.
- Show native scan progress, severity totals, findings and fixed versions.
- Keep reports and the vulnerability database only in the app's scoped data directory.
- Ship a signed `.srelens-extension` package with per-platform binaries and the official Trivy logo.

Linux and Windows are the initial execution targets. macOS follows the host's sandbox validation gate; the web host currently refuses executable apps. Private-registry fallback scans are later work. Operator integration is part of the first release, while Operator installation remains optional.

Development uses TDD, Angular conventional commits, and no co-author trailers. Creating a GitHub repository, opening a PR and publishing releases are separate follow-up actions.
