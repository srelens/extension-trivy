# Working in this repository

Read `README.md`, the design and the implementation plan before changing code.

## Required workflow

- Use TDD for every behavior change: add a meaningful failing test, run it, implement the smallest fix, then run it again.
- Use Angular conventional commits, such as `feat(trivy): scan an image in the sandbox` or `fix(trivy): preserve failed scan states`.
- Do not add co-author trailers. Do not create PRs or publish unless the user requests those actions.
- Prefer the existing srelens Go SDK and standard library. Pin Trivy and host revisions; never build a release against a floating branch.
- Keep generic host changes in the srelens repository and follow its CONTRIBUTING.md, docs/DEVELOPMENT.md and AGENTS.md.

## App boundaries

- Trivy Operator must not be required to install, start or scan with this app.
- Prefer Operator reports when their APIs are available. Only confirmed absence selects automatic local scanning; a denied/failed lookup is unknown, not absence. Offer an explicit local scan for missing/stale coverage.
- Preserve source, report age and workload/container identity. Do not combine Operator and local counts as if they were independent vulnerabilities.
- Exposed-secret report matches must not appear in native findings, logs, normalized stored reports or exports; show finding metadata instead.
- Run Trivy in process. Never launch `trivy`, `kubectl`, a shell, Docker or another subprocess from the sidecar.
- No kubeconfig, ambient network, registry credentials or files outside `sidecar.DataDir(ctx)`.
- stdout is JSON-RPC only; logs go to stderr without credentials or secret findings.
- Keep the cluster and namespace explicit through calls, routes, reports and cache keys.
- A failed, cancelled, unsupported, incomplete or stale scan is never a clean scan or a zero count.
- Do not disable the sandbox, increase global limits or fabricate missing host APIs to make the prototype pass.
- Do not require Operator CRDs, Kubernetes scan Jobs or an external Trivy server as a fallback.

## Verification

During implementation run `go test -race ./...`, manifest/package checks and the real supervisor/sandbox checks specified in the plan. A unit-test fixture is not live acceptance. Drive each UI change in a browser harness and inspect wide and narrow panes.

Do not record a host revision as tested, publish a package or mark the executable milestone complete until its acceptance evidence exists.
