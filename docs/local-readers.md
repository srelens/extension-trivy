# Local reader testing

This is a development reader build, not the completed Trivy scanning app.
It runs `cmd/trivy-sidecar` with the Go SDK from host commit
`b1f430b3d2ee1ce2d8a08bd323865861b6ef9d14`, prepared in `.host-v0.2`.
The old `.host` fixture-proof checkout is preserved independently.

Prepare and verify from this checkout:

```sh
python3 scripts/prepare_host.py --source /path/to/srelens
python3 scripts/prepare_trivy.py
python3 scripts/prepare_fixtures.py
python3 -m unittest discover -s scripts -p 'test_*.py' -v
go test -race ./...
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags='-s -w' \
  -o bin/darwin-arm64/trivy-sidecar ./cmd/trivy-sidecar
```

The local host commit has not been pushed. Until it is available remotely,
`--source` must point to a local host repository containing that exact commit.
Package the binary with `manifest.json` as `extension.json`, `icons/icon.svg`,
`LICENSE`, and a README containing `THIRD_PARTY_NOTICES.md`. Use the host's
package tool and the trusted publisher key; do not put that key in this repo.

In the updated local Srelens desktop, open **Apps → Trivy → Overview**.
Choose the cluster in the rail before opening a page. Existing tabs remain
pinned to their original cluster and installed app revision. The namespace
picker can narrow all three readers; cluster-scoped reports remain explicit.

- **Overview** checks all twelve Operator report APIs. Discovery failures say
  unknown and show their reason. Only confirmed absence selects the app source.
- **Images** shows Deployment, StatefulSet and DaemonSet images, including
  regular and init containers, with workload identity. This is inventory,
  not a scan result.
- **Reports** lists served Operator reports and retained normalized reports.
  Select a report to open **Findings**, where applicable source, age, severity,
  fixed version and subject are preserved. Exposed-secret match text is removed.

## Acceptance recorded on 2026-10-06

A signed reader package was installed in the local desktop's app store. Its
operations ran through the production registry, real kubeconfig and macOS
sandbox, without an MCP server. On `kind-srelens-demo`:

- All twelve Operator report APIs were confirmed absent.
- Four workload containers were returned: coredns, local-path-provisioner,
  kindnet-cni and kube-proxy. No environment or Secret data was requested.
- Reports returned an empty list because no Operator reports or app scans
  existed. This does not establish that the cluster has no vulnerabilities.
- All three operation RPCs completed; none failed, timed out or were refused.
  The sidecar used 5,816,920 bytes of RAM at inspection, within the unchanged
  256 MiB limit. Its CPU allowance remained 1 CPU.

The production UI components were driven and inspected at wide and narrow
widths in a browser harness with clearly identified fixture data. Overview,
Images and Reports were also driven with a captured response from the live
sandbox test, explicitly labeled as a snapshot with live queries disabled.
Host follow-up `635d9c1e9687d5e465e36fc64f67829a49aee3ba` keeps shared scalar
metadata above the table rather than repeating the cluster ID in every row;
two regression tests, operation route/navigation tests and typecheck pass.
Differing row identities remain visible, including when filtering. The user's
2026-10-06 native screenshot confirms Images renders on M01: namespace
`ai-services`, Deployment `ollama-gpu`, regular container `ollama`, image
`ollama/ollama:latest`. This confirms native rendering and inventory for that
cluster; it does not establish Operator availability or successful image scans.
Backend live acceptance and browser snapshot inspection remain separate evidence.

Host verification passed `cargo test --workspace` (4,243 tests, 32 ignored),
the complete frontend suite (7,767 tests in 448 files), typecheck, production
build and the Go SDK race suite. Frontend coverage was 92.01% lines, 85.12%
branches and 87.24% functions, above the unchanged floors. The app race suite
and manifest/preparation tests passed. Served Operator payloads, RBAC failures,
secret redaction, incomplete reports and aging caches have contract tests;
a real installed Operator has not yet been tested end to end.

## Still required for the whole app

There is no scan operation in this reader package. Verified host OCI acquisition,
production Trivy database loading, image scans and cancellation remain open.
The measured database is 1,477,152,768 bytes unpacked. The user approved a
Trivy-specific 2 GiB aggregate allowance on 2026-10-06; memory, CPU, other apps'
data limits and sandbox isolation remain unchanged. Even with that allowance,
acquisition must fit images, staging and reports within the budget,
and actual scanner RAM/cancellation acceptance must pass. Windows execution,
signed release and catalog publication are separate outstanding gates.
