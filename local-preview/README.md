# Trivy local preview

Development-only executable package for macOS arm64. It runs the existing
offline feasibility fixture through srelens's installed-app operation interface,
inside Seatbelt and the host's unchanged resource limits. It needs no Operator,
cluster access, network grant or subprocess.

The `scan-fixture` operation scans `image.tar` with the fixture database in its
private app data directory. It returns the image identity, engine version and
bounded vulnerability occurrences. Missing artifacts fail the request; they are
never a successful zero-findings result.

Install the native package locally, then find **Trivy local preview** in
**Settings → Apps**. Its **Details → Inspector** shows the process after the
first operation call. The current host exposes operations through MCP as
`plugin/org.srelens.trivy-preview/scan-fixture`; it does not yet render executable
operation screens. This preview contributes no cluster pages.

This package is not a release. Arbitrary image acquisition, Operator integration,
production report storage, native scan screens and the remaining feasibility
checks are pending. The known APK completeness limitation still blocks
production use; only the checked pinned fixtures are acceptance evidence.

## Preparing the local fixture

Prepare `.fixtures/runtime` as described in [feasibility.md](../docs/feasibility.md).
Install the package before seeding data. The host's private directory is
`settings.extensions.data/<name>` beside `settings.extensions.json`, where
`<name>` is the first 32 hex characters of SHA-256 of `org.srelens.trivy-preview`:
`a32a7e0e13520aed4b6655e0ea0968f0`. Create that directory with mode `0700` and
copy the contents of `.fixtures/runtime` into it. The fixture archive and database
are runtime data, not package payloads. Only this app's directory is used.

## Measured local acceptance

On 2026-10-05, the macOS arm64 desktop built from host
`ec264a683e8953eff190444938097a6ba5fac9be` verified the signed package, installed
it with unsigned apps disabled and invoked `scan-fixture` through its own MCP
server. The scan returned six vulnerability occurrences for pinned image
`sha256:055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1`
using engine `0.75.0+srelens.1`. The desktop Inspector reported a running process
under host-enforced memory limits. The package was 44,174,543 bytes compressed.
The real SDK operation and missing-artifact failure passed `go test -race ./...`
against that host SDK. This is fixture acceptance, not a live cluster scan.
