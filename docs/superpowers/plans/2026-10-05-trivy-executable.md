# Trivy Executable App Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` to implement this plan task by task. Subagent-driven execution is an alternative only if the user selects it. Steps use checkboxes for tracking.

**Goal:** Ship a signed executable Trivy app that prefers available Trivy Operator reports and scans container images itself when the Operator is absent.

**Architecture:** A Go sidecar reads and normalizes available Operator reports through the broker, or embeds the pinned Trivy scanner for operator-free scans of broker-acquired artifacts. Generic host additions provide typed binding availability, workload-image discovery, OCI transfer and native executable screens/streams. The app contains no frontend bundle and no subprocess wrapper.

**Tech Stack:** Go 1.27.0 or later for the selected Trivy candidate, srelens Go SDK, Trivy v0.75.0 candidate, existing Rust registry/sandbox/protocol, React host components, Python/Node packaging conventions from cert-manager.

**Spec:** [Trivy design](../specs/2026-10-05-trivy-design.md). Read it before executing. Task 1 has a working feasibility prototype; [evidence](../../feasibility.md) records what passed and what blocks production work.

**Current ruling, 2026-10-06:** The user authorized local macOS implementation
and testing, executable packages up to 512 MiB, and a production-Trivy-only
2 GiB data allowance. Native reader UI is confirmed by the user's M01 screenshot.
Continue local OCI/scanner work under these allowances; historical Task 1
limits and cross-platform release gates below do not override this approval.
Production DB memory and cancellation still require measurement. Linux/Windows
runtime acceptance and signed release/catalog publication remain separate gates.

## Global constraints

- Trivy Operator must not be required to install, start or scan with this app.
- Prefer served Operator report APIs; confirmed absence selects automatic app scanning. Unknown/unreadable discovery is an error with retry, not absence. Missing/stale coverage permits an explicit app scan.
- Operator integration is in the first release: preserve source/category/subject/timestamp, avoid double-counting and redact exposed-secret matches from rendered, stored normalized and exported details.
- TDD: failing behavioral test → observed failure → minimal implementation → passing test → Angular conventional commit. No co-author trailers; no PR or publication without a user request.
- No subprocess, direct network, kubeconfig, Kubernetes Secret read, external scanner server or application HTML/JavaScript renderer.
- Keep the host's 256 MiB memory, one CPU and 30-second ordinary request limits. The user approved 2 GiB aggregate data for production `org.srelens.trivy` on 2026-10-06; other apps retain 1 GiB. Long scans use cancellable streams.
- One active scan, at most 10 completed reports, findings pages of 1–100 rows, 512-byte image references and a visible stale-DB threshold of 24 hours.
- Never claim a failed/incomplete/stale scan is clean. Pin cluster, namespace, app revision, image digest, target platform, engine version and DB digest.
- Inspected host baseline: `d3fd0618239b91ec83aa354bea57beeea41c464a`. Trivy candidate: `591e9799316a602e703f0b484f6c6d7b234ec8f3`, with one documented fd-chmod patch. Linux arm64 fixture execution is verified; this is not complete app/platform compatibility.
- Production implementation starts only after the feasibility/contract gate below passes and this design/plan is reviewed. Plan creation does not authorize release publication.

## Review focus

1. Operator installed/absent or optional report kinds missing: prefer Operator details when served, scan without it and avoid duplicate scans/counts (Tasks 3–6).
2. RBAC/registry failures and unsupported image analyzers: display failure or incomplete scope, never zero vulnerabilities or fabricated Operator absence (Tasks 2–5).
3. Mutable tags, multi-architecture images and repeated CVEs in different packages: digest/platform-correct reports and occurrence counts (Tasks 1, 2, 4).
4. Large layers/DBs, malicious archive paths and simultaneous scans: remain bounded and isolated; reject rather than raise global limits (Tasks 1, 2, 4).
5. Pane closure, cluster switch, app update or crash during a scan: cancel or visibly refuse stale ownership and recover cleanly (Tasks 2, 4–6).

## File responsibilities

Create during implementation, not as empty scaffolding:

- `go.mod`, `go.sum`, `compatibility.json`: pinned scanner/toolchain and exact prepared host SDK revision.
- `cmd/trivy-sidecar/main.go`: SDK registration, stdout/stderr and process exit only.
- `internal/scanner/scanner.go`, `scanner_test.go`: in-process offline scanning and cancellation.
- `internal/reports/reports.go`, `reports_test.go`: normalization, bounded persistence and pagination.
- `internal/workloads/workloads.go`, `workloads_test.go`: scoped broker discovery and image identities.
- `internal/operator/operator.go`, `operator_test.go`: availability/source choice, report readers, normalization and provenance.
- `manifest.json`, `icons/icon.svg`, `scripts/validate.py`, `scripts/package.py`, `scripts/sign.mjs`: executable contract, branded package and signatures.
- `tests/protocol_test.go`, `tests/package_test.py`, `tests/acceptance.md`: protocol/package checks and live evidence.
- `.github/workflows/validate.yml`, `release.yml`: verification and immutable signed packages, following cert-manager.
- `docs/feasibility.md`, `docs/host-contract.md`: measured spike results and the reviewed generic platform contracts.

## Task 1: Prove the scanner fits the sandbox

**Files:** Create `go.mod`, `go.sum`, `scripts/prepare_host.py`, `internal/scanner/scanner.go`, `internal/scanner/scanner_test.go`, `tests/protocol_test.go`, `docs/feasibility.md`, `docs/host-contract.md`. Keep generated fixtures/downloads outside git.

**Interfaces:** Introduce `ScanArchive(ctx context.Context, archivePath, dbDir string) (types.Report, error)` in `internal/scanner`. Paths are supplied by a test harness now and by the broker in production. The host-contract document owns exact broker/UI names, wire payloads and version negotiations proposed by the design.

- [x] Write `TestScanArchiveOffline` with a digest-pinned image/archive and DB fixture: assert a known vulnerability occurrence, a non-empty engine/DB identity, and no direct network or subprocess attempt. Add `TestUnsupportedIsNotClean`, `TestCancelledScanStops`, and archive path/symlink refusal cases.
- [x] Run `go test ./internal/scanner -run 'TestScanArchive|TestUnsupported|TestCancelled' -count=1`; observe failure before adding the scanner body.
- [x] Prepare the exact host checkout. Implement the smallest adapter around the pinned Trivy artifact API, disabling downloads, telemetry, updates, VEX and remote analyzer lookups. Use the scoped directory for all temporary files; validate the OCI archive representation Trivy actually accepts.
- [ ] Run the tests, then run the same binary under the real host supervisor/sandbox on Linux and Windows. Measure peak memory, disk, CPU and cancellation; verify archive mode-setting behavior in the sandbox. Use `go test -race ./...` and the host's `sandbox_conformance` suite.
- [ ] Record actual image/DB digests, versions, RSS, disk usage, outcomes and fixture preparation in `docs/feasibility.md`. Test regular/init containers, platform-specific artifacts and duplicate CVE occurrences in different targets.
- [ ] Finalize the host contract with exact scalar inputs, stream frames and proposed `host/fetchOciArtifact` request/response. Verify the contract against existing SDK/protocol/host source; do not describe proposed methods as existing ones.
- [ ] Verify a real stripped executable through the native package path. Current result: the native packer refuses the binary because it exceeds 64 MiB; gzip also exceeds the 16 MiB compressed limit. Revise integration/distribution for review before proceeding.
- [x] Commit the reviewed partial proof with an honest Angular subject such as `feat(trivy): add offline scanner feasibility prototype`. Do not imply the full gate passed.

**Gate:** The proof must fit 256 MiB memory, 1 GiB data and the current native package format, run without ambient network/subprocesses, and leave the host responsive on the required real platforms. If it does not, stop production implementation and report the measured constraint. Obtain review of the proof/contract before Task 2; do not bypass isolation, raise global limits or require an Operator/server.

**Partial evidence:** Linux arm64 scan/early-cancellation/health checks and all 14 Linux host conformance cases passed. Windows amd64 cross-compiles, but AppContainer execution is pending; Linux amd64 execution is also unverified. True in-flight cancellation remains unproven. A separately reproduced APK inventory-truncation diagnostic currently fails the desired completeness assertion and blocks production. [Host contracts](../../host-contract.md) remain unchecked proposals, including distribution, atomic aggregate-budget reservation and stable input-lifetime decisions. Regular/init-container discovery, production DBs and all subsequent tasks remain pending.

## Task 2: Add the generic host capabilities the proof requires

**Repository:** `srelens`, in an isolated feature checkout; do not alter unrelated user work.

**Files:** Workload reader registration and output types in `crates/registry/src/lib.rs`, `crates/kube/src/`; new `crates/registry/src/extensions/oci.rs` and `oci_tests.rs`; update `crates/plugin-host/src/manifest.rs`, `src/sidecar/broker.rs`, `sdk/protocol`, `sdk/go/sidecar` and generated protocol types. Native operation bridge and its tests belong in `crates/registry/src/extensions/`, `packages/core/src/lib/extensions.ts`, and `packages/ui-next/src/extensions/`. Update relevant schemas and `docs/extensions/`.

**Interfaces:** Implement the reviewed `docs/host-contract.md`: checked binding availability (`served`/`absent`/`unknown`), `k8s.listWorkloadImages`, `network.fetchOciArtifact`, the checked SDK broker calls, native operation pages and scan-stream bridge. Reuse `crd::Served`; its absence/failed-lookup distinction must survive the wire. OCI results contain an app-relative archive path, digest and bytes; no tokens or caller-chosen path. Workload results contain regular/init-container identities, not environment or Secrets.

- [ ] Add failing caller-payload tests for all new inputs, plus namespace/RBAC denial, served/absent/unknown report bindings, discovery permission failure, 16-binding availability limit, cluster scope, regular/init containers, tag resolution, platform selection, digest mismatch, ungranted registry/token realm/CDN redirect, corrupted archive, symlink/path traversal, cancellation and remaining-disk-budget refusal.
- [ ] Add failing native-operation tests: stale app revision, pinned context, unknown inputs, stream cancellation on pane close/disable/update, unsupported OS refusal and explicit read errors. Assert frames remain under the protocol's 4 MiB line limit.
- [ ] Run targeted Rust/Vitest tests and observe failures. Implement only the reviewed generic contracts; reuse existing HTTP policy, grants, secret injection, supervisor, stream manager and native result controls. Keep acquisition bounded and secrets entirely host-owned.
- [ ] Introduce the required extension/protocol API versions while preserving old clients. Regenerate committed schemas, capability catalog and Go protocol types. Check the Rust serde fields against the core/SDK camelCase caller payloads.
- [ ] Run `cargo test --workspace`, `pnpm test`, `pnpm typecheck`, `pnpm build`, and `go test -race ./...` in the host SDK. Drive operation screens at wide and narrow pane widths, including stream failures and retries.
- [ ] Commit separate reviewable host changes with Angular messages, for example `feat(extensions): broker scoped OCI artifacts`. Return their exact validated revision for app compatibility.

## Task 3: Deliver executable workload-image discovery

**Files:** Create `cmd/trivy-sidecar/main.go`, `internal/workloads/workloads.go`, `workloads_test.go`, `manifest.json`, `compatibility.json`; update `go.mod`/`go.sum` to use the validated host checkout from Task 2.

**Interfaces:** `ListImages(ctx context.Context, clusterID string, namespace *string) ([]WorkloadImage, error)` uses SDK host reads. `WorkloadImage` holds kind, namespace, name, UID, resourceVersion, container, containerType and image. Register `list-images` with scalar `clusterId` and optional `namespace`.

- [ ] Write failing tests asserting three declared workload bindings, explicit cluster/namespace, regular/init-container rows, shared-image identity preservation, RBAC failure with reason, and no Operator CRD request. A manual scan must not invoke discovery.
- [ ] Run `go test ./internal/workloads -count=1`; observe failure. Implement broker-only discovery and register the SDK operation. Use a nonreserved app ID for unsigned local testing.
- [ ] Test lifecycle/host callback messages with an in-memory SDK harness and the real supervisor; assert stdout is valid JSON-RPC and no credentials cross the pipe.
- [ ] Validate the manifest with the exact host parser and desktop policy, not JSON Schema alone. Write tested compatibility only after those checks pass.
- [ ] Commit: `feat(trivy): discover workload images through the broker`.

## Task 3a: Deliver Operator-first report integration

**Files:** Create `internal/operator/operator.go`, `operator_test.go`; extend `manifest.json`, SDK registration, normalized report types and protocol fixtures.

**Interfaces:** `SourceStatus(ctx context.Context, clusterID string, namespace *string) (SourceStatusResult, error)` consumes Task 2's typed binding availability. `ListOperatorReports(ctx context.Context, clusterID string, namespace *string, cursor string, limit int) (ReportPage, error)` reads only served declared bindings through SDK `Read`/`Resource`. Register `source-status` and `list-reports`; `ReportPage` carries category, source, subject, scanner/artifact identity, timestamp, rows and cursor. Defaults/maxima are 100; return cluster-scoped reports separately from namespace-filtered ones.

- [ ] Write failing tests for all 12 report kinds in the design, using real pinned CRD sample shapes. Assert report metadata/details, scanner version, timestamps, vulnerability fixed versions, category-specific check details, cluster/namespaced scope and exposed-secret match redaction. Large SBOM/compliance content must remain bounded/on-demand.
- [ ] Add source-selection tests: served report API → Operator source and zero OCI/DB acquisition calls; all absent → app source; failed discovery or report read → explicit unknown/error and retry. An empty list is "No reports yet", not absence or zero findings.
- [ ] Add tests for missing optional report kinds, stale reports, unknown owner lineage, duplicate Operator/app coverage, Operator installation/removal and cluster switching. Do not guess Deployment ownership from a ReplicaSet name or require a specific Operator installation namespace.
- [ ] Run `go test ./internal/operator -count=1`; observe failures. Implement the minimum adapter with existing custom-resource bindings, explicit per-binding availability and native typed results. Preserve complete supported metadata without inventing missing DB information.
- [ ] Run `go test -race ./...`, host manifest/policy validation and the SDK callback harness. Confirm report viewing does not start the local scanner or make registry requests.
- [ ] Commit: `feat(trivy): prefer operator reports with scoped details`.

## Task 4: Deliver cancellable scans and bounded findings

**Files:** Extend `internal/scanner`; create `internal/reports/reports.go`, `reports_test.go`; extend main registration and protocol tests.

**Interfaces:** Scan stream `scan {clusterId, namespace?, image, platform}` uses Task 2's OCI broker and Task 1's offline scanner when app scanning is selected or explicitly requested. Task 3a selects Operator data by default when available. Ordinary operation `findings {reportId, cursor?, limit?}` returns typed rows and a continuation cursor for either source. Define `Finding` fields exactly as the spec lists; retain source/category/subject, engine, DB where known, platform, digest and scan/report time with each report.

- [ ] Write failing tests for a known vulnerable image, a supported zero-findings image, mutable tags resolving to different digests, repeated CVEs in different packages/targets, stale DB (>24 hours), DB acquisition failure, unsupported analyzer scope, scan cancellation and two simultaneous scans. Test that Operator presence suppresses automatic local scans and missing/stale reports require an explicit app-scan action.
- [ ] Write persistence tests: default/max page size 100, reject limits outside 1–100, reject invalid cursors/report ownership, keep at most 10 completed reports, clean partial artifacts, preserve prior results with their timestamp, and refuse insufficient disk budget.
- [ ] Run `go test ./internal/scanner ./internal/reports -count=1`; observe failures. Implement one active scan, typed progress/finding/terminal frames and bounded reports using the scoped data directory. Reuse only matching digest/platform/engine/DB identities.
- [ ] Run `go test -race ./...` and real supervisor cancellation/crash/restart tests. Ordinary pagination calls must stay under 30 seconds; long scanning work stays on the stream.
- [ ] Commit: `feat(trivy): scan images and retain bounded findings`.

## Task 5: Deliver native app screens and package validation

**Files:** Extend `manifest.json`; add `icons/icon.svg`, package scripts, package tests, README installation/settings documentation and upstream license notices. Host-side UI fixes remain generic and in its own repository.

**Interfaces:** Declare Overview, Images, Reports and Findings using Task 2's reviewed operation-page contract. Show Operator/app source, available categories, report age and fallback scope. Use host namespace/image controls and findings tables; the app sends data only. Pin routes to cluster, app revision and report identity.

- [ ] Write failing manifest/package tests for operation names/inputs, mandatory executable package install, exact binary declarations, changed binaries/signatures, missing icon, unsupported API and preserved README/license notices. Reuse cert-manager's native packer/digest/signature flow.
- [ ] Validate wide/narrow host screens with a stubbed broker: Operator/app source, each supported category's details, progress, severity names/counts, filterable findings, fixed versions, stale reports/DB, unsupported platform, partial/failed scans, retry and cancellation. Include empty Operator lists, denied discovery, explicit fallback, exposed-secret match redaction, a complete scan with zero findings and a cluster switch while a scan is open.
- [ ] Implement the minimal manifest and package, then run Go tests, host parser/policy checks, native package verification and the browser harness. Confirm Operator reads happen only for served/granted bindings and that absence does not block installation or app scanning. No custom app frontend assets or baked-in DB archives belong in the package.
- [ ] Commit: `feat(trivy): package native scan and findings screens`.

## Task 6: Live acceptance, then signed release preparation

**Files:** Add `.github/workflows/validate.yml`, `release.yml`, `tests/acceptance.md`, CHANGELOG and release documentation; update compatibility only from actual results.

**Interfaces:** Native `.srelens-extension` packages carry tested Linux/Windows binaries and publisher signatures. Use `APP_SIGNING_PRIVATE_KEY` through GitHub secrets only; confirm this new repository is included in any selected-repository org-secret policy when a GitHub repository is created.

- [ ] Test the release workflow rejects missing/mismatched signing material, mismatched manifest versions and changed package files. Validate before publishing; sign manifest and native digest-list bytes and verify with the publisher public key.
- [ ] Run all app checks and the real supervisor on each claimed platform. Cross-compilation alone does not satisfy acceptance; do not declare macOS execution before its host gate passes.
- [ ] In a test cluster with **no Trivy Operator**, install the candidate package through Settings → Apps using the nonreserved development ID if it is unsigned. Verify direct scans, workload discovery, known vulnerable/zero-findings fixtures, counts, fixed versions, DB age, RBAC/registry failure, cancellation, resource limits and crash recovery. This proves pre-release behavior, not signed catalog installation.
- [ ] Repeat with Trivy Operator installed: use its reports/details without local acquisition, verify each available category, empty/stale/missing coverage, report/discovery RBAC denial, cluster-scoped data, source labels and deduplication. Install/remove the Operator while the app remains open and confirm safe source transitions and explicit fallback scans.
- [ ] Verify disable/update/remove terminate streams/processes and clean app-owned data as the host contract promises. Record evidence for all nine executable criteria in #521, exact host/app/DB/image revisions and inspected UI panes.
- [ ] Commit: `ci(trivy): validate and prepare signed executable releases`.
- [ ] Once explicitly requested, create/publish the GitHub app repository/release and update the signed catalog. Install that exact signed catalog release and repeat acceptance under its production ID before marking the Trivy reference-app milestone complete. Do not automatically close the whole SDK epic if other criteria remain.

## Next action

Finish Task 1's package/distribution and complete-inventory decisions, prove in-flight cancellation, obtain a Windows runner for real AppContainer execution and review the measured proof and proposed host contracts. Do not start production Tasks 2–6 while those gates remain open. No production host changes, remote repository creation or release publication has happened.
