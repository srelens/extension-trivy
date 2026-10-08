# Trivy Job Fallback Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` inline, preserving
> the execution method already selected for this app. Steps use checkboxes.

**Goal:** Run fallback Trivy scans in temporary Kubernetes Jobs while keeping
Operator reports preferred and the local controller small.

**Architecture:** A generic checked host Job callback creates a constrained
Job, collects a bounded result and cleans up owned resources. The Go app
normalizes its JSON into the existing report store and native operation pages.

**Tech stack:** Existing Rust kube-rs/registry/protocol, Go SDK and standard
library, native React UI, official digest-pinned Trivy container.

**Spec:** [Job fallback design](../specs/2026-10-06-trivy-job-fallback-design.md).

## Global constraints

- TDD, Angular commits, no co-author trailers; local work only, no PR/publication.
- Prefer served Operator data; absence and discovery failure stay distinct.
- Default selected namespace, explicit Job action, one active scan.
- No local Trivy runtime/DB/image download; no Secret read or node collector.
- Local 256 MiB/one CPU/1 GiB data; Job one CPU/1 GiB RAM/16 GiB ephemeral limit.
- Job deadline 1200 seconds, TTL 600 seconds, no retries, owner-UID cleanup.
- At most ten completed reports, 20,000 findings and 100-row pages.

## Review focus

1. Mixed Operator availability must preserve available categories and missing scope.
2. A denied, failed, unschedulable or truncated scan must never appear clean.
3. Namespace/cluster/revision changes must not redirect an open scan or its cleanup.
4. Job replacement and host loss must not delete unrelated resources or leave reader RBAC.
5. Large/private images must report their real error and keep prior reports usable.

## Task 1: Retire the local scanner runtime path

**Files:** app `go.mod`, `go.sum`, `internal/scanner`, `internal/probe`,
`cmd/trivy-probe`, `cmd/prepare-db`, their historical tests, README/compatibility;
host `crates/registry/src/extensions/sidecars.rs`.
**Interfaces:** Production `go list -deps ./cmd/trivy-sidecar` contains only the
SDK and standard library. Optional local feasibility tools live in a nested
module with their original fixture/source pins.

- [x] Add a failing dependency test and change the quota test to expect defaults
  for production Trivy; run and observe both failures.
- [x] Move optional scanner/probe tools/tests into the separate module, adjust
  fixture/preparation paths, tidy production dependencies, remove the quota exception.
- [x] Verify production Go race tests, Python manifest/preparation tests and the
  CI-style host quota test; commit `refactor(trivy): run scans in the cluster`.

## Task 2: Add the generic scoped Job runner

**Files:** host `crates/registry/src/extensions/jobs.rs`, `jobs_tests.rs`,
`extensions.rs`, `lib.rs`; `crates/plugin-host/src/manifest.rs`, sidecar broker;
`sdk/protocol` types/methods/schema, `sdk/go/sidecar/host.go` and tests;
capability/manifest schemas and catalog.
**Interfaces:** `host/runJob {context, capability, inputs}` ->
`extensions.runJob {id, revision, context, namespace, capability, inputs}` ->
metadata plus a bounded app-relative result file. Job binding arguments fix
image/command/args/scalar inputs/RBAC; the spec fixes all host Pod/lifetime limits.

- [x] Write caller-payload and authorization tests, Job template/RBAC/readiness-volume tests,
  owner-UID/result-limit/failure/cancellation cleanup tests; observe failures.
- [x] Implement the smallest typed facade and broker/SDK callback, using existing
  resolver/grant checks and kube-rs. No new subprocess or local network surface.
- [x] Regenerate schemas/catalog/Go types; verify protocol conformance, SDK race
  tests, registry/desktop combined tests and Rust workspace checks.
- [x] Commit `feat(extensions): run scoped app Jobs` and record the exact SDK pin.

## Task 3: Normalize container reports and add scan streams

**Files:** app `internal/jobs/jobs.go`, `jobs_test.go`, `internal/app/app.go`,
`internal/operator/service.go`, `internal/reports`, `tests/app_test.go`,
`manifest.json`, `compatibility.json`, `scripts/prepare_host.py`.
**Interfaces:** `ScanNamespace(ctx, broker, scope)` and
`ScanImage(ctx, broker, scope, image)` call the Job binding; JSON parsers return
existing report Metadata/Findings. Streams expose phase and bounded terminal IDs.

- [x] Add failing namespace/image JSON normalization tests, missing/error/partial
  report refusal, source/severity/fixed-version/occurrence/secret-redaction tests,
  one-active-scan/cancellation and Operator preference tests; observe failures.
- [x] Implement standard-library parsers and SDK Job calls, preserve prior reports,
  register two stream operations and honest source/coverage text.
- [x] Add scoped immutable Job bindings and official scanner image digest;
  validate the manifest using the real host parser. Pin the tested host SDK.
- [x] Run Go race/Python/package tests; commit `feat(trivy): collect in-cluster scans`.

## Task 4: Connect native scan actions and live acceptance

**Files:** host `ExtensionOperation.tsx` and its tests; app README, job acceptance
notes, signed local package staging outside git.
**Interfaces:** Image row -> pinned scan-image route with image/namespace;
Overview -> scan-namespace; user runs explicitly, cancels from the native page.

- [x] Write failing route/action/progress/cancel/failure tests; observe failures.
- [x] Allow generic row actions to open stream pages, show prefilled parameters,
  and inspect wide/narrow native components with bounded report data.
- [x] Run real known-vulnerable namespace/image Jobs in kind without Operator;
  confirm results, resource bounds, cancellation and owned-resource cleanup.
- [x] Run required suites/builds and one final whole-branch review; fix important
  findings with TDD, sign/install the small controller locally and verify it.
- [x] Commit Angular changes, fast-forward the authorized local checkouts, leave
  Srelens running. Remote repository, release and catalog remain unrequested.
