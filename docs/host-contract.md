# Host contract for the Trivy app

Status: partially implemented, 2026-10-06. Host commit `b1f430b3d2ee1ce2d8a08bd323865861b6ef9d14` implements the binding-availability callback, kind-bound workload reader and native operation/stream surfaces below. Workspace tests and live macOS reader acceptance pass; see [local reader evidence](local-readers.md). **OCI artifact acquisition is still a proposal**, not an available host method.

## Blocking prerequisites

The user authorized macOS executable apps and a 512 MiB package limit; host commit `ec264a683e8953eff190444938097a6ba5fac9be` contains that change. The APK inventory-truncation defect was fixed with a reproduced regression test in app commit `9ab8998`.

The real production database is 1,477,152,768 bytes unpacked. On 2026-10-06 the user approved a 2 GiB aggregate data allowance for the production ID `org.srelens.trivy` only. Memory remains 256 MiB, CPU remains one core, other apps retain 1 GiB, and sandbox isolation remains required. Production database RSS, true in-flight cancellation, OCI transfer integrity/quotas and Windows AppContainer execution remain open. Fixture success is not live scan acceptance.

## Versions and authority

The implemented additions use extension API 0.8 and sidecar protocol 0.2.0.
Protocol 0.1.0 remains supported for old sidecars.
New callbacks require negotiated 0.2.0; an old host is incompatible, not an
absent Operator. If 1.0 lands independently, follow its additive-version rules.

Sidecar callbacks identify the app and installed numeric revision through its
existing `CapabilityBroker` session. Never accept app identity from a sidecar.
Native calls carry `id` and `revision`, following current extension calls.
Before every callback, validate installed/enabled/granted app, revision and
explicit context. Revoke work on disable, update, removal or view closure.

All multi-word Rust input fields explicitly rename to the caller's camelCase
wire spelling. Test the actual Go/core caller payloads, including rejected
snake_case spellings; regenerate protocol/schema/Go types together.

## Binding availability

Implemented native capability: `extensions.bindingAvailability`:

```json
{"id":"org.srelens.trivy","revision":7,"context":"cluster-a","namespace":"team-a","bindings":["vulnerability-reports","cluster-vulnerability-reports"]}
```

Implemented sidecar callback: `host/bindingAvailability`:

```json
{"context":{"clusterId":"cluster-a","namespace":"team-a"},"bindings":["vulnerability-reports","cluster-vulnerability-reports"]}
```

Both return:

```json
{"bindings":[{"binding":"vulnerability-reports","state":"served","version":"v1alpha1","namespaced":true},{"binding":"cluster-vulnerability-reports","state":"absent"}]}
```

Accept 1–16 unique declared binding names, using the SDK's identifier rules.
Refuse undeclared or ungranted bindings before discovery. Resolve custom
resources through the existing served-version check. A successful discovery
with no served version is `absent`; a refused or failed discovery is `unknown`
with a bounded `reason`. A whole-call authorization error remains an error.
Built-in readers use their registry availability rather than CRD lookup.

The app checks all twelve declared Operator report bindings. Any served
category selects Operator reports for that category and suppresses automatic
local scans. Only confirmed absence of every relevant report API selects app
scanning automatically. Unknowns offer retry and explicit local scanning.
Empty report lists mean no reports yet, not a missing Operator.

## Workload images

Implemented read-only, app-grantable capability: `k8s.listWorkloadImages`.
Each binding fixes `kind` to Deployment, StatefulSet or DaemonSet. The caller
supplies existing `context` and optional `namespace` inputs; it cannot change
kind or request a manifest. Return a bounded list of workload identities:

```json
{"items":[{"namespace":"team-a","kind":"Deployment","name":"web","uid":"workload-uid","resourceVersion":"42","containers":[{"name":"app","type":"regular","image":"ghcr.io/example/web:v1"},{"name":"setup","type":"init","image":"ghcr.io/example/setup:v1"}]}]}
```

Use the caller's pinned cluster. Include regular and init containers; exclude
environment variables, credentials, Secret references and pod specifications.
An RBAC failure is a failed read, never an empty successful list. Direct image
scans do not call this reader. Report ownership uses UID/owner references,
never a guess based on resource name.

Cap each call at 1,000 container rows and the protocol's 4 MiB output limit.
Enumerate Kubernetes workloads in pages of at most 100 objects within the
ordinary request deadline. On overflow, return a bounded explicit error asking
the user to narrow the namespace; never return a partial list as complete.
Pagination of app finding/report operations is a separate contract below.

## OCI artifacts

Proposed grant: `network.fetchOciArtifact`. A manifest binding fixes its purpose
(`image` or `trivy-db-v2`), registry hosts and allowed repository prefixes.
Database bindings cannot be repurposed for arbitrary image downloads.

Proposed callback: `host/fetchOciArtifact`:

```json
{"context":{"clusterId":"cluster-a","namespace":"team-a"},"capability":"image-artifacts","reference":"ghcr.io/example/web:v1","platform":"linux/amd64"}
```

Image response:

```json
{"kind":"image","format":"docker-archive","path":"artifacts/sha256-<manifest-digest>.tar","digest":"sha256:<platform-manifest-digest>","platform":"linux/amd64","bytes":2764800}
```

Database response:

```json
{"kind":"trivy-db-v2","format":"trivy-db-v2","path":"databases/sha256-<artifact-digest>","digest":"sha256:<artifact-digest>","bytes":524411,"schemaVersion":2,"updatedAt":"2026-10-01T00:00:00Z"}
```

References are nonempty and at most 512 bytes. Image platforms are explicitly
`linux/amd64` or `linux/arm64`; database bindings use the same scalar platform
field but do not choose a platform-specific executable. Reject URLs, embedded
credentials, arbitrary paths and ungranted repositories. Resolve a tag once;
for an image index select and verify the requested platform manifest. Keep
the image manifest digest distinct from the image config ID in scanner output.

The host performs authentication, validates token realms and redirects against
the grant, bounds metadata and transfer sizes, and verifies all blob digests.
Credentials and response bodies never cross the callback. Return metadata and
app-relative paths only. Transfers are cancellable; incomplete writes are
removed and the final representation is renamed atomically after verification.
Refuse symlinks, traversal, unexpected archive entries and artifacts exceeding
the remaining data budget, including database extraction and staging.

Before Task 2 approval, define atomic app-budget reservations across image/DB
transfers, extraction, scanner cache, report writes and staging. Concurrent
callbacks must not each spend the same measured remaining bytes. Serialize
acquisition per app as the initial policy, account for temporary and final
copies, release reservations on cancellation/crash and retain ownership through
atomic commit. The current periodic host measurement alone is not a reservation
mechanism or evidence that simultaneous staging fits.

Also define how verified inputs stay stable until the active scanner releases
them. Neither pathname checks nor readonly file modes on a writable parent
prevent replacement. Acquisition finishes before scanning; cache eviction and
DB replacement cannot touch active inputs. The adapter depends on that lifetime
guarantee. An OS-specific immutable-input or equivalent verified-read design
still needs review; no new enforcement is claimed in this prototype.

Trivy's archive entry point accepts Docker-save tar/gzip files and an OCI
layout **directory**, not an arbitrary OCI-layout tar. This adapter deliberately
accepts regular Docker archive files. The broker must convert verified image
blobs to that representation, without running Docker or another executable.
Database acquisition produces verified `trivy.db` and `metadata.json` files.
The prototype expects them in `db/`; revisioned cache selection is later work.

## Native operation pages and stream bridge

The host supports generic native operation pages in the manifest, with declared operation,
scalar form inputs and host-rendered table/result fields. No app HTML,
JavaScript, iframe or special Trivy component belongs in the package.
The parser, schemas, native UI and Go types must agree on the new fields.

The app-stream source union now accepts an operation source:

```json
{"kind":"operation","method":"scan","params":{"clusterId":"cluster-a","namespace":"team-a","image":"ghcr.io/example/web:v1","platform":"linux/amd64"}}
```

The existing native stream owner fields (`id`, `revision`, `view`, `channel`,
`context`, `namespace`) remain authoritative. Cross-check operation parameters
against that context. The stream remains cancellable and checked through app
lifecycle changes. It is not an ordinary request held beyond 30 seconds.

Implemented route identity:
`/extension-operation-contexts/<clusterId>/<id>/<revision>/<operation>`, with every segment
encoded. Report tabs additionally carry encoded scalar parameters including
`reportId`. The screen and sidebar opener are registered. Cluster switching
must not remount/re-pin an existing tab.

Existing wire lifecycle uses `stream/open`, `stream/data`, `stream/error`,
`stream/close`, and host `stream/cancel`. Normal scan data has discriminated
`state`: queued, acquiring-db, acquiring-image, scanning or completed. Progress
includes bounded phase/counts; completed carries report ID, source, timestamp,
image manifest digest/platform, engine version, DB digest/age and named severity
totals. Operational failures use stream errors and do not carry completed zero
totals. The UI retains cancellation as a separate local state after cancelling.

## Production app operations and storage

The reader build implements four ordinary app methods. The scan stream remains
proposed; the fixture-only probe is not its implementation:

- `source-status {clusterId, namespace?}`
- `list-images {clusterId, namespace?}`
- stream `scan {clusterId, namespace?, image, platform}`
- `list-reports {clusterId, namespace?, cursor?, limit?}`
- `findings {reportId, cursor?, limit?}`

Limits default to 100 and accept 1–100. Use opaque cursors scoped to the
app/report/context. An unknown report ID or mismatched context is an error.
Every finding preserves subject/container/target/package identity, rather than
deduplicating CVEs across independent occurrences.

Under the private app data root, store JSON report metadata and JSONL findings.
Use atomic writes, retain the last 10 completed app reports, and bound reports,
Operator cache, DB, image archives, temporary data and staging together to
2 GiB for `org.srelens.trivy`. Failed/cancelled scans never replace a completed report. Operator CRs
remain authoritative in the cluster; local normalized views are bounded cache.
Never persist exposed-secret match text. Updates/restarts retain local reports;
uninstall relies on the host's existing scoped-data pruning.

## Required contract tests

Task 2 must test caller-spelled JSON, typed unknown/absent discovery, stale
revision and grant rejection, kind-fixed regular/init image discovery,
cross-context operations/routes, OCI digest/redirect/path/budget failures,
cancellation, bounded frames/cursors, old clients, and lifecycle revocation.
No claim of implemented or tested production support exists until those tests
and the outstanding feasibility gates pass.
