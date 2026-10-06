# Trivy in-cluster fallback design

This supersedes the local in-process scanning and OCI acquisition parts of the
2026-10-05 design. The user selected container execution on 2026-10-06 to avoid
a local Trivy executable, database and image cache. Existing Operator readers,
native UI, cluster identity checks and normalized report storage remain useful.
The existing inline execution preference, TDD, Angular commits, no co-author
trailers and no PR/publication authorization remain in force.

## Behavior

Read all twelve declared Trivy Operator report APIs, preserving served, absent
and unknown separately. Prefer served Operator reports for each category. A
failed discovery is never absence. Missing categories offer an explicit
in-cluster scan; opening a reader never silently creates workloads.

The default scan covers the selected namespace. A separate whole-cluster mode
requires explicit scope selection and its own permission description; it is
not the default. The pending scope preference can revise that default.

Run a short-lived Kubernetes Job containing the official, digest-pinned Trivy
0.75.0 image. Scan workload image vulnerabilities and Kubernetes resource
misconfigurations. Disable node-collector and secret scanning. Do not claim
node, compliance or Operator-specific category coverage that was not collected.
Manual image scans use the same Job mechanism without Kubernetes reader access.

Keep a small Go controller using the Srelens SDK and standard-library JSON;
no production dependency on the Trivy Go library or local scanner binary.
Kubernetes performs scanner execution and database/image downloads. Results,
metadata and paginated findings use the existing private JSON/JSONL store.
The historical local scanner proof remains an optional, separate test module.

## Generic host job contract

A declared `k8s.runJob` binding fixes a digest-pinned image, command/argument
array, allowed scalar input names and optional read-only namespace RBAC rules.
Use `${inputs.<name>}` only as a whole argument: no shell interpolation or
caller-supplied Pod specification. The host supplies cluster, namespace, app ID
and numeric revision. No caller may choose another app's identity or data path.

New callback `host/runJob` takes:

```json
{"context":{"clusterId":"pinned-cluster","namespace":"team"},"capability":"scan-namespace","inputs":{"namespace":"team"}}
```

It calls the confirmation-gated `extensions.runJob` facade. The facade validates
installed/enabled app, revision, context scope, binding and grant, and the exact
input names/types before any mutation. A Job request needs a named namespace.
The confirmed operation includes creation, result collection and cleanup.
An old host that does not serve the callback refuses it; it never simulates a
successful empty scan. Keep extension API 0.8/protocol 0.2 additions gated to
the new callbacks and grant, preserving older reader packages.

Create a uniquely named Job with its active deadline immediately in force. A
required, initially absent ConfigMap volume prevents its container starting
before access is ready. Its UID owns a dedicated ServiceAccount, Role and
RoleBinding when namespace reading is required; create the readiness ConfigMap
last. This avoids a forever-suspended orphan if the host loses the create response. Whitelist non-secret resource names and get/list/watch verbs;
no wildcard, Secrets, token creation, nodes/proxy, exec or write permissions.
Manual image scans disable ServiceAccount token mounting and create no reader RBAC.

Host-owned Pod configuration: no host namespaces, host paths, privilege or
extra capabilities; UID 10001, no privilege escalation, read-only root,
RuntimeDefault seccomp, writable emptyDir mounts at `/data` and `/tmp`.
One Pod, no retries, 20-minute active deadline and 10-minute finished TTL.
Default requests: 100m CPU, 256 MiB RAM, 2 GiB ephemeral storage.
Limits: one CPU, 1 GiB RAM, 16 GiB ephemeral storage; emptyDir also has a 16 GiB
size limit. Scheduling or namespace quota refusal is an explicit failed scan.

The host waits for the owned Job, checks Pod owner UID and terminal container
exit status, and streams logs into an app-relative file capped at 8 MiB.
A result response carries Job UID, namespace, scanner image/image ID, timestamps,
app-relative result path and byte count. It never returns credentials or tokens.
All Kubernetes requests have bounded timeouts. A dropped/cancelled call triggers
owned-resource cleanup; UID preconditions prevent deleting a replacement Job.
The active deadline/TTL and owner references cover host loss. Previous complete
reports survive cancellation, timeout, failure, app restart and update.

## App output and UI

`scan-namespace {clusterId, namespace}` and
`scan-image {clusterId, namespace, image}` are cancellable native streams.
One active scan per app; concurrent requests get an explicit busy error.
Frames carry truthful phase text and finally a bounded completed result with
report IDs and counts; never stream a whole unbounded report into a UI frame.
Native row actions may open a stream page with pinned inputs but never auto-run it.

Parse image or Kubernetes JSON using standard-library types. Validate schema,
required identity, result completeness and every resource error before calling
it a completed scan. Preserve subject, image/target, package occurrence,
installed/fixed versions, severity/source, description and references.
Do not count the same finding across Operator and Job coverage as one total.
Record execution source `job`, scanner image digest, scan time and DB metadata
when present; unknown metadata remains unknown. Redact any unexpected secret
match content before storing or rendering it.

Keep at most ten completed reports, at most 20,000 findings per report and
100 rows per findings page. Job logs, normalized reports and staging share the
ordinary 1 GiB app allowance; the now-unnecessary Trivy-only 2 GiB exception is
removed. Local RAM remains 256 MiB and one CPU.

Keep the polished native logo/header, searchable namespace control, compact
resource/container columns, working sort, severity words, Inspect details,
explicit errors/retry, and pinned routes. Add a visible in-cluster scan action
and useful progress/cancellation state without custom app HTML or JavaScript.

## Verification

TDD covers wire spelling, grant/scope/revision/input refusal, Job/RBAC/security
configuration, UID ownership, failure/oversized output/cancellation cleanup,
result normalization, duplicate occurrences, false-clean prevention and bounded
persistence. Drive wide/narrow UI with real response snapshots clearly labeled.
Run real Jobs in the local kind test cluster with no Operator, verify known
vulnerable results, cancellation and cleanup, then install the signed controller
locally. Do not create a remote repository, PR, release or catalog entry.

References: [Trivy Kubernetes scanning](https://trivy.dev/docs/latest/target/kubernetes/),
[Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/),
[ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/).
