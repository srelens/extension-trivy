# Offline scanner feasibility

Task 1 is **in progress; the production gate has not passed**. A real offline
Trivy scan works in the unchanged Linux sandbox on arm64. The executable does
not fit the current native package format; real Windows AppContainer execution,
in-flight cancellation and complete inventory handling are still unproven.
No installable app, Operator adapter, production
broker, dashboard or release is claimed by this prototype.

## Pinned inputs

- Host: `d3fd0618239b91ec83aa354bea57beeea41c464a`, prepared in `.host`.
- Trivy: `v0.75.0`, commit `591e9799316a602e703f0b484f6c6d7b234ec8f3`.
- Go module checksum: `h1:iOMkI0qX3Dfo+A6lznchBvtDD4ZSu+H9RBww1z5Qz58=`.
- Development build: Go 1.27.1; Linux proof: Docker Linux arm64,
  kernel `7.0.14-linuxkit`, cgroup v2, Rust 1.98.1.
- Engine identity: `0.75.0+srelens.1`, including the compatibility patch below.

The image fixture is `ghcr.io/aquasecurity/trivy-test-images:alpine39`, resolved
to index `sha256:7746df395af22f04212cd25a92c1d6dbc5a06a0ca9579a229ef43008d4d1302a`
and platform `linux/amd64`. Its config identity is
`sha256:055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1`.
The layer digest is
`sha256:e7c96db7181be991f19a9fb6975cdbbd73c65f4a2681348e63a141a2192a5f10`.
Preparation verifies both blobs and produces a deterministic Docker archive.
No Docker subprocess runs inside the sidecar.

| Fixture | Bytes | SHA-256 |
|---|---:|---|
| Canonical Alpine Docker archive | 2,764,800 | `24e9cea338601b1ed9422f3a6e9bfe2235a45588d53c34f2c9606098bcf5b1a5` |
| Upstream Alpine DB YAML | 833 | `e8454df110f7d75d368e5b4d2c9581eb3ee5c6c3118fc698d6fd824ec2573a34` |
| Upstream vulnerability DB YAML | 79,181 | `b8167a98a187774a3944c9f63e77685bd9f38f1ec2c75c48cb00eead4707cdc4` |
| Upstream Debian DB YAML | 937 | `613f84285604a4a79b5595e3adbce4e73c22e7d78aa87c7530d76bc45620ea64` |
| Generated Bolt DB | 524,288 | `f3bc1bc86c3b2e3e45fa8e292a43b716a4d9197055cbf9c607e17addf9d85e26` |
| DB metadata | 123 | `ae6400f3026e75b630afb7950661e6d9a98735fdb3f851af4e2ccec7d195b1df` |
| Upstream Debian Docker archive | 7,779,559 | `60d91170eedb6f4af94899684b500338a84f10d643f2761e6a4821959d0c9e3a` |

The small fixture DB is schema 2, dated `2026-10-01T00:00:00Z`. It is deliberately
stale test data, not a production DB or evidence of current vulnerability
coverage. The scanner returns its metadata unchanged; production freshness
handling belongs to Task 4. The tests assert CVE-2019-1549 in **both**
`libcrypto1.1` and `libssl1.1`, including installed and fixed versions. The
Debian fixture additionally exercises per-package `dpkg/status.d` extraction
and CVE-2019-1563.

## Narrow Trivy compatibility patch

The unmodified Debian scan failed under Linux seccomp with
`chmod ...: operation not permitted`. Trivy's composite filesystem copied a
package status file, then called `os.Chmod(f.Name(), 0o600)` on the pathname.
The host correctly refuses that syscall.

`patches/trivy-fd-chmod.patch` changes just that call to `f.Chmod(0o600)`. The
same mode is applied through the already-open descriptor, which the existing
sandbox allows. No host syscall policy or resource limit changes. The engine
version explicitly identifies the patch. `scripts/prepare_trivy.py` checks
the pinned module checksum and original file hash, then applies the patch
to a private ignored `.trivy` copy. It never edits the shared Go module cache.
Repeat preparation checks every path and file in that copy, not just the patch.
Host preparation refuses tracked modifications and untracked SDK files while
preserving unrelated local/proof files.

- Original `pkg/fanal/analyzer/fs.go`:
  `4877b47e37516bbd2de578f82f3dacd4ea454b36ab5a20f36d606d4f4ffb09bc`.
- Patched file:
  `d29d01f98f210ab4280fc871d944f6de3c3d81315594a86714b39fd51faf4e7b`.

This temporary compatibility patch is not an independently maintained Trivy
fork. Revisit it on each scanner update and remove it when upstream supports
the same sandbox behavior.

## Test evidence and limits

TDD failures were observed before implementing the scanner, SDK probe and host
preparation. Additional failing regressions demonstrated that an internal
symlink directory was accepted and that an OS with no package inventory could
incorrectly become a clean report. The scanner now rejects both. A separate
supported-inventory test still accepts a real zero-findings result.

Go race tests cover the offline result, inventory absence, supported zero
findings, cancellation, outside paths and symlinks. The SDK test uses real
JSON-RPC initialization, activation and streams over pipes: failed scans emit
`stream/error`, not a success terminal frame, and health calls remain usable.

The Rust proof invokes the pinned host's **real** `Supervisor` and `OsSandbox`.
It runs an Alpine scan, cancels/restarts a scan and runs the Debian scan. The
production host implementation is unchanged. A privileged outer Docker test
container is used only to delegate cgroups; the scanner still runs within the
host's Landlock, seccomp and cgroup boundaries.

Measured Linux arm64 results from the final inventory-guard build:

| Check | Result |
|---|---|
| Memory ceiling | `memory.max = 268435456` (256 MiB) |
| Cgroup memory peak | 127,418,368 bytes; zero max/OOM/OOM-kill events |
| Scanner RSS/high-water mark | 109,580 KiB |
| CPU ceiling | `cpu.max = 100000 100000` (one CPU) |
| Alpine scan CPU usage | 106,122 microseconds, including startup |
| Alpine scan time | 67 milliseconds |
| Maximum health-call latency | 41 milliseconds |
| Early cancellation and successful rescan | 36 milliseconds |
| Sampled app data peak | 3,379,200 bytes |
| Host Linux sandbox conformance | 14/14 passed, including positive controls |

An additional `strace -ff` run of the real sandboxed Alpine test showed no
socket/connect/bind/send/receive calls and no child processes. All scanner
`clone` calls create threads. Trusted launcher execution precedes the probe;
the probe does not execute another binary. The tracer is outside the sandbox
and is not required by the app. Its own RSS is not scanner RSS.

The cancellation case drops the stream after the initial progress frame.
That can happen before Trivy begins; host stream-count bookkeeping does not
prove scanner termination. It verifies early cancellation, responsiveness and
reuse only. Interruption after observable scanner work and a bounded release
deadline remain required before the production gate passes.

These measurements prove the small fixtures only. Large production DBs,
large or hostile layers and every ecosystem still need acceptance under the
same limits. Linux amd64 execution and Windows AppContainer execution are
unverified; a Windows amd64 cross-build succeeds but does not satisfy that gate.

## Incomplete-inventory blocker

Review identified and a real scan reproduced a false-clean candidate result:
an Alpine installed-package DB containing a benign package, then a 70 KiB line,
then vulnerable `libssl1.1` produces only the benign inventory and no findings.
The pinned APK analyzer uses the default `bufio.Scanner` token limit without
checking `scanner.Err()`. The adapter's nonempty-inventory guard cannot detect
that truncation. The candidate therefore **must not serve arbitrary production
images** or claim complete/clean coverage.

The unresolved acceptance test is retained as
`tests/limitations/apk_inventory_test.go.txt`, outside the passing fixture suite.
It asserts the desired behavior and currently fails; it is not skipped and its
assertion is not changed to accept the bug. Reproduce the diagnostic separately:

```sh
(
  set -eu
  test ! -e internal/scanner/candidate_apk_test.go
  trap 'rm -f internal/scanner/candidate_apk_test.go' EXIT
  cp tests/limitations/apk_inventory_test.go.txt internal/scanner/candidate_apk_test.go
  go test ./internal/scanner -run '^TestCandidateAPKInventoryMustNotBePartiallyClean$' -count=1
)
```

This diagnostic is an expected failure and blocks production, even when
`go test -race ./...` passes the supported fixture/protocol cases. Resolve
incomplete analyzer coverage in the integration contract and rerun this gate
before Task 2. Do not grow a private scanner fork or suppress parser failures
to make the acceptance claim pass.

## Native package blocker

The pinned host caps packages at 16 MiB compressed and **64 MiB total
unpacked**. A stripped Linux arm64 probe measured 146,997,408 bytes (about
140 MiB); gzip measured 41,970,263 bytes. The Windows amd64 cross-build measured
162,655,232 bytes. These are development feasibility measurements, not a
released distribution.

`tests/host/package_limit.rs` passes the actual Linux binary to the pinned
host's native `extension_package::digest_list`. The host refuses it:
`bin/linux-arm64/trivy-probe is larger than the package allows`. This is a real
package refusal, not an inferred limit. A multi-platform package would be
larger still. Do not raise global limits or claim installation works.

The [host contract](host-contract.md) records a proposed distribution decision
for review. It is not implemented or approved. Production Tasks 2–6 remain
pending until that decision, missing execution/cancellation/completeness proof and contract
review clear Task 1.

## Reproduce the development proof

From the app checkout, prepare exact dependencies before Go commands:

```sh
python3 scripts/prepare_host.py
python3 scripts/prepare_trivy.py
python3 scripts/prepare_fixtures.py
python3 -m unittest discover -s scripts -p 'test_*.py' -v
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags='-s -w' \
  -o .superpowers/trivy-probe-linux ./cmd/trivy-probe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags='-s -w' \
  -o .superpowers/trivy-probe-windows.exe ./cmd/trivy-probe
```

For a Linux cgroup-v2 container with delegation (use the artifact matching its
CPU), mount this checkout as `/work`, set `CARGO_TARGET_DIR` and `CARGO_HOME`
under `/work/.superpowers`, and run:

```sh
mount -o remount,rw /sys/fs/cgroup
mkdir /sys/fs/cgroup/host
echo $$ > /sys/fs/cgroup/host/cgroup.procs
echo +memory +cpu > /sys/fs/cgroup/cgroup.subtree_control
export SRELENS_SANDBOX_CGROUP_ROOT=/sys/fs/cgroup
export TRIVY_PROOF_BINARY=/work/.superpowers/trivy-probe-linux
export TRIVY_PROOF_FIXTURES=/work/.fixtures/runtime
export TRIVY_PROOF_DEBIAN_FIXTURES=/work/.fixtures/debian-runtime
cargo test --locked --manifest-path /work/tests/sandbox/Cargo.toml \
  -- --test-threads=1 --nocapture
cargo test --locked --manifest-path /work/.host/Cargo.toml \
  -p srelens-plugin-host --test sandbox_conformance -- --nocapture --test-threads=1
```

For the native package refusal, copy `tests/host/package_limit.rs` to
`.host/crates/registry/tests/trivy_package_limit.rs`, then run the host's
`cargo test -p srelens-registry --test trivy_package_limit` with
`TRIVY_PROOF_BINARY` set. This adds only a proof test, never production code.

Fixtures, patched upstream source, binaries and raw logs are ignored. Local
evidence lives in `.superpowers/sdd/2026-10-05-trivy-executable/`; input checksums
and preparation scripts make the proof repeatable without committing large
artifacts. No `compatibility.json` claims production acceptance yet.
