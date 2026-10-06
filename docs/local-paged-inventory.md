# Large inventory and native report UI acceptance

Host commit `c72ba93dc456312ccef02f589ca088cd596d733d` and controller
commit `e82d652a130f34432ef8cf6319a4807a82053d1a` were verified on macOS arm64.
The controller was built from committed source with a clean SDK checkout at the
exact host pin. Its 1,460,289-byte local package was signed by the trusted srelens
publisher and installed as app revision 20. No release or catalog publication
was performed.

The production registry, supervisor and OS sandbox returned the M01
all-namespace inventory: **1,880 regular and init-container images across
59 namespaces in 17 pages**. Every container identity appeared once, and the
final continuation was empty. This reproduces and resolves the earlier
1,000-row failure. The acceptance policy denied all cluster-write consent;
this check created no scan Job or report.

Images explicitly request bounded Kubernetes pages, preserving cluster,
namespace and workload-kind scope through both host and controller cursors.
The existing per-page row and message limits remain in place. Readers that
omit pagination still return a complete bounded inventory or an error, under
one aggregate timeout; they never silently return a partial inventory.
Next page and Previous page browse the inventory. Search filters the current
page. Retry repeats the failed page; Start from first page handles expired
continuations without retaining stale navigation history.

The native report UI uses compact report rows, subject and image identity,
per-report severity badges, source filters, readable timestamps and one primary
Findings action. Secondary actions and complete metadata sit in a popover.
Operator `criticalCount`/`highCount` summaries render in severity order, and
resources sharing an image remain distinguishable. Counts from retained scans
and Operator reports are not combined.

TDD regressions were observed failing before fixes for large inventories,
caller cursor payloads, broker forwarding, SDK first-page requests, paging
recovery and Operator display. The full Rust workspace, Go SDK and controller
race tests, seven Python contract/preparation tests, UI typecheck and 7,785
frontend tests passed; frontend line coverage was 92.18%.

The real native components were driven at wide and narrow widths using captured
signed scan results. Namespace scans wait for an explicit Run, terminal status
remains visible, Findings opens with the pinned route, report metadata opens,
and source filtering keeps report rows separate. Synthetic Operator reports
were labeled as fixtures and used only for visual verification.

Evidence is saved locally under `/private/tmp/srelens-trivy-ui-evidence`:
`live-inventory-summary.json`, `live-acceptance.log`, test logs and browser
screenshots. Historical container-scan, registry-refusal and cancellation
acceptance remains documented in `local-container-scans.md`; this pagination
change does not replace that evidence. Windows, other controller platforms
and release/catalog acceptance remain untested by this local change.
