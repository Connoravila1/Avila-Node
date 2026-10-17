# egui interface plan

The desktop should make the node pleasant to operate and its behavior understandable.
Use egui capabilities when they serve an actual interaction. Each measurement and
visualization must come from a defined source, with unknown, stale and disconnected
states. The node remains usable headlessly.

## Foundation implemented here

The application uses the pinned [eframe 0.36.2 application interface](https://docs.rs/eframe/0.36.2/eframe/trait.App.html)
and the owner's orange AN logo. The shell provides menus, resizable navigation,
status context, scrollable pages, keyboard navigation, appearance controls and
floating help/settings windows. Capabilities and events use
[egui_extras tables](https://docs.rs/egui_extras/0.36.2/egui_extras/struct.TableBuilder.html)
with resizable columns. Events can be filtered, ordered, selected, and copied with
their explanation. Configuration inspection offers explicit copy actions.

The event retention indicator measures the actual diagnostic buffer's occupancy.
It does not represent chain synchronization. No peer graph or block chart is fed
invented measurements. In GUI-owned mode, **Settings → Appearance** offers Light,
Dark, Match the system, and 90–130% scale choices. The startup flag accepts
`--theme light|dark|system`; Black is not a CLI value or a GUI-owned theme. In attach
mode, **View** offers Black and 75–200% scale choices. Its Black palette sets panel
and window backgrounds to `#000000`. Native checks exercised 130% and 200% scale
and restored 100%; see the viewport limits below. Appearance settings persist
locally. Generic egui memory, search terms, node data and window state are not
saved.

The GUI-owned default is Light at 100% scale. On Linux, appearance is stored in
`$XDG_DATA_HOME/avilanode/app.ron`, or `~/.local/share/avilanode/app.ron` when that
environment variable is unset. eframe chooses the application-data directory on
other platforms. Changes are saved on normal close and periodic autosave; a forced
termination can lose the most recent change. A malformed record resets to defaults.

## Capabilities and their intended uses

| egui capability | Concrete node use | When to implement |
| --- | --- | --- |
| Panels, layouts, grids, scroll areas | Navigation, status, readable forms and details | Foundation |
| MenuBar, keyboard shortcuts, context menus | Navigation, help and explicit copy actions | Foundation |
| Tables with virtual rows and resizable columns | Event/capability lists; later peers, transactions and blocks | Foundation, extended with actual data |
| TextEdit, checkboxes, ComboBox | Event search, order, appearance preferences | Foundation |
| Windows and collapsible sections | Event details, settings, help, diagnostic explanations | Foundation |
| ProgressBar | Real event retention; later separate download/validation/index progress | Foundation, then synchronization |
| Sliders, DragValue, radio controls | UI zoom; later validated resource budgets and policy values | Foundation, then configuration commands |
| Tooltips and selectable text | Reasons, units, unknown-state explanations, copyable paths/hashes | Foundation and every milestone |
| Local textures and images | Embedded branding; later local diagnostic artifacts | Foundation |
| Built-in settings and inspection tools | Develop and inspect egui styling, layout, memory and accessibility | Development builds |
| egui_plot line/bar/histogram views | Validation throughput, latency, bandwidth, resource and policy comparisons | After real bounded metric series exist |
| Custom Painter, transforms, pan/zoom | Peer topology, package dependencies, chain branches and reorg explanations | After typed graph data and interactions exist |
| Drag and drop | Rearrange workspace panes; import bounded local fixtures/config with validation | When those workflows exist |
| Multiple native viewports | Detach an event, peer, transaction or comparison inspector | When operators need simultaneous inspection |
| Modal dialogs | Confirm destructive commands and explain resulting state changes | When those commands exist |
| Local persistence | Theme and scale; later workspace layout with a separate schema | Appearance implemented; layout after design and migration tests |
| Animation and profiling integrations | Explain measured changes and identify GUI overhead | When useful; reduced-motion/static alternatives |

Review the [egui demo source](https://github.com/emilk/egui/tree/main/crates/egui_demo_lib/src/demo)
as each relevant workflow is built. Plotting and docking libraries are separate
ecosystem dependencies; evaluate compatibility and interaction benefit before
adding them. Enabling every Cargo feature is not a product requirement.

## Current node views and limits

On **Chain**, choose **Inspect** beside a recent block, or enter a height or full
block hash in **Block inspector**. Previous/next follow the returned block-hash
links. The detail shows header fields and measured body size, weight, transaction
count and transaction summaries. A header-only, pruned or otherwise unavailable
body is identified explicitly. For the measured prune gate and pruned-body
recovery limits, see the [prune/checkpoint boundary note](../experiments/2026-10-17-prune-checkpoint-boundary.md).
The transaction map sizes each rectangle by its
share of loaded transaction weight; the block header/framing is excluded and
shade is a logarithmic cue. It covers only summaries currently loaded. A cell or keyboard-selectable transaction-table
row selects that transaction. The inspector retains at most 2,000 summaries,
fetched 100 at a time, and labels partial map coverage while more are available.
Selected transaction detail requests are pinned to block hash, txid, and index;
input and output pages are each capped at 100. The view shows outpoint, sequence,
script/witness prefixes, output values and standard addresses when available.
Current source also recovers non-coinbase input values and fees from a matching
active-chain block undo record when that record is available and passes the
bounded reader. The transaction total fee is input total minus all output values;
the displayed sat/vB rate uses the measured transaction weight converted to
virtual bytes. Known amounts carry a `block_undo` source label. Coinbase has no
prevout amount or fee. Missing, non-active-chain, hash-mismatched, oversized,
malformed, or arithmetically inconsistent undo remains explicitly unknown. This
path does not query the current UTXO set, a txindex, or peers, and does not change
consensus checks or validation-status claims. Script hex remains a bounded prefix
when truncated.

Existing databases are not backfilled. The persisted lookup path stays disabled
while admission metadata fails to cover any retained undo record, or the sticky
record maximum exceeds 8 MiB; adding admitted new rows alone does not repair
incomplete historical coverage. Recent in-memory tail/run undo remains eligible.
Once persisted-table coverage is complete and the global maximum is within 8 MiB,
the selected row is still checked against its recorded size and block hash before
scanning at most 8 MiB. This is an encoded parser/input bound, not a physical or
RSS guarantee: ordinary redb page access may exceed the record limit. Native
checks on this laptop exercised the in-memory retained-undo path; persisted
lookups against an existing database without complete current-writer admission
remain unavailable.

The **Network traffic** page shows cumulative bytes sent and received by the
current node worker, including peers that disconnected, and rates derived from
successive samples. The session retains at most 900 samples (about 15 minutes at
one sample per second); the chart shows at most 120 valid rate intervals. Pairs
across a run restart, counter reset, nonpositive time interval or gap over 2.5
seconds are omitted. Demo mode is simulated and does not report live network
traffic; block inspection requires a live node session.

In its default mode, the GUI starts and controls its own node worker. Attach mode
instead observes an already-running node through its loopback RPC endpoint; it
does not start a second node or chainstate. The attached block inspector and
status views use background RPC workers. RPC operations use three-second
connect, read, and write inactivity timeouts; this is not a total-call deadline.

Native captures reviewed on 2026-10-17 show the Chain page with the offline
mainnet-genesis fixture at 1120×760 and 760×600. The fixture is explicitly marked
as offline, not live node data. Both captures show the inspector and measured
genesis header/body facts; the compact view keeps the long hashes on-screen, while
the transaction table continues below the initial viewport. The larger capture
shows the single coinbase weight-composition segment. These captures do not verify
live-node responses or transaction paging.

At the undo-inspector proof, the source passed a guarded workspace gate: 1,172 Rust tests
(including 86 GUI tests; five ignored), 17 Python tests, formatting, all-target
Clippy and rustdoc with warnings denied, paired release CLI/GUI builds, and
smoke checks. The 2,560 MiB cap / 1,024 MiB reserve run peaked at 2,031 MiB in
319 s. Source fingerprint SHA-256 at that proof:
`b8d1e8aad825943419f4e7fc25bb46e01387dd91c0d3169c8ef97a0c41458f2c`. The CLI
and GUI binaries installed for that proof had SHA-256
`9fa0079142f80ea292fc4bbd6bff213755ecf7dd31491e2ca991645a480b7d0d` and
`b0ee9470af909e3622fdd0df7395f13aa3f54dfd62ed5f3c563a0a3d5a4aae0c`, respectively.
Earlier live captures used mainnet block 83018
(`00000000002bba570c3fbc62f77f54685b7011bfa202a086d4005131cc0ceed6`), which
contains 225 transactions. The inspector loaded summaries in 100 → 200 → 225
steps, updated its loaded-coverage labels, and removed the load-more button at the
end. Selecting map cell 84 opened the matching transaction detail; selecting
table row 1 showed the real one-input/two-output transaction, full txid, and
explicitly unknown fee. The 200 px input/output panes showed the facts and
selectable address. The block was marked as a lookup snapshot. At 760×600 and
1440×900 with 100% scale, the partial-map caption, transaction table, map, and
detail panes were readable.

The preceding installed GUI's View scale was exercised at 130% and 200%, then
restored to 100%; its floating scrollbar exposed lower choices but overlapped the
privacy label. Black-to-Dark reset, peer-address masking on six rows, Help/About,
and Node → Close monitor were checked. Closing the monitor left the daemon active
while its height advanced from 162,749 to 162,836. This is a changing sync sample,
not evidence of completion.

Final native checks show compact, wrapped transaction rows with all fields
including measured weight and the full next-block hash at 130% on 760×600. The
seven-column table remains fully visible at 100% on 760×600 and 200% on 1440×900.
At 1440×900 and 200%, the solid View-menu scrollbar exposes scale and privacy
controls, stays open while scrolled, and closes after selecting a choice. With
direct keyboard dispatch at 1440×900/100%, clicking index 0 then pressing Tab,
Tab, Space focused and selected index 1 and opened its matching details. This
verifies this row-focus sequence only; screen-reader behavior, 760×600 page 2
for a transaction with more than 100 outputs, missing-cookie recovery, and
cross-platform behavior remain unverified. A 440-input transaction was
paged natively (details below); a later >100-output check is recorded below.
This is not a full visual or accessibility audit.

Native checks then used active mainnet block 257285, transaction 1
(`e0236df7f02f5611faa1de318c3e462477a0aa6e8939b7ab0ae30d94dd4085ea`). At
1440×900 and 760×600, both at 100% scale, the inspector showed input value
7.22282802 BTC, total fee 0 BTC, rate 0.00 sat/vB at 258 vB, the block-undo
source caption, and the per-input amount. An earlier query of block 255048
initially returned amounts over RPC, but the GUI later showed them unknown after
the undo moved from in-memory tail to a persisted backend whose historical
admission coverage was incomplete; the database was not backfilled. The first
GUI detail request visibly timed out with OS error 11. Selecting the row again
recovered the detail; this
does not establish automatic retry behavior. The native sample had a zero fee;
nonzero-fee rendering is not yet established by a native fixture. GUI close
exited 0 and left the same daemon PID active while height advanced 256,261 →
258,591. The GUI's 512 MiB cap / 512 MiB reserve run peaked at 108 MiB in 196 s.
See the [undo-inspector experiment note](../experiments/2026-10-17-undo-inspector-amounts.md)
for proof details. These checks do not claim full IBD completion, nonzero-fee
rendering, screen-reader behavior, or cross-platform behavior. This 257285
sample does not establish >100-output paging; that was checked separately as
described below.

Launch with `--full-verify` to disable the assume-valid checkpoint for that run
and verify historical scripts during initial sync, matching the CLI's
`assumevalid=0` behavior. This can make initial sync substantially slower. The
default is unchanged, and the flag does not alter saved GUI preferences.

For a native devtools capture of the measured offline genesis fixture, run
`AVILA_GUI_CAPTURE=/tmp/avila-gui-capture AVILA_GUI_CAPTURE_ONLY=block-detail-genesis-fixture cargo run -p avila-gui --features devtools -- --demo`.
The harness writes full-size and compact screenshots with JSON provenance sidecars.
This capture is a deterministic fixture view, not evidence from a live node.

## Attaching to an existing node

Start a daemon with cookie-authenticated RPC enabled on a loopback address, then
launch the GUI with the same network configuration so it can find that daemon's
data directory and local RPC cookie:

```sh
avila-gui --attach --config /path/to/avila.toml
```

If the daemon's RPC address differs from `services.rpc.bind` in that config, pass
it explicitly:

```sh
avila-gui --attach --config /path/to/avila.toml --rpc-addr 127.0.0.1:18443
```

Only loopback RPC addresses are accepted. The attach worker reads the cookie from
the configured network data directory for each request; if the cookie is not
available yet, the view reports RPC unavailable and retries. It never places the
cookie in status, console output, or errors. Closing the GUI stops its attach
workers and leaves the daemon running. Attach mode cannot start or stop the node,
apply settings, change pruning or memory limits, or alter verification policy.
`--fast-ibd` and `--full-verify` are rejected with `--attach`; they only configure
a GUI-owned node. `--demo` is also incompatible with attach mode.

The attached window has five pages: Overview, Blocks, Peers, Traffic, and RPC
console. The console allows only these read-only methods: `help`,
`getblockchaininfo`, `getvalidationreport`, `getnetworkinfo`, `getnettotals`,
`getpeerinfo`, `getmempoolinfo`, `getchaintips`, `getblockheader`,
`getblockhash`, `getblockinspect`, and `getblockstats`. Input is limited to 8 KiB,
responses to 64 KiB, and one console request can be pending at a time. Node
configuration and wallet/mutating RPC methods are not exposed by this console.

At the tested default 100% scale, the attached header keeps Node, View, and Help
reachable at 760×600 and 1440×900. Higher zoom still has layout limits described
below. View offers Light, Dark, System, and Black
themes; 75–200% interface scale; and peer-address masking in the peer table and
RPC JSON (`addr`, `addrlocal`, and `addrbind` fields). These attached appearance
choices persist locally. Node → Close monitor closes only this GUI window, while
Help → About shows the running package version.

Validation policy comes from `getvalidationreport.validation_policy`:
`historical_scripts_required: true` is shown as requiring all historical scripts;
`false` is shown with the `assume_valid_checkpoint` only when that value is a
valid hash. Missing or malformed policy metadata is displayed as unknown. A
server without the required validation-report RPC cannot provide a fresh required
status sample, so the attached view reports the RPC error/stale state instead of
inferring strict validation from an older coverage label. The Overview labels
`initialblockdownload` as the daemon estimate, warns when connected or header
height is zero, and says that a 100% connected/header height ratio is not an ETA,
work-based validation measure, or catch-up guarantee.

### Attached-block checks completed and pending

Completed native checks used the actual attached node and block 83018, not demo or
fixture data. The inspector loaded 225 transaction summaries in three pages and
stopped offering more when all were loaded. A map cell selected its matching
transaction; the table selected a real one-input/two-output transaction and showed
its full txid, unknown fee, input/output facts and selectable address. At 760×600
and 1440×900 with 100% scale, the map caption, table, and detail panes fit and
remained readable. Lookup-snapshot status was visible. The attached console
returned actual chain info and rejected a method outside its allowlist. Traffic
counters/rates and the graph rendered; six peer rows were visible and peer-address
masking was checked. Help/About showed the package version. Node → Close monitor
closed only the GUI; the daemon remained active and its height advanced from
162,749 to 162,836.

A later native check used actual mainnet block 200000
(`000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf`). Map
selection opened transaction 384
(`bcb887acb2c01b6c5c8b92c22a368135d207f07a26eff170fe730b1cd40d2547`), with
440 inputs and 2 outputs. Input pages 1–100, 101–200, 201–300, 301–400, and
401–440 were displayed; Previous returned through 101–200 and 1–100, and forward
navigation reached the final page with no Next control. The detail heading stayed visible.
This confirms >100-input paging and backward navigation for that transaction.
The RPC responded quickly; controller retention, timeout and single-flight states
were tested, but delayed native RPC was not exercised. The GUI
closed with exit 0 through Node → Close monitor; the same daemon PID continued
from height 214,599 to 219,741 with five peers and 971,827 headers. Full IBD
remains in progress; this is not a completion claim.

A later native check used block 275318
(`00000000000000028f7229a62048c5401bc1f9e939ff144c15abdf38c0c31091`), which
contains 1,339 transactions. At 1440×900/100%, transaction index 291, txid
`42af068a6fede69b672226affacb35083a6f4c226e17d0798f8f8436db272cf4`, showed
one input and 111 outputs. The view advanced from outputs 1–100 to 101–111,
removed Next on the last page, and Previous returned to outputs 1–100. At
760×600/100%, page 1 was visible but page 2 was not confirmed. The first detail
request returned OS error 11; explicit reselection recovered the 111 outputs.
Fee stayed unknown because retained undo admission coverage was incomplete; no
automatic retry or known-fee result is claimed. See the
[native output-paging note](../experiments/2026-10-17-native-output-paging.md).
The GUI closed with exit 0 and zero windows while daemon PID 1,318,056 remained
active at checked height 282,769 (09:44:29.321384 UTC). This does not imply IBD
completion.

Native checks show wrapped transaction rows with weight and the full stacked
next-block hash at 130%/760×600. At 200%/1440×900, the View menu's solid scrollbar
exposes scale and privacy controls without overlap and keeps the menu open while
scrolling. At 1440×900/100%, direct keyboard dispatch verified click index 0 →
Tab to txid 0 → Tab to index 1 → Space selects transaction 1 and opens matching
details. Missing-cookie recovery, screen-reader behavior, and cross-platform
behavior remain unverified. The 1440×900/100% output-page flow is verified;
760×600 page 2 and other scale combinations remain unverified.
Do not use fixture or demo data for live attached-node checks.

Keep native screenshots and provenance notes in a review-artifact directory
outside the repository. Do not include private peer addresses in shared artifacts.

## Acceptance requirements

- The same node commands and status semantics must serve the CLI and GUI.
- Status labels distinguish headers, active tip, historical validation, assumptions,
  local policy, wallet/index coverage and observation freshness.
- Text and keyboard alternatives accompany colors, graphs, animation and pointer
  actions. Keep AccessKit enabled and verify actual screen-reader behavior on each
  supported platform; enabling the feature alone is not an accessibility audit.
- Long lists render visible rows and retained data has defined limits. Hidden/idle
  views should not force continuous repainting.
- Test the smallest supported viewport, increased text scale, long identifiers,
  empty lists, unavailable measurements, stale data and failures. Check all three
  themes for readable text, selected/hover/focus states and visible boundaries.
- Graphs reflect Bitcoin behavior: blocks arrive independently of the local mempool,
  local relay rejection does not imply block invalidity, and confirmations can be
  affected by reorganizations.
- Network and disk operations run outside the paint callback. Explicitly distinguish
  a draft setting from a validated, applied and acknowledged node configuration.
