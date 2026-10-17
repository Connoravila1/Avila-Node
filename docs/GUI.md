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
body is identified explicitly. The transaction map sizes each rectangle by its
share of loaded transaction weight; the block header/framing is excluded and
shade is a logarithmic cue. It covers only summaries currently loaded. A cell or keyboard-selectable transaction-table
row selects that transaction. The inspector retains at most 2,000 summaries,
fetched 100 at a time, and labels partial map coverage while more are available.
Selected transaction detail requests are pinned to block hash, txid, and index;
input and output pages are each capped at 100. The view shows outpoint, sequence,
script/witness prefixes, output values and standard addresses when available.
Prevout values and fees remain explicitly unknown because this detail path does
not look up previous outputs; script hex is shown as a bounded prefix when
truncated.

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

Final native validation passed GUI formatting, Clippy, 82 GUI tests, and a
release build under the 2.5 GiB memory cap (1 GiB reserve; 811 MiB peak, 55 s).
The full workspace passed 1,152 tests (5 ignored), plus 14 Python tests. Live
captures used mainnet block 83018
(`00000000002bba570c3fbc62f77f54685b7011bfa202a086d4005131cc0ceed6`), which
contains 225 transactions. The inspector loaded summaries in 100 → 200 → 225
steps, updated its loaded-coverage labels, and removed the load-more button at the
end. Selecting map cell 84 opened the matching transaction detail; selecting
table row 1 showed the real one-input/two-output transaction, full txid, and
explicitly unknown fee. The 200 px input/output panes showed the facts and
selectable address. The block was marked as a lookup snapshot. At 760×600 and
1440×900 with 100% scale, the partial-map caption, transaction table, map, and
detail panes were readable.

The attached View scale was exercised at 130% and 200%, then restored to 100%
through the scrolled menu. The View scrollbar remained usable without closing the
menu and exposed 175%, 200%, and privacy options at 200% on 1440×900. The
Help/About version was correct. Black-to-Dark reset, peer-address masking on six
rows, and Node → Close monitor were checked. Closing the monitor left the daemon
active while its height advanced from 162,749 to 162,836. This is a changing sync
sample, not evidence of completion.

At 130% on 760×600, long block hashes, transaction details, outpoints, addresses,
and scripts wrap; the transaction-table Weight column and adjacent Next block hash
still clip. At 100% on 760×600, fact labels and values remain readable. At 200% on
1440×900, the View menu can be scrolled to and used for every scale and privacy
choice; while hovered, its floating scrollbar overlaps the end of the privacy
label. Keyboard selection of a transaction-table row and screen-reader behavior
were not verified. A transaction with more than 100 inputs or outputs was not
tested, and missing-cookie recovery remains unverified. These observations are
not a full visual or accessibility audit.

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

At 130% on 760×600, the transaction-table Weight column and adjacent Next block
hash still clip, although long inspector/detail fields wrap. At 200% on 1440×900,
scrolling the View menu exposes 175%, 200%, and privacy; its floating scrollbar
overlaps the end of the privacy label while hovered. Keyboard selection of a
transaction-table row, a transaction with more than 100 inputs or outputs,
missing-cookie recovery, and screen-reader behavior remain unverified. Do not use
fixture or demo data for live attached-node checks.

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
