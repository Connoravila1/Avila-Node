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
invented measurements. **View → Appearance** provides Light, Dark and Black themes
and 75–200% interface scaling. Black uses `#000000` for panel and window backgrounds;
controls retain visible boundaries and interaction states. Theme and scale persist
locally in a versioned appearance record. `--theme light|dark|black` selects a startup
theme. Generic egui memory, search terms, node data and window state are not saved.

The default is Dark at 100% scale. On Linux, appearance is stored in
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
body is identified explicitly. The weight composition and transaction table start
with 100 transactions per request and can be paged; the GUI retains at most 2,000
transaction summaries for the selected block. Composition is labeled as partial
while more transactions remain. Fee and feerate fields are not part of this
inspector's data contract.

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

The guarded native workspace pipeline passed after attach mode was integrated:
build, rustdoc, Clippy, and 1,138 tests passed (5 ignored). The CLI and GUI were
deployed, and a clean restart advanced validation from height 1,555 to 1,610 with
block-hash consistency checks passing. Native attach captures from a running node
show the Overview and block 170 at 760×600 and 1440×900. Keyboard navigation
reached Blocks and height search selected 170. The inspector showed
active-chain/fully-checked status and measured header/body facts. Final lower-page
captures show both transaction rows and all seven table columns at both sizes.
Displayed txids are compacted to fit; clicking the coinbase txid copied and
matched the complete txid. The Node menu and theme-tinted brand mark are visible
in the light theme.

Further native attach checks showed an actual `getblockchaininfo` result at
connected height 37,129, rejection of an RPC method outside the console allowlist,
traffic counters/rates and plot, and six peer rows. Peer addresses were kept out
of repository documentation and shareable captures. Closing the GUI exited
cleanly while the same daemon remained active and advanced from height 40,815 to
40,835. These changing heights reflect an active sync sample, not catch-up or
completion. GUI tests (74), Clippy, and GUI build passed after the table layout and
compact-txid changes; the guarded workspace pipeline also passed build, rustdoc,
Clippy, and 1,138 tests (5 ignored).

Transaction paging beyond the first 100 entries, zoom behavior, missing-cookie
recovery, and screen-reader behavior remain unverified. These observations are
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

Completed native checks used the actual attached node and block 170, not demo or
fixture data. At 760×600 and 1440×900, both transaction rows and all seven columns
were readable. The displayed txid is abbreviated; a native clipboard comparison
confirmed clicking it copied the complete coinbase txid. Keyboard navigation
reached Blocks, height search selected 170, and the Node menu remained visible in
light theme. The attached console returned actual chain info and rejected a method
outside its allowlist. Traffic counters/rates and the graph rendered; six peer
rows were visible. Closing the GUI left the daemon running, and its connected
height advanced from 40,815 to 40,835.

Still to check: choose a body-available block with at least 100 transactions,
load the next page, and verify the partial-composition label and table update.
Also verify missing-cookie recovery, zoom, and screen-reader behavior. Do not use
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
