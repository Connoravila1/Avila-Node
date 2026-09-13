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
