# Desktop interface

`avila-gui` is the node's desktop interface, built on
[eframe 0.36.2](https://docs.rs/eframe/0.36.2/eframe/trait.App.html) with the
glow renderer. It should make the node pleasant to run and its behavior
understandable. Every figure it shows comes from a defined source, with unknown,
stale and disconnected states shown as such, and the node stays fully usable
without it.

This page records what exists, the rules the interface follows, and what is
planned next.

## What exists

The window has a brand rail down the left (the logo's orange field), a status
line across the top (phase; block, peers, network and uptime; Start/Stop), and one
page at a time:

| Page | What it shows | Source |
| --- | --- | --- |
| Overview | The Trust Ribbon (proven vs. assumed history, measured by blocks or by work), the last block, peers, the mempool with a preview of the next block, recent blocks | Sync snapshots; the ribbon mirrors `getvalidationreport` |
| Chain | The coverage ribbon with a year ruler, halvings and zoom; validation and snapshot details; block rhythm as bars or a block clock | Chain profile and validation report |
| Peers | A constellation of peers (distance is ping, dots sized by blocks delivered, lines show transport), a peer panel with the BIP324 session fingerprint and traffic by purpose, and a sortable table | Peer snapshots |
| Activity | A filterable log of blocks, peers, verification and node events, in UTC | Session events and the node journal |
| Settings | How the next run starts (peers, proxy, pruning, cache, listening, indexes, Electrum), privacy, appearance, this build's details | `RunSettings` and preferences |
| Toybox | A game and two skins, shown only when Settings turns it on | Nothing from the node |

Shortcuts: Ctrl+1–5 switch pages; Ctrl+Shift+H hides peer addresses.

### Rules the interface follows

- **Orange means proven by this machine.** It marks only what this node verified
  itself: the ribbon's solid segments, the proven percentage, the block pulse on the
  peer graph, the clock's center. Hatched orange means assumed from a snapshot.
  Skins remap the color, not the meaning.
- **Type:** Jost for display numbers, Instrument Sans for interface text, IBM Plex
  Mono for data. Block hashes show their leading zeros dimmed.
- **Privacy follows Bitcoin Core's split.** Full peer addresses appear where you go
  looking for them (the table and the peer panel) and never in views made for
  sharing: the peer graph labels peers by software, and the activity log says
  "peer N". Settings → Privacy (or Ctrl+Shift+H) masks everything. Peer user agents
  are sanitized with Core's character set and length limit before display.
- **Eclipse warnings** come from the node's advisory checks and link to the Peers
  page. They are signs, not proof.
- **Performance budget:** every page idles at about 4 frames per second. A frame
  costs about 0.5–0.9 ms in release builds (1–1.4 ms with a toybox skin).
  Animations run only on pages that draw them and never chase a continuously moving
  target. Network and disk work stay off the paint path.

### Appearance

Light (the default), Dark, or Match the system, at 90–130% size. Preferences are
saved through eframe's storage. Only appearance is saved today; see
[Known gaps](#known-gaps).

### The toybox

Off by default. Nothing in it touches the node, and it must stay light: everything
is drawn in code.

- **Shitcoin Defense:** protect the bitcoin in the middle by turning a shield.
  Knock shitcoins away and let sats through. Three get in and it's over. Waves speed
  up; combos, a halving power-up, and a best score kept in preferences. It opens only
  when you press Play.
- **Windows XP skin:** a full Luna desktop. The title-bar buttons really minimize,
  restore and close the window. It adds menus, toolbar, address bar, task pane,
  status bar, taskbar, a Start menu, dialogs, and a tray balloon for eclipse
  warnings. XP's fonts (Tahoma or Verdana, Trebuchet MS) are borrowed from the
  system when installed and never bundled. No Microsoft artwork is used.
- **Julia skin:** pink throughout, with titles and big numbers in Pacifico,
  hearts in place of dots, a candy-striped ribbon with a bow, and jelly buttons.

Download cost, stripped release binary: the first toybox +48.9 KB, the XP desktop
+143.6 KB, and the Julia round (including a 21.6 KB Pacifico subset, OFL) +72.8 KB.

### Development harnesses

All run with `--demo`, a deterministic simulated mainnet that every screen labels
as simulated.

| Variable | Effect |
| --- | --- |
| `AVILA_GUI_CAPTURE=<dir>` | Saves a PNG of every page and pose, then quits |
| `AVILA_GUI_CAPTURE_ONLY=<text>` | Limits the capture to file names containing the text |
| `AVILA_GUI_BENCH=1` | Prints idle frames per second and frame times per page |
| `AVILA_GUI_PAGE=<page>` | Opens on that page |
| `AVILA_GUI_SKIN=xp\|julia` | Wears a skin for one run without saving preferences |

## Known gaps

- **Node settings are not saved.** The "Starting the node" form resets every time the
  app opens; only appearance persists.
- **The config file holds four fields** (schema version, network, data folder,
  journal size) and rejects any other key. Peers, proxy, cache, pruning, indexes,
  listening, Electrum and RPC exist only as `avila run` flags.
- **No network choice in the app.** Started without `--config`, the interface runs
  on regtest with a `./data` folder, so a desktop launcher cannot reach mainnet.
- **Mostly verified on simulated data.** Real-sync behavior (failures, stalls,
  reorgs), the XP window's live drag and resize, and the game's feel with a real
  mouse still need checking.

## Plan

In priority order:

1. **Persistent node settings, shared by the CLI and the app.** Extend the config
   schema (version 2) to hold the run options, with command-line flags still able to
   override the file, as Core does with `bitcoin.conf`. Settings reads and writes
   that file: validate before saving, write atomically, keep "applies at next start",
   and show the file's path with a button to open its folder for hand editing. There
   will be no raw text editor in the app. RPC passwords stay out of the form (cookie
   authentication), and the file is readable by its owner only.
2. **A first-run screen.** Choose the network, the data folder and a disk budget
   (full or pruned), with the trust choice explained: start from a snapshot, or verify
   everything from genesis. The node itself never discovers or creates config files
   on its own; the app would create one only after this explicit confirmation. That
   decision is pending with the owner.
3. **Real-sync testing.** Signet, then mainnet, covering failure, stall and reorg
   states and the XP window controls.
4. **Show the node's newer evidence:** the censorship-divergence alarm (#19),
   per-block verification receipts (#5) and mempool history (#32). Wallet screens
   (balances, receive, send, signer) come after the wallet's security audit.
5. **Peer controls,** as Core has: disconnect or ban from the peer panel, add a peer,
   pause networking.
6. **Search and a block page.** Look up a height, hash or transaction id; each block
   says whether it was proven here or assumed.
7. **Accessibility.** The hand-painted controls (buttons, radios, check boxes, skin
   widgets) must report themselves to screen readers through AccessKit, with keyboard
   paths for every action and a reduced-motion option.

Later, if wanted:
- running in the tray and starting at login (a tray dependency and platform work);
- an RPC console;
- a mempool and fee page;
- a resource panel (disk, memory, bandwidth);
- a copy-diagnostics button for bug reports.

## Acceptance requirements

- The same node commands and status semantics serve the CLI and the GUI.
- Status labels distinguish headers, active tip, historical validation, assumptions,
  local policy, wallet and index coverage, and observation freshness.
- Text and keyboard alternatives accompany colors, graphs, animation and pointer
  actions. Keep AccessKit enabled and verify actual screen-reader behavior on each
  supported platform; enabling the feature alone is not an accessibility audit.
- Long lists render only visible rows, and retained data has defined limits. Hidden
  or idle views do not force continuous repainting.
- Test the smallest supported window (760×480), larger text sizes, long identifiers,
  empty lists, unavailable measurements, stale data and failures, in light, dark
  and each skin: readable text, visible selected, hover and focus states.
- Graphs reflect Bitcoin behavior: blocks arrive independently of the local mempool,
  local relay rejection does not imply block invalidity, and reorganizations can
  change confirmations.
- A draft setting is distinguished from a validated, applied and acknowledged node
  configuration.
