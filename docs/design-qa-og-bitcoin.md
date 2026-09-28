# OG Bitcoin skin — native visual verification

Final result: passed

The user reviewed the native preview on 2026-09-28, accepted its appearance,
and requested the work be wrapped up. No further visual iteration followed.

## Target and implementation

The target is **Bitcoin 0.1, January 2009**, from
[trottier/original-bitcoin](https://github.com/trottier/original-bitcoin).
The previous skin's 2011/Qt interpretation was the wrong client.

The authoritative layout and assets are
[uibase.cpp](https://github.com/trottier/original-bitcoin/blob/master/src/uibase.cpp),
[ui.cpp](https://github.com/trottier/original-bitcoin/blob/master/src/ui.cpp), and
[src/rc](https://github.com/trottier/original-bitcoin/tree/master/src/rc).
The visual reference is an
[archived Bitcoin 0.1.x screenshot](https://cloudfront-us-east-1.images.arcpublishing.com/coindesk/J5K736OYEZCXTNR2H4KU4IT2IM.png)
with Windows XP Silver chrome. Its later 0.1.x wallet state differs from the
0.1.0 source: for example, the source includes the Change button.

Source visual truth: [reference.png](evidence/og-bitcoin/reference.png).
Rendered implementation: [original-size.png](evidence/og-bitcoin/original-size.png)
and [compact.png](evidence/og-bitcoin/compact.png).
Full-view comparison: [comparison.png](evidence/og-bitcoin/comparison.png).
Focused typography, icon, and control comparison:
[controls-comparison.png](evidence/og-bitcoin/controls-comparison.png).
These comparisons put both images in the same input; the implementation is
a native eframe capture, not a browser mockup or a pasted original screenshot.

## Dimensions and state

- Historical image: 1634 × 892 pixels; client crop `(18, 0, 1578, 732)`.
  The crop was normalized to 705 × 331 pixels for comparison. The archive
  does not establish the original display density, so this is composition
  normalization rather than a claim of exact historical DPI.
- Native default-size capture: 1175 × 807 physical pixels, approximately
  705 × 484 logical points, at 1.6666666 pixels per point.
- Native compact capture: 1175 × 552 physical pixels, approximately
  705 × 331 logical points, at the same density.
- Linux reports a fractional height of 484.1875 / 331.1875 points. Evidence
  images round to the requested logical size before comparing.
- State: light/Silver appearance, Overview, All Transactions selected.
  The historical client has a wallet and two transactions. Avila has no
  wallet, so the original wallet fields and list stay empty, with explanatory
  tooltips. Native verification uses the existing simulated session; its
  title and status strip identify simulated data.

## Findings and fixes

No remaining actionable P0/P1/P2 findings in the accepted appearance.

| Surface | Verification and outcome |
| --- | --- |
| Fonts and typography | Replaced modern display/UI/mono faces with compact 11-point UI text. Prefer installed Tahoma, with bundled WineTahoma regular/bold fallback; the caption prefers installed Trebuchet MS Bold. Compared toolbar labels, address labels, tabs, headings, and footer text in the focused image. WineTahoma glyph widths and egui antialiasing differ slightly from Microsoft Tahoma/GDI (P3). |
| Spacing and layout | Restored the compact caption/menu/two-tool toolbar, source-sized 250-point address field, balance field, notebook, five transaction columns, full-height white list, and three status fields. The default frame is 705 × 484; a 705 × 331 compact capture and larger page captures also render. The source's fixed control geometry takes precedence over the later archived client's geometry. |
| Colors and tokens | Replaced beige Qt styling with Silver surfaces, black text, white list background, native blue selection, beveled edges, and compact square menus. The historical image has a slight color cast; Silver system colors are used rather than copying the image's cast (expected difference). |
| Asset fidelity and quality | Toolbar arrow/book and BC window icons are original bitmap/ICO resources, with their original transparency masks. No substitute logo or generated art. Source hashes and licensing are in the asset README. Nearest-neighbor sampling preserves small source icons. |
| Copy and content | Original File/Options/Help, Send Coins, Address Book, Your Bitcoin Address, Balance, All Transactions, Status/Date/Description/Debit/Credit, and footer count labels restored. Added Node menu and Recent Blocks tab preserve Avila's functionality. Empty wallet fields, disabled wallet controls, and simulated labels are intentional product-state differences. |

## Comparison history

1. **Before:** [before.png](evidence/og-bitcoin/before.png). P1: wrong-era beige
   chrome and modern fonts. P1: raised page-navigation toolbar replaced the
   original wallet toolbar. P2: large page margins and a short block panel
   changed the original list proportions; footer dot/action button changed
   the original status strip.
2. **First native revision:** original icons, Silver frame, period typography,
   compact controls, and full-height list. P2: Overview still substituted
   node labels for the original address/balance/transaction surface, and menu
   headers retained modern button borders.
3. **Revised and accepted preview:** restored the original wallet surface
   and transaction notebook, moved node data to Recent Blocks, removed menu
   header borders, and replaced the Toybox thumbnail with the rendered GUI.
   Post-fix evidence is the full-view and focused comparison linked above.

## Native interactions

[interaction-receipts.json](evidence/og-bitcoin/interaction-receipts.json)
records actual page/skin/session state, viewport density, and clipboard
commands after real egui pointer input. All seven recorded checks pass:

- Recent Blocks displays existing node data; selected rows use native blue.
- Copy to Clipboard emits the complete current chain tip.
- Node → Chain reaches the Chain page.
- Stop reaches Stopped with zero live connections; Start resumes the demo.
- Back to the modern look restores the Standard skin.
- Default and compact window captures reach their requested dimensions
  after rounding the platform's fractional logical height.

The navigation check was repeated in a fresh process because a prior open
menu affected sequential capture input. Its successful fresh-process
capture is [navigate-chain.png](evidence/og-bitcoin/navigate-chain.png).
Other extra pages were captured at 1120 × 760 points. About, menu, selected,
start/stop, and clipboard states were inspected in the native GUI.

No runtime errors were emitted by the completed capture runs.
Release validation: `cargo test --offline --release -p avila-gui --features
devtools -j 2` passed all 56 tests. Both build and tests ran under
`tools/guard_run.sh --max 3072 --reserve 4096`; observed peak memory was
1101 MiB for the final preview build and 779 MiB for the passing test run.
An earlier test compile found two outdated preference fixtures from
concurrent work; the other instance corrected them before the passing run.
The private preview's build features and source hashes are recorded in
[build-receipt.json](evidence/og-bitcoin/build-receipt.json); its sources were
stable during compilation. A subsequent documentation-only correction
updated the Classic enum comment from 2011 to 2009.

## Implementation handoff

- Select **Toybox → OG Bitcoin**. The original client frame opens on Overview;
  leaving the skin restores the previous window size.
- Extra pages, node start/stop, tip copying, Toybox, address privacy, and the
  modern appearance are accessible through **Node**. The original wallet
  tools have explanatory tooltips; this skin does not add a wallet or miner.
- Rendering is in `crates/avila-gui/src/classic.rs`; font/style installation
  is in `theme.rs`; integration is in `app.rs`. Original resource provenance
  is in `assets/original-bitcoin/README.md`; font provenance is in
  `assets/fonts/README-WineTahoma.md`.
- The normal GUI build excludes capture tooling. Reproduce the captures
  with a `devtools` release build, `AVILA_GUI_CAPTURE=<dir>`,
  `AVILA_GUI_CAPTURE_ONLY=classic`, `AVILA_GUI_SKIN=classic`, and `--demo`.
  Run builds through `tools/guard_run.sh` as required by the repository.
- This work stays within GUI presentation and its existing action hooks.
  Other instances' shared-tree changes are retained.

Follow-up polish: exact Windows GDI font rasterization and inactive-window
caption treatment remain platform-dependent P3 differences. They do not
block the user-accepted skin.
