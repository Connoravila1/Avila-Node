# Foundation review — September 13, 2026

Reviewed the original `b54db78` scaffold, both GitHub branches, the shared planning
conversation and the owner's PDF. The original workspace compiled and its 22 tests
passed. Its configuration validation, bounded diagnostic history, explicit startup
failure and separation of headless/desktop entry points provide a usable foundation.

## Findings and completed changes

| Finding | Resolution |
| --- | --- |
| Scope and roadmap work stopped after a short README | Added scope, architecture, staged acceptance gates, GUI guidance and experiment template |
| Scaffold was isolated on a branch with a draft PR | Fast-forwarded `main`, preserved history, pushed it and removed the fully merged branch; GitHub marked PR #1 merged |
| No committed `Cargo.lock`; CI generated a fresh resolution | Generated and committed the application lockfile; CI now requires it |
| Existing source did not match the pinned formatter | Applied the repository's rustfmt configuration |
| CLI binary and coordinator library shared a rustdoc output path | Disabled binary rustdoc generation; library docs own that path and CLI usage remains in `--help` |
| Desktop consisted of four basic inspection pages | Added menus, resizable/compact navigation, searchable virtualized event tables, filtering, details/copy actions, theme/scale controls and development inspectors |
| Logo was outside the repository | Copied the supplied PNG unchanged; embedded it in the desktop and window icon and displayed it in the README |
| Large interface scale could hide event rows below the controls | Added page scrolling and input/render regression coverage at the smallest supported window and double scale |

Verified the pinned Rust 1.98.1 toolchain and egui/eframe 0.36.2 against downloaded
upstream artifacts. Verified the pinned checkout action resolves to the v4 release
line. GUI extras add table support with default features disabled. The CLI's active
dependency graph does not include egui or eframe.

## Validation

- Workspace compilation, formatting, Clippy with warnings denied, and rustdoc with
  warnings denied.
- 24 tests: the original 22 configuration, journal, coordinator and CLI tests, plus
  two egui input/render tests covering search focus, empty results, page shortcuts,
  and content access at the minimum window size and increased scale.
- CLI configuration and JSON inspection smoke checks.
- Native Linux/X11 launch and visual inspection at default and minimum window
  sizes. Keyboard/search behavior is additionally checked directly through egui's
  input pipeline; desktop automation was inconsistent in this environment.
- Local documentation links and the copied logo's checksum.

These checks establish the application foundation, not Bitcoin node correctness.
There is still no consensus validator, persistent chainstate, P2P synchronization,
mempool/relay or wallet backend. Native Wayland, Windows/macOS packaging, screen-reader
behavior and extended operational testing remain future validation work.
