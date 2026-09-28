//! Every configuration knob, as a table — the node's `config
//! describe`, live. Knobs the sync loop can take mid-run (`Live`)
//! get an inline control and apply at the next tick; the rest carry
//! a "restart" mark. Edits are session-scoped: the config file is
//! never written from here, and a restart reverts to it. Each applied
//! edit journals `config_changed`, each refusal `config_rejected` —
//! the activity stream is the receipt.

use super::{Action, Scene};
use crate::theme::mono;
use crate::widgets::{self, Kind};
use avila_node::Node;
use avila_node::config::{EditKind, describe_config};
use avila_node::sync::ControlMsg;
use eframe::egui::{self, RichText, TextEdit, Ui};
use std::collections::BTreeMap;
use std::sync::mpsc::Sender;

/// Enum knobs and their legal strings — the same sets `config` and
/// `apply_knob` validate; the dropdown can't offer an invalid one.
const CHOICES: &[(&str, &[&str])] = &[
    ("network", &["mainnet", "testnet4", "signet", "regtest"]),
    ("relay.tx.announce", &["all", "private_only", "none"]),
    ("relay.block.announce", &["auto", "headers", "inv", "none"]),
    ("relay.block.serve", &["full", "tip", "none"]),
    ("extrapool.relay", &["never", "outbound", "all"]),
];

/// The page's live-edit state — survives navigation, dies with the app.
#[derive(Default)]
pub struct ConfigPage {
    /// Text-edit drafts, per path — the un-applied in-flight value.
    drafts: BTreeMap<String, String>,
    /// Sent on the control channel, not yet journaled back.
    pending: BTreeMap<String, serde_json::Value>,
    /// Confirmed live this session — what `config_changed` reported.
    overrides: BTreeMap<String, serde_json::Value>,
    /// `config_rejected` reasons, per path.
    rejected: BTreeMap<String, String>,
    /// Restart knobs staged into the runtime overlay — what the next
    /// start will load.
    staged: BTreeMap<String, serde_json::Value>,
    /// The path filter box.
    pub filter: String,
    /// What the last preset application did ("applied 5 live knobs;
    /// TOML for the rest is on the clipboard").
    preset_note: Option<String>,
    /// The preset whose preview card is open.
    preset_open: Option<PresetSel>,
    /// The save-as-preset card's draft name while it's open.
    saving: Option<String>,
    /// The header's circle-i card — how the layers fit together.
    info_open: bool,
}

impl ConfigPage {
    /// Fold a journal event into the edit state — `config_changed`
    /// confirms a pending edit, `config_rejected` records the refusal.
    /// `run_started` wipes the lot: a new run reads the file, not the
    /// old session's edits.
    pub fn note(&mut self, ev: &serde_json::Value) {
        let Some(kind) = ev.get("kind").and_then(|k| k.as_str()) else {
            return;
        };
        let path = ev.get("path").and_then(|p| p.as_str()).unwrap_or("");
        match kind {
            "run_started" => {
                self.pending.clear();
                self.overrides.clear();
                self.rejected.clear();
                self.staged.clear();
                self.preset_note = None;
            }
            "config_changed" if !path.is_empty() => {
                self.pending.remove(path);
                self.rejected.remove(path);
                if let Some(v) = ev.get("value") {
                    self.overrides.insert(path.to_string(), v.clone());
                }
            }
            "config_rejected" if !path.is_empty() => {
                self.pending.remove(path);
                let reason = ev
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .unwrap_or("rejected")
                    .to_string();
                self.rejected.insert(path.to_string(), reason);
            }
            _ => {}
        }
    }

    /// True when the page's live state already carries `value` for
    /// `path` — applied or in flight — so a file diff on that knob
    /// isn't a divergence, it's the edit's persistence landing.
    pub fn already_live(&self, path: &str, value: &serde_json::Value) -> bool {
        self.overrides.get(path) == Some(value) || self.pending.get(path) == Some(value)
    }
}

/// The knob's effective value this session — the override the journal
/// confirmed, else the value staged for the next start, else what the
/// config file said. Owned so the map stays free for the row's edits.
fn effective(state: &ConfigPage, path: &str, file: &serde_json::Value) -> serde_json::Value {
    state
        .overrides
        .get(path)
        .or_else(|| state.staged.get(path))
        .cloned()
        .unwrap_or_else(|| file.clone())
}

/// JSON → TOML for the overlay write; `Null` means "remove the key" —
/// the file's own value returns.
fn toml_of(v: &serde_json::Value) -> Option<toml::Value> {
    match v {
        serde_json::Value::Bool(b) => Some(toml::Value::Boolean(*b)),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(toml::Value::Integer)
            .or_else(|| n.as_f64().map(toml::Value::Float)),
        serde_json::Value::String(s) => Some(toml::Value::String(s.clone())),
        serde_json::Value::Array(a) => {
            Some(toml::Value::Array(a.iter().filter_map(toml_of).collect()))
        }
        serde_json::Value::Object(m) => Some(toml::Value::Table(
            m.iter()
                .filter_map(|(k, v)| toml_of(v).map(|t| (k.clone(), t)))
                .collect(),
        )),
        serde_json::Value::Null => None,
    }
}

/// Persist a knob into the runtime overlay — validated against the
/// merged config before the file moves. Returns the reason on refusal.
fn stage(file: &std::path::Path, state: &mut ConfigPage, path: &str, value: serde_json::Value) {
    match avila_node::config::write_overlay_knob(file, path, toml_of(&value)) {
        Ok(()) => {
            state.staged.insert(path.to_string(), value);
            state.rejected.remove(path);
        }
        Err(reason) => {
            state.rejected.insert(path.to_string(), reason);
        }
    }
}

fn render_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Bool(b) => (if *b { "on" } else { "off" }).to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "—".to_string(),
        serde_json::Value::Array(a) => {
            if a.is_empty() {
                "—".to_string()
            } else {
                a.iter()
                    .map(|x| {
                        x.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| x.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        }
        other => other.to_string(),
    }
}

/// One named bundle: `live` paths go to the running node through the
/// control channel; `restart` paths go on the clipboard as a TOML
/// block to paste into the config file — the app never writes it.
struct Preset {
    name: &'static str,
    /// Who this is for — one plain line under the name.
    who: &'static str,
    /// (path, JSON literal) — parsed at apply time.
    live: &'static [(&'static str, &'static str)],
    /// (path, TOML literal) — emitted under `[section]` headers.
    restart: &'static [(&'static str, &'static str)],
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "Blocks only",
        who: "For a node that syncs and verifies but doesn't relay or serve \
              transactions — the extrapool still records what it refused.",
        live: &[
            ("net.blocks_only", "true"),
            ("relay.tx.announce", "\"none\""),
            ("relay.tx.stem", "false"),
            ("relay.block.serve", "\"tip\""),
            ("extrapool.observe", "true"),
        ],
        restart: &[],
    },
    Preset {
        name: "Small footprint",
        who: "For a laptop or small VPS — a 64 MiB mempool with two-hour \
              expiry and no extrapool; pruning and dbcache go in the file.",
        live: &[
            ("mempool.max_mb", "64"),
            ("mempool.expiry_secs", "7200"),
            ("extrapool.observe", "false"),
        ],
        restart: &[("storage.prune_mb", "2000"), ("storage.dbcache_mb", "256")],
    },
    Preset {
        name: "Full serving",
        who: "For a well-connected box meant to serve the network — full \
              block serving, compact blocks, filters; indexes go in the file.",
        live: &[
            ("net.blocks_only", "false"),
            ("relay.block.serve", "\"full\""),
            ("relay.tx.announce", "\"all\""),
            ("relay.block.compact_serve", "true"),
            ("filters.serve", "true"),
        ],
        restart: &[
            ("indexes.txindex", "true"),
            ("filters.build", "true"),
            ("net.listen", "\"0.0.0.0:8333\""),
        ],
    },
];

/// The header's circle-i card — the layer model in six lines.
fn info_card(ui: &mut Ui, pal: crate::theme::Palette) {
    ui.add_space(4.0);
    egui::Frame::new()
        .fill(pal.well)
        .stroke(egui::Stroke::new(1.0, pal.hairline))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_max_width(560.0);
            ui.label(
                RichText::new("how this page works")
                    .size(12.0)
                    .strong()
                    .color(pal.text),
            );
            ui.add_space(4.0);
            for line in [
                "The app never writes your config file. Anything you change \
                 here goes to <name>.runtime.toml beside it, and that file wins \
                 when the config loads.",
                "live — sent to the running node right away, and written to \
                 the overlay so it survives a restart.",
                "needs restart — staged into the overlay. The node only reads \
                 it when it starts.",
                "If you edit either file yourself, a banner lists what changed. \
                 Live changes can be applied without restarting.",
                "A restart only restarts the node — the app stays open. Stop \
                 node, start node, done.",
                "Nothing here touches consensus rules — no knob changes what \
                 makes a block valid.",
            ] {
                ui.label(RichText::new(line).size(12.0).color(pal.muted));
            }
        });
}

fn presets_menu(ui: &mut Ui, state: &mut ConfigPage, prefs: &mut crate::prefs::Prefs) {
    let pal = crate::theme::Palette::of(ui.ctx());
    egui::ComboBox::from_id_salt("config-presets")
        .selected_text(RichText::new("presets…").size(12.0).color(pal.muted))
        .width(140.0)
        .show_ui(ui, |ui| {
            for (i, p) in PRESETS.iter().enumerate() {
                if prefs.hidden_presets.iter().any(|n| n == p.name) {
                    continue;
                }
                if ui
                    .selectable_label(false, p.name)
                    .on_hover_text(p.who)
                    .clicked()
                {
                    state.preset_open = Some(PresetSel::BuiltIn(i));
                    ui.close();
                }
            }
            if !prefs.custom_presets.is_empty() {
                ui.separator();
            }
            for (i, c) in prefs.custom_presets.iter().enumerate() {
                if ui
                    .selectable_label(false, &c.name)
                    .on_hover_text("your preset")
                    .clicked()
                {
                    state.preset_open = Some(PresetSel::Custom(i));
                    ui.close();
                }
            }
        });
}

/// The save-as-preset card — a name, a count of what it captures, and
/// the save/cancel pair.
#[allow(clippy::too_many_arguments)]
fn save_card(
    ui: &mut Ui,
    pal: crate::theme::Palette,
    state: &mut ConfigPage,
    knobs: &[avila_node::config::KnobDescription],
    prefs: &mut crate::prefs::Prefs,
) {
    let diverged = |kind: EditKind| -> Vec<(String, String)> {
        knobs
            .iter()
            .filter(|k| k.edit == kind)
            .filter(|k| effective(state, k.path, &k.value) != k.default)
            .map(|k| {
                (
                    k.path.to_string(),
                    serde_json::to_string(&effective(state, k.path, &k.value)).unwrap_or_default(),
                )
            })
            .collect()
    };
    let live = diverged(EditKind::Live);
    let restart = diverged(EditKind::Restart);
    ui.add_space(6.0);
    egui::Frame::new()
        .fill(pal.well)
        .stroke(egui::Stroke::new(1.0, pal.hairline))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.label(
                RichText::new("save the current values as a preset")
                    .size(14.0)
                    .color(pal.text)
                    .strong(),
            );
            ui.label(
                RichText::new(format!(
                    "captures {} live knob{} and {} restart knob{} — everything that \
                     differs from the defaults",
                    live.len(),
                    if live.len() == 1 { "" } else { "s" },
                    restart.len(),
                    if restart.len() == 1 { "" } else { "s" },
                ))
                .size(12.0)
                .color(pal.muted),
            );
            ui.add_space(6.0);
            let mut saved = false;
            ui.horizontal(|ui| {
                if let Some(name) = &mut state.saving {
                    ui.label(RichText::new("Name").size(12.0).color(pal.muted));
                    ui.add(TextEdit::singleline(name).desired_width(220.0));
                    let name = name.trim().to_string();
                    let ok = !name.is_empty() && !(live.is_empty() && restart.is_empty());
                    if widgets::button(ui, "save", Kind::Primary)
                        .on_disabled_hover_text(
                            "needs a name, and something must differ from defaults",
                        )
                        .clicked()
                        && ok
                    {
                        prefs.custom_presets.retain(|c| c.name != name);
                        prefs.custom_presets.push(crate::prefs::CustomPreset {
                            name: name.clone(),
                            live,
                            restart,
                        });
                        state.preset_note = Some(format!("saved preset “{name}”"));
                        saved = true;
                    }
                }
                if widgets::button(ui, "cancel", Kind::Quiet).clicked() {
                    saved = true;
                }
            });
            if saved {
                state.saving = None;
            }
        });
}

/// Which preset a card is showing — one of ours or one the user saved.
#[derive(Clone, Copy)]
enum PresetSel {
    BuiltIn(usize),
    Custom(usize),
}

/// The preview card: every knob the preset touches, its value now and
/// after, what applies live and what stages for restart — then an
/// explicit apply, plus a remove that hides a built-in or deletes a
/// saved one.
#[allow(clippy::too_many_arguments)]
fn preset_card(
    ui: &mut Ui,
    pal: crate::theme::Palette,
    state: &mut ConfigPage,
    control: Option<&Sender<ControlMsg>>,
    config_file: Option<&std::path::Path>,
    prefs: &mut crate::prefs::Prefs,
    knobs: &[avila_node::config::KnobDescription],
    sel: PresetSel,
) {
    // Resolve to owned values so builtins and customs share the loop.
    let (name, who, live, restart) = match sel {
        PresetSel::BuiltIn(i) => match PRESETS.get(i) {
            Some(p) => (
                p.name.to_string(),
                p.who.to_string(),
                p.live
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect::<Vec<_>>(),
                p.restart
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect::<Vec<_>>(),
            ),
            None => {
                state.preset_open = None;
                return;
            }
        },
        PresetSel::Custom(i) => match prefs.custom_presets.get(i) {
            Some(c) => (
                c.name.clone(),
                "your preset".to_string(),
                c.live.clone(),
                c.restart.clone(),
            ),
            None => {
                state.preset_open = None;
                return;
            }
        },
    };
    ui.add_space(6.0);
    egui::Frame::new()
        .fill(pal.well)
        .stroke(egui::Stroke::new(1.0, pal.hairline))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(&name).size(14.0).color(pal.text).strong());
            ui.label(RichText::new(&who).size(12.0).color(pal.muted));
            ui.add_space(6.0);
            let current = |path: &str| -> String {
                knobs
                    .iter()
                    .find(|k| k.path == path)
                    .map(|k| render_value(&effective(state, path, &k.value)))
                    .unwrap_or_else(|| "?".to_string())
            };
            for (path, raw) in &live {
                let new = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(path).font(mono(12.0)).color(pal.text));
                    ui.label(
                        RichText::new(format!("{} → {}", current(path), render_value(&new)))
                            .font(mono(12.0))
                            .color(pal.signal),
                    );
                    ui.label(RichText::new("applies now").size(11.0).color(pal.muted));
                });
            }
            for (path, raw) in &restart {
                let new = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(path).font(mono(12.0)).color(pal.text));
                    ui.label(
                        RichText::new(format!("{} → {}", current(path), render_value(&new)))
                            .font(mono(12.0))
                            .color(pal.signal),
                    );
                    ui.label(
                        RichText::new("needs restart — staged in the overlay")
                            .size(11.0)
                            .color(pal.muted),
                    );
                });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if widgets::button(ui, "apply this preset", Kind::Primary).clicked() {
                    let mut applied = 0;
                    let mut staged_n = 0;
                    for (path, raw) in &live {
                        let value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
                        if let Some(file) = config_file
                            && let Err(e) =
                                avila_node::config::write_overlay_knob(file, path, toml_of(&value))
                        {
                            state
                                .rejected
                                .insert(path.clone(), format!("not persisted: {e}"));
                        }
                        if let Some(tx) = control {
                            let _ = tx.send(ControlMsg::Set {
                                path: path.clone(),
                                value: value.clone(),
                            });
                        }
                        state.pending.insert(path.clone(), value);
                        applied += 1;
                    }
                    for (path, raw) in &restart {
                        let value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
                        if let Some(file) = config_file {
                            stage(file, state, path, value);
                            staged_n += 1;
                        }
                    }
                    let mut note = format!("{name}: {applied} applied now");
                    if staged_n > 0 {
                        note.push_str(&format!(
                            ", {staged_n} staged for the next start in {}",
                            config_file
                                .map(|f| {
                                    avila_node::config::overlay_path(f)
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("the overlay")
                                        .to_string()
                                })
                                .unwrap_or_else(|| "the overlay".to_string()),
                        ));
                    }
                    state.preset_note = Some(note);
                    state.preset_open = None;
                }
                if widgets::button(ui, "cancel", Kind::Quiet).clicked() {
                    state.preset_open = None;
                }
                ui.add_space(8.0);
                if widgets::button(ui, "remove this preset", Kind::Quiet)
                    .on_hover_text("Remove it for good")
                    .clicked()
                {
                    match sel {
                        PresetSel::BuiltIn(_) => prefs.hidden_presets.push(name.clone()),
                        PresetSel::Custom(i) => {
                            prefs.custom_presets.remove(i);
                        }
                    }
                    state.preset_open = None;
                }
            });
        });
    ui.add_space(4.0);
}

/// Parse a draft back into the knob's JSON shape — strings stay
/// strings, digits become numbers, `a->b, c->d` becomes an array.
fn draft_value(path: &str, draft: &str, was: &serde_json::Value) -> Option<serde_json::Value> {
    match was {
        serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            Some(serde_json::Value::String(draft.trim().to_string()))
        }
        serde_json::Value::Number(_) => {
            let t = draft.trim();
            t.parse::<u64>()
                .map(serde_json::Value::from)
                .ok()
                .or_else(|| t.parse::<i64>().map(serde_json::Value::from).ok())
        }
        serde_json::Value::Array(_) => {
            let items: Vec<serde_json::Value> = draft
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect();
            Some(serde_json::Value::Array(items))
        }
        serde_json::Value::Null => Some(serde_json::Value::String(draft.trim().to_string())),
        _ => None,
    }
    .map(|v| {
        // `relay.block.announce`'s empty string is "auto" — the UI
        // shows and accepts the word, the wire takes "".
        if path == "relay.block.announce"
            && let serde_json::Value::String(s) = &v
            && s == "auto"
        {
            return serde_json::Value::String(String::new());
        }
        v
    })
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut Ui,
    s: &Scene,
    state: &mut ConfigPage,
    node: &Node,
    prefs: &mut crate::prefs::Prefs,
    control: Option<Sender<ControlMsg>>,
    config_file: Option<&std::path::Path>,
    // Knob paths whose on-disk value differs from the running node's
    // (`Some(vec![])` = the file changed but no longer parses).
    dirty: Option<&[String]>,
) -> Option<Action> {
    let pal = s.pal;
    let knobs = describe_config(node.config().get());
    // `AVILA_PRESET_PREVIEW=<i>` opens a preset card — the capture
    // harness's way into the preview.
    if let Ok(i) = std::env::var("AVILA_PRESET_PREVIEW")
        && state.preset_open.is_none()
    {
        state.preset_open = Some(PresetSel::BuiltIn(i.parse().unwrap_or(0)));
    }
    widgets::section(
        ui,
        "Node policy",
        Some(
            "Bright marks apply now; dim ones at the next start. Edits land in the \
             .runtime.toml overlay — the file itself is never rewritten.",
        ),
    );
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Filter").size(13.0).color(pal.muted));
        ui.add(TextEdit::singleline(&mut state.filter).desired_width(200.0));
        ui.add_space(14.0);
        // A drawn circle-i — the fonts don't carry ⓘ, so paint it.
        // Left of everything else, where page-level info belongs.
        {
            let (r, resp) = ui.allocate_exact_size(egui::vec2(17.0, 17.0), egui::Sense::click());
            let p = ui.painter_at(r);
            let on = state.info_open;
            p.circle_stroke(
                r.center(),
                7.5,
                egui::Stroke::new(1.0, if on { pal.signal_text } else { pal.muted }),
            );
            p.text(
                r.center() - egui::vec2(0.0, 0.5),
                egui::Align2::CENTER_CENTER,
                "i",
                egui::FontId::proportional(11.0),
                if on { pal.signal_text } else { pal.muted },
            );
            let resp = resp
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("how this page works");
            if resp.clicked() {
                state.info_open = !state.info_open;
            }
        }
        if control.is_none() {
            ui.add(
                egui::Label::new(
                    RichText::new("stopped — edits stage into the overlay")
                        .size(12.0)
                        .color(pal.muted),
                )
                .truncate(),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(file) = config_file {
                // Just the name — the full path is the hover; a long
                // path would push the row off the window's edge.
                let name = file
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("the config");
                if ui
                    .link(
                        RichText::new(format!("edit {name}"))
                            .size(12.0)
                            .color(pal.muted),
                    )
                    .on_hover_text(format!("Open {} in your editor", file.display()))
                    .clicked()
                {
                    let _ = std::process::Command::new("xdg-open").arg(file).spawn();
                }
            }
            if control.is_some() || config_file.is_some() {
                // Put every overridden or staged knob back at its
                // default — live ones through the channel (the same
                // config_changed receipt as a hand edit), all of them
                // into the overlay so the reset survives a restart.
                if !(state.overrides.is_empty() && state.staged.is_empty())
                    && widgets::button(ui, "restore defaults", Kind::Quiet)
                        .on_hover_text(
                            "Every live knob back to its default; every staged value \
                             defaults too — the overlay carries it.",
                        )
                        .clicked()
                {
                    for k in &knobs {
                        let live = state.overrides.contains_key(k.path) && k.edit == EditKind::Live;
                        let restart =
                            state.staged.contains_key(k.path) && k.edit == EditKind::Restart;
                        if !(live || restart) {
                            continue;
                        }
                        if let Some(file) = config_file {
                            let _ = avila_node::config::write_overlay_knob(
                                file,
                                k.path,
                                toml_of(&k.default),
                            );
                        }
                        if live {
                            let _ = control.as_ref().map(|tx| {
                                tx.send(ControlMsg::Set {
                                    path: k.path.to_string(),
                                    value: k.default.clone(),
                                })
                            });
                            state.pending.insert(k.path.to_string(), k.default.clone());
                        }
                    }
                    state.overrides.clear();
                    state.staged.clear();
                    state.drafts.clear();
                    state.rejected.clear();
                }
                presets_menu(ui, state, prefs);
                if widgets::button(ui, "save as preset…", Kind::Quiet)
                    .on_hover_text(
                        "Name the current values — everything that differs from defaults goes in",
                    )
                    .clicked()
                {
                    state.saving = Some(String::new());
                }
            }
        });
    });
    if state.info_open {
        info_card(ui, pal);
    }
    if let Some(note) = &state.preset_note {
        ui.label(RichText::new(note).size(12.0).color(pal.signal));
    }
    if state.saving.is_some() {
        save_card(ui, pal, state, &knobs, prefs);
    }
    if let Some(sel) = state.preset_open {
        preset_card(
            ui,
            pal,
            state,
            control.as_ref(),
            config_file,
            prefs,
            &knobs,
            sel,
        );
    }

    // The file moved on disk — say which knobs drifted, and offer the
    // restart that re-reads it.
    if let Some(diffs) = dirty {
        ui.add_space(8.0);
        let mut action = None;
        let control = &control;
        ui.horizontal(|ui| {
            if diffs.is_empty() {
                ui.label(
                    RichText::new(
                        "the config file changed but doesn't parse — the node keeps its loaded values",
                    )
                    .size(12.0)
                    .color(pal.alert),
                );
            } else {
                ui.label(
                    RichText::new(format!(
                        "config file changed — {} knob{} differ{}: {}",
                        diffs.len(),
                        if diffs.len() == 1 { "" } else { "s" },
                        if diffs.len() == 1 { "s" } else { "" },
                        diffs.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
                            + if diffs.len() > 4 { ", …" } else { "" },
                    ))
                    .size(12.0)
                    .color(pal.signal),
                );
                // Live knobs in the diff can land without a restart —
                // send the file's value down the channel.
                let live_diffs: Vec<&str> = diffs
                    .iter()
                    .filter(|p| {
                        knobs
                            .iter()
                            .any(|k| k.path == *p && k.edit == EditKind::Live)
                    })
                    .map(|s| s.as_str())
                    .collect();
                let restart_diffs = diffs.len() - live_diffs.len();
                if !live_diffs.is_empty()
                    && control.is_some()
                    && let (Some(tx), Some(file)) = (control.as_ref(), config_file)
                    && let Ok(v) = avila_node::config::load_config(Some(file))
                    && widgets::button(ui, "apply live now", Kind::Quiet)
                        .on_hover_text(
                            "The changed live knobs send to the running node — no restart.",
                        )
                        .clicked()
                {
                    for k in avila_node::config::describe_config(v.get()) {
                        if live_diffs.contains(&k.path) {
                            let _ = tx.send(ControlMsg::Set {
                                path: k.path.to_string(),
                                value: k.value.clone(),
                            });
                            state.pending.insert(k.path.to_string(), k.value.clone());
                        }
                    }
                }
                if restart_diffs > 0
                    && widgets::button(
                        ui,
                        if control.is_some() {
                            "restart node"
                        } else {
                            "start node"
                        },
                        Kind::Primary,
                    )
                    .on_hover_text("Stop and start again — the file is re-read")
                    .clicked()
                {
                    action = Some(Action::Restart);
                }
            }
        });
        ui.add_space(2.0);
        if action.is_some() {
            return action;
        }
    }
    ui.add_space(10.0);

    let filter = state.filter.trim().to_lowercase();
    let mut group = String::new();
    let mut first = true;
    for k in &knobs {
        if !filter.is_empty()
            && !k.path.to_lowercase().contains(&filter)
            && !k.doc.to_lowercase().contains(&filter)
        {
            continue;
        }
        // Section the rows by their leading segment ("relay.tx.…" → relay).
        let head = k.path.split('.').next().unwrap_or("");
        let title = match k.path.split('.').take(2).collect::<Vec<_>>().as_slice() {
            ["relay", sub] => format!("relay · {sub}"),
            _ => head.to_string(),
        };
        if title != group {
            group = title.clone();
            ui.add_space(if first { 0.0 } else { 14.0 });
            first = false;
            ui.label(
                RichText::new(group.to_uppercase())
                    .size(11.0)
                    .color(pal.muted)
                    .strong(),
            );
            ui.add_space(4.0);
        }
        row(ui, pal, state, k, control.as_ref(), config_file, dirty);
    }
    None
}

fn row(
    ui: &mut Ui,
    pal: crate::theme::Palette,
    state: &mut ConfigPage,
    k: &avila_node::config::KnobDescription,
    control: Option<&Sender<ControlMsg>>,
    config_file: Option<&std::path::Path>,
    dirty: Option<&[String]>,
) {
    // Live knobs need the channel to apply now; without it (stopped),
    // or for restart knobs, the overlay still takes the edit.
    let editable = match k.edit {
        EditKind::Live => control.is_some() || config_file.is_some(),
        EditKind::Restart => config_file.is_some(),
    };
    let value = effective(state, k.path, &k.value);
    let changed = state.overrides.contains_key(k.path);
    let staged = state.staged.contains_key(k.path);
    let pending = state.pending.contains_key(k.path);
    let rejected = state.rejected.get(k.path).cloned();

    ui.horizontal(|ui| {
        // Path + doc take the left half; the control and its marks
        // take the right.
        ui.vertical(|ui| {
            ui.set_min_width(300.0);
            ui.set_max_width(340.0);
            ui.label(
                RichText::new(k.path)
                    .size(12.5)
                    .font(mono(12.5))
                    .color(pal.text),
            );
            ui.label(RichText::new(k.doc).size(11.0).color(pal.muted));
        });
        ui.add_space(12.0);
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.set_min_width(300.0);
                if let Some(v) = control_cell(ui, pal, state, k, &value, editable) {
                    // Every in-app edit writes the overlay — the file
                    // survives untouched and the value persists across
                    // restarts. A write failure only refuses a staged
                    // restart knob; a live knob still applies, marked
                    // as not persisted.
                    match (k.edit, control.is_some()) {
                        // Live + running: persist and apply now.
                        (EditKind::Live, true) => {
                            if let Some(file) = config_file
                                && let Err(e) = avila_node::config::write_overlay_knob(
                                    file,
                                    k.path,
                                    toml_of(&v),
                                )
                            {
                                state
                                    .rejected
                                    .insert(k.path.to_string(), format!("not persisted: {e}"));
                            }
                            let _ = control.as_ref().map(|tx| {
                                tx.send(ControlMsg::Set {
                                    path: k.path.to_string(),
                                    value: v.clone(),
                                })
                            });
                            state.pending.insert(k.path.to_string(), v);
                        }
                        // Live-but-stopped or restart — the overlay
                        // carries it to the next start.
                        _ => {
                            if let Some(file) = config_file {
                                stage(file, state, k.path, v);
                            }
                        }
                    }
                }
                if pending {
                    ui.label(RichText::new("applying…").size(11.5).color(pal.muted));
                } else if changed {
                    ui.label(
                        RichText::new("live")
                            .size(11.5)
                            .color(pal.signal_text)
                            .strong(),
                    )
                    .on_hover_text("Applied to the running node — and persisted in the overlay");
                } else if staged {
                    ui.label(
                        RichText::new("staged")
                            .size(11.5)
                            .color(pal.signal_text)
                            .strong(),
                    )
                    .on_hover_text("In the overlay — applies on the next start");
                } else if k.edit == EditKind::Live {
                    ui.label(RichText::new("live").size(11.5).color(pal.muted))
                        .on_hover_text("Applies to the running node without a restart");
                } else if let Some(file) = config_file {
                    let r = ui
                        .add(
                            egui::Label::new(
                                RichText::new("needs restart →")
                                    .size(11.5)
                                    .color(pal.muted)
                                    .underline(),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(format!(
                            "Applies at startup — click to open {} in your editor",
                            file.display()
                        ));
                    if r.clicked() {
                        // The file opens in whatever the desktop hands
                        // .toml to; the knob's doc line names what to
                        // find once it lands.
                        let _ = std::process::Command::new("xdg-open").arg(file).spawn();
                    }
                } else {
                    ui.label(RichText::new("needs restart").size(11.5).color(pal.muted))
                        .on_hover_text("Applies at startup — no config file was loaded");
                }
            });
            if dirty.is_some_and(|d| d.iter().any(|p| p == k.path)) {
                let text = if staged {
                    "staged — applies on restart"
                } else {
                    "file differs — restart to apply"
                };
                ui.label(RichText::new(text).size(11.0).color(pal.signal));
            }
            if let Some(reason) = rejected {
                ui.label(
                    RichText::new(format!("rejected: {reason}"))
                        .size(11.5)
                        .color(pal.alert),
                );
            }
        });
    });
    ui.add_space(2.0);
}

/// The right-hand cell — a checkbox, a dropdown, or a text draft,
/// depending on the knob's value type. Returns the committed value;
/// the caller routes it (channel + overlay for live, overlay for
/// restart).
fn control_cell(
    ui: &mut Ui,
    pal: crate::theme::Palette,
    state: &mut ConfigPage,
    k: &avila_node::config::KnobDescription,
    value: &serde_json::Value,
    editable: bool,
) -> Option<serde_json::Value> {
    let choices = CHOICES.iter().find(|(p, _)| *p == k.path).map(|(_, c)| *c);
    if !editable {
        ui.label(
            RichText::new(
                if k.path == "relay.block.announce" && value.as_str() == Some("") {
                    "auto".to_string()
                } else {
                    render_value(value)
                },
            )
            .size(12.5)
            .font(mono(12.5))
            .color(if k.edit == EditKind::Live {
                pal.text
            } else {
                pal.muted
            }),
        );
        return None;
    }
    if let serde_json::Value::Bool(b) = value {
        let mut on = *b;
        if ui.checkbox(&mut on, "").changed() {
            return Some(serde_json::Value::Bool(on));
        }
        return None;
    }
    if let Some(choices) = choices {
        let shown = if k.path == "relay.block.announce" && value.as_str() == Some("") {
            "auto".to_string()
        } else {
            value.as_str().unwrap_or_default().to_string()
        };
        let mut picked = shown.clone();
        egui::ComboBox::from_id_salt(format!("cfg-{}", k.path))
            .selected_text(RichText::new(&picked).font(mono(12.5)).size(12.5))
            .width(130.0)
            .show_ui(ui, |ui| {
                for c in choices {
                    ui.selectable_value(&mut picked, (*c).to_string(), *c);
                }
            });
        if picked != shown {
            let v = if picked == "auto" {
                String::new()
            } else {
                picked
            };
            return Some(serde_json::Value::String(v));
        }
        return None;
    }
    // Numbers, strings, lists — a draft field; Enter or Apply commits.
    let (draft_text, committed) = {
        let draft = state
            .drafts
            .entry(k.path.to_string())
            .or_insert_with(|| render_value(value));
        let resp = ui.add(
            TextEdit::singleline(draft)
                .desired_width(160.0)
                .font(mono(12.5)),
        );
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        (draft.clone(), enter)
    };
    let dirty = draft_text.trim() != render_value(value);
    let committed = dirty && committed;
    if dirty && (committed || widgets::button(ui, "apply", Kind::Quiet).clicked()) {
        match draft_value(k.path, &draft_text, value) {
            Some(v) => {
                state.drafts.remove(k.path);
                return Some(v);
            }
            None => {
                state
                    .rejected
                    .insert(k.path.to_string(), format!("can't parse {draft_text:?}"));
            }
        }
    }
    None
}
