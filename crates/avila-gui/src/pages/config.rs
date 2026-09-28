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
    /// The path filter box.
    pub filter: String,
    /// What the last preset application did ("applied 5 live knobs;
    /// TOML for the rest is on the clipboard").
    preset_note: Option<String>,
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
}

/// The knob's effective value this session — the override the journal
/// confirmed, else what the config file said. Owned so the map stays
/// free for the row's edits.
fn effective(state: &ConfigPage, path: &str, file: &serde_json::Value) -> serde_json::Value {
    state
        .overrides
        .get(path)
        .cloned()
        .unwrap_or_else(|| file.clone())
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
    blurb: &'static str,
    /// (path, JSON literal) — parsed at apply time.
    live: &'static [(&'static str, &'static str)],
    /// (path, TOML literal) — emitted under `[section]` headers.
    restart: &'static [(&'static str, &'static str)],
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "Quiet node",
        blurb: "Blocks in, nothing out: no tx announcements, stem off, \
                blocks served at the tip only — still watches what it refuses.",
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
        name: "Lean laptop",
        blurb: "Small mempool, two-hour memory, no extrapool — for a box \
                that syncs and isn't a server.",
        live: &[
            ("mempool.max_mb", "64"),
            ("mempool.expiry_secs", "7200"),
            ("extrapool.observe", "false"),
        ],
        restart: &[("storage.prune_mb", "2000"), ("storage.dbcache_mb", "256")],
    },
    Preset {
        name: "Public server",
        blurb: "Serve everything: full block serving, compact blocks, \
                filters and indexes to match.",
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

/// The restart knobs' TOML: `a.b.c = v` grouped under `[a.b]`.
fn preset_toml(restart: &[(&'static str, &'static str)]) -> String {
    let mut out = String::new();
    let mut last = "";
    for (path, val) in restart {
        let (sec, key) = match path.rsplit_once('.') {
            Some(s) => s,
            None => continue,
        };
        if sec != last {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("[{sec}]\n"));
            last = sec;
        }
        out.push_str(&format!("{key} = {val}\n"));
    }
    out
}

fn presets_menu(ui: &mut Ui, state: &mut ConfigPage, control: Option<&Sender<ControlMsg>>) {
    let pal = crate::theme::Palette::of(ui.ctx());
    egui::ComboBox::from_id_salt("config-presets")
        .selected_text(RichText::new("apply a preset…").size(12.0).color(pal.muted))
        .width(150.0)
        .show_ui(ui, |ui| {
            for p in PRESETS {
                if ui
                    .selectable_label(false, p.name)
                    .on_hover_text(p.blurb)
                    .clicked()
                {
                    let mut applied = 0;
                    if let Some(tx) = control {
                        for (path, raw) in p.live {
                            let value =
                                serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
                            if tx
                                .send(ControlMsg::Set {
                                    path: (*path).to_string(),
                                    value: value.clone(),
                                })
                                .is_ok()
                            {
                                state.pending.insert((*path).to_string(), value);
                                applied += 1;
                            }
                        }
                    }
                    let mut note = format!(
                        "{}: {} live knob{} sent",
                        p.name,
                        applied,
                        if applied == 1 { "" } else { "s" },
                    );
                    if !p.restart.is_empty() {
                        ui.ctx().copy_text(preset_toml(p.restart));
                        note.push_str(" — the restart knobs' TOML is on the clipboard");
                    }
                    state.preset_note = Some(note);
                    ui.close();
                }
            }
        });
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

pub fn show(
    ui: &mut Ui,
    s: &Scene,
    state: &mut ConfigPage,
    node: &Node,
    control: Option<Sender<ControlMsg>>,
    config_file: Option<&std::path::Path>,
    // Knob paths whose on-disk value differs from the running node's
    // (`Some(vec![])` = the file changed but no longer parses).
    dirty: Option<&[String]>,
) -> Option<Action> {
    let pal = s.pal;
    let knobs = describe_config(node.config().get());
    widgets::section(
        ui,
        "Node policy",
        Some(
            "Every knob the config file sets. Bright marks edit the running node — dim ones \
             need a restart. The file is never written; restart reverts.",
        ),
    );
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Filter").size(13.0).color(pal.muted));
        ui.add(TextEdit::singleline(&mut state.filter).desired_width(200.0));
        if control.is_none() {
            ui.label(
                RichText::new("start the node to edit — live marks apply while it runs")
                    .size(12.0)
                    .color(pal.muted),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(file) = config_file {
                if ui
                    .link(
                        RichText::new(format!("edit {}", file.display()))
                            .size(12.0)
                            .color(pal.muted),
                    )
                    .on_hover_text("Open the config file in your editor")
                    .clicked()
                {
                    let _ = std::process::Command::new("xdg-open").arg(file).spawn();
                }
            }
            if control.is_some() {
                // Undo every live override by sending the knob's
                // default back through the channel — the journal gets
                // the same config_changed receipt as any other edit.
                if !state.overrides.is_empty()
                    && widgets::button(ui, "reset live edits", Kind::Quiet)
                        .on_hover_text(
                            "Send every live knob its default — the file is untouched; \
                             restart-only knobs aren't reachable here.",
                        )
                        .clicked()
                {
                    for k in &knobs {
                        if state.overrides.contains_key(k.path) && k.edit == EditKind::Live {
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
                    state.drafts.clear();
                    state.rejected.clear();
                }
                presets_menu(ui, state, control.as_ref());
            }
        });
    });
    if let Some(note) = &state.preset_note {
        ui.label(RichText::new(note).size(12.0).color(pal.signal));
    }

    // The file moved on disk — say which knobs drifted, and offer the
    // restart that re-reads it.
    if let Some(diffs) = dirty {
        ui.add_space(8.0);
        let mut action = None;
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
                if widgets::button(ui, "restart node", Kind::Primary).clicked() {
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
    let live = k.edit == EditKind::Live && control.is_some();
    let value = effective(state, k.path, &k.value);
    let changed = state.overrides.contains_key(k.path);
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
                control_cell(ui, pal, state, k, &value, live, control);
                if pending {
                    ui.label(RichText::new("applying…").size(11.5).color(pal.muted));
                } else if changed {
                    ui.label(
                        RichText::new("live")
                            .size(11.5)
                            .color(pal.signal_text)
                            .strong(),
                    )
                    .on_hover_text("Applied to the running node — reverts on restart");
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
                            "Applies at startup — click to edit {}",
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
                ui.label(
                    RichText::new("file differs — restart to apply")
                        .size(11.0)
                        .color(pal.signal),
                );
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
/// depending on the knob's value type.
fn control_cell(
    ui: &mut Ui,
    pal: crate::theme::Palette,
    state: &mut ConfigPage,
    k: &avila_node::config::KnobDescription,
    value: &serde_json::Value,
    live: bool,
    control: Option<&Sender<ControlMsg>>,
) {
    let send = |value: serde_json::Value| {
        if let Some(tx) = control {
            let _ = tx.send(ControlMsg::Set {
                path: k.path.to_string(),
                value: value.clone(),
            });
        }
    };
    let choices = CHOICES.iter().find(|(p, _)| *p == k.path).map(|(_, c)| *c);
    if !live {
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
        return;
    }
    if let serde_json::Value::Bool(b) = value {
        let mut on = *b;
        if ui.checkbox(&mut on, "").changed() {
            send(serde_json::Value::Bool(on));
            state
                .pending
                .insert(k.path.to_string(), serde_json::Value::Bool(on));
        }
        return;
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
            send(serde_json::Value::String(v.clone()));
            state
                .pending
                .insert(k.path.to_string(), serde_json::Value::String(v));
        }
        return;
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
                send(v.clone());
                state.pending.insert(k.path.to_string(), v);
                state.drafts.remove(k.path);
            }
            None => {
                state
                    .rejected
                    .insert(k.path.to_string(), format!("can't parse {draft_text:?}"));
            }
        }
    }
}
