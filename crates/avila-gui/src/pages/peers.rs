//! Who the node is talking to, and how: the constellation for the shape
//! of it, a panel for one peer's particulars (its BIP324 session
//! fingerprint, what its traffic is for), and the table for the record.

use super::{Action, Scene, start_offer};
use crate::constellation::{self, Constellation, Outcome, netgroup};
use crate::fingerprint::{self, HEIGHT, WIDTH};
use crate::model::{PeerView, Purpose, bytes, services, span, thousands};
use crate::session::agent_name;
use crate::theme::{self, Palette, body, font, mono};
use crate::widgets::{self, Col, Kind, fit, put};
use eframe::egui::{
    self, Align, Color32, Layout, Rect, RichText, Sense, Stroke, StrokeKind, Ui, vec2,
};
use std::collections::HashMap;

/// The side panel's width when there's room for it beside the sky.
const SIDE: f32 = 372.0;

pub fn show(
    ui: &mut Ui,
    s: &Scene,
    selected: &mut Option<u64>,
    sky: &mut Constellation,
) -> Option<Action> {
    let Some(v) = &s.session.view else {
        widgets::empty(
            ui,
            "No peers",
            "The node isn’t running. Start it to connect to the network.",
        );
        return start_offer(ui, s);
    };
    let mut peers: Vec<&PeerView> = v.peers.iter().collect();
    peers.sort_by_key(|p| {
        (
            !p.established,
            p.inbound,
            std::cmp::Reverse(p.connected_secs),
        )
    });
    if peers.is_empty() {
        let body = if s.network == avila_core::Network::Regtest {
            "Regtest has no DNS seeds. Add a peer’s address under Settings, then restart the node."
        } else {
            "The node is asking DNS seeds for addresses; peers usually answer within seconds."
        };
        widgets::empty(ui, "Looking for peers", body);
        return None;
    }
    if selected.is_some_and(|id| !peers.iter().any(|p| p.id == id)) {
        *selected = None;
    }
    let deliverer = peers
        .iter()
        .find(|p| p.last_block == Some(v.connected))
        .map(|p| p.id);
    let pulse = s.pulse().map(|f| (deliverer, f));
    let now = s.session.now();
    let mut outcome = Outcome::default();
    if ui.available_width() >= 900.0 {
        ui.horizontal_top(|ui| {
            let w = ui.available_width() - SIDE - 32.0;
            ui.allocate_ui_with_layout(vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(w);
                outcome = sky.show(ui, &peers, *selected, pulse, now, 380.0, s.swirl);
            });
            ui.add_space(32.0);
            ui.allocate_ui_with_layout(vec2(SIDE, 0.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(SIDE);
                panel(ui, s, &peers, selected);
            });
        });
    } else {
        outcome = sky.show(ui, &peers, *selected, pulse, now, 320.0, s.swirl);
        ui.add_space(12.0);
        panel(ui, s, &peers, selected);
    }
    if let Some(id) = outcome.clicked {
        *selected = (*selected != Some(id)).then_some(id);
    } else if outcome.clicked_empty {
        *selected = None;
    }
    ui.add_space(8.0);
    constellation::legend(ui);
    shared_groups(ui, s, &peers);
    ui.add_space(22.0);
    table(ui, s, &peers, selected);
    None
}

fn panel(ui: &mut Ui, s: &Scene, peers: &[&PeerView], selected: &mut Option<u64>) {
    match selected.and_then(|id| peers.iter().find(|p| p.id == id)) {
        Some(p) => {
            if detail(ui, s, p) {
                *selected = None;
            }
        }
        None => overview(ui, s, peers),
    }
}

/// The whole set, in numbers.
fn overview(ui: &mut Ui, s: &Scene, peers: &[&PeerView]) {
    let est: Vec<&&PeerView> = peers.iter().filter(|p| p.established).collect();
    let n = est.len();
    let v2 = est.iter().filter(|p| p.v2).count();
    let recon = est.iter().filter(|p| p.recon).count();
    let inbound = est.iter().filter(|p| p.inbound).count();
    let recv: u64 = est.iter().map(|p| p.bytes_recv).sum();
    let sent: u64 = est.iter().map(|p| p.bytes_sent).sum();
    let groups = {
        let mut g: Vec<String> = est.iter().map(|p| netgroup(p)).collect();
        g.sort();
        g.dedup();
        g.len()
    };
    let mut pings: Vec<f64> = est.iter().filter_map(|p| p.ping_ms).collect();
    pings.sort_by(f64::total_cmp);
    let ping = pings
        .get(pings.len() / 2)
        .map_or("—".to_owned(), |ms| format!("{ms:.0} ms"));
    ui.add_space(8.0);
    widgets::figure(
        ui,
        &n.to_string(),
        if n == 1 { "peer" } else { "peers" },
        46.0,
    );
    ui.add_space(10.0);
    facts(ui, "peer-facts", |ui| {
        for (k, v) in [
            ("Encrypted", format!("{v2} of {n}")),
            ("Reconciling with Erlay", recon.to_string()),
            ("Dialed us", inbound.to_string()),
            ("Network groups", groups.to_string()),
            ("Median ping", ping),
            ("Received", bytes(recv)),
            ("Sent", bytes(sent)),
        ] {
            key(ui, s, k);
            ui.label(RichText::new(v).font(mono(13.0)).color(s.pal.text));
            ui.end_row();
        }
    });
    ui.add_space(14.0);
    ui.label(
        RichText::new("Select a peer to see its session fingerprint and what its traffic is for.")
            .size(13.0)
            .color(s.pal.faint),
    );
}

/// One peer up close. Returns whether it was closed.
fn detail(ui: &mut Ui, s: &Scene, p: &PeerView) -> bool {
    let pal = s.pal;
    let mut closed = false;
    ui.horizontal(|ui| {
        let name = p.addr.clone().unwrap_or_else(|| format!("peer {}", p.id));
        ui.add(egui::Label::new(RichText::new(name).font(mono(15.0)).color(pal.text)).truncate());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            closed = widgets::button(ui, "Close", Kind::Quiet).clicked();
        });
    });
    let who = p
        .agent
        .as_deref()
        .map_or("unknown software".into(), agent_name);
    let direction = if p.inbound { "dialed us" } else { "we dialed" };
    ui.label(
        RichText::new(format!(
            "{who} · {direction} · connected {}",
            span(p.connected_secs)
        ))
        .size(13.0)
        .color(pal.muted),
    );

    heading(ui, s, "Transport");
    match &p.session_id {
        Some(id) => {
            ui.label(
                RichText::new("Encrypted with BIP324")
                    .size(14.0)
                    .color(pal.text),
            );
            ui.add_space(4.0);
            ui.horizontal_top(|ui| {
                randomart(ui, id, &pal);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    for pair in fingerprint::hex_groups(id).chunks(2) {
                        ui.label(
                            RichText::new(pair.join(" "))
                                .font(mono(11.5))
                                .color(pal.muted),
                        );
                    }
                    ui.add_space(4.0);
                    if widgets::button(ui, "Copy id", Kind::Quiet).clicked() {
                        ui.ctx().copy_text(fingerprint::hex_groups(id).concat());
                    }
                });
            });
            ui.label(
                RichText::new(
                    "Both ends derive this session id. If the other side’s matches — its getpeerinfo shows the same hex — nobody is in the middle.",
                )
                .size(12.5)
                .color(pal.faint),
            );
        }
        None => {
            ui.label(
                RichText::new("Plaintext (v1). Anyone on the path can read this connection.")
                    .size(14.0)
                    .color(pal.muted),
            );
        }
    }

    heading(ui, s, "Relay");
    let relay = if p.recon {
        "Reconciles transactions with Erlay (BIP330): sets are compared instead of announcing each one."
    } else {
        "Announces transactions one by one (no Erlay on this link)."
    };
    ui.label(RichText::new(relay).size(13.5).color(pal.text));
    let offers = services(p.services);
    if !offers.is_empty() {
        ui.add_space(2.0);
        ui.label(
            RichText::new(format!("Offers: {}", offers.join(", ")))
                .size(13.0)
                .color(pal.muted),
        );
    }

    heading(ui, s, "Traffic");
    traffic(ui, s, p);

    heading(ui, s, "Record");
    facts(ui, "peer-record", |ui| {
        let ping = match (p.ping_ms, p.ping_min_ms) {
            (Some(ms), Some(min)) => format!("{ms:.0} ms (best {min:.0} ms)"),
            (Some(ms), None) => format!("{ms:.0} ms"),
            _ => "—".into(),
        };
        let delivered = match p.last_block {
            Some(h) => format!("{} · latest {}", p.blocks_served, thousands(h.into())),
            None => p.blocks_served.to_string(),
        };
        let height = p
            .their_height
            .filter(|h| *h > 0)
            .map_or("—".into(), |h| thousands(h as u64));
        for (k, v) in [
            ("Ping", ping),
            ("Blocks delivered", delivered),
            ("Height at connect", height),
        ] {
            key(ui, s, k);
            ui.label(RichText::new(v).font(mono(12.5)).color(pal.text));
            ui.end_row();
        }
    });
    closed
}

fn heading(ui: &mut Ui, s: &Scene, text: &str) {
    ui.add_space(14.0);
    ui.label(
        RichText::new(text)
            .font(font(theme::MEDIUM, 12.5))
            .color(s.pal.muted),
    );
    ui.add_space(2.0);
}

fn facts(ui: &mut Ui, id: &str, rows: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([20.0, 7.0])
        .min_col_width(120.0)
        .show(ui, rows);
}

fn key(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(RichText::new(text).size(13.0).color(s.pal.muted));
}

/// The session id as a picture: where the bishop walked, darker where
/// it walked more; a ring where it started, a dot where it stopped.
fn randomart(ui: &mut Ui, id: &[u8; 32], pal: &Palette) {
    let art = fingerprint::randomart(id);
    let cell = 8.0;
    let pad = 7.0;
    let size = vec2(
        cell * WIDTH as f32 + pad * 2.0,
        cell * HEIGHT as f32 + pad * 2.0,
    );
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let p = ui.painter();
    p.rect(
        rect,
        6,
        pal.well,
        Stroke::new(1.0, pal.hairline),
        StrokeKind::Inside,
    );
    let origin = rect.min + vec2(pad, pad);
    for (y, row) in art.visits.iter().enumerate() {
        for (x, n) in row.iter().enumerate() {
            if *n == 0 {
                continue;
            }
            let a = (0.2 + 0.17 * f32::from((*n).min(5))).min(1.0);
            let r = Rect::from_min_size(
                origin + vec2(x as f32 * cell, y as f32 * cell),
                vec2(cell - 1.5, cell - 1.5),
            );
            p.rect_filled(r, 1.5, pal.text.gamma_multiply(a));
        }
    }
    let at = |(x, y): (usize, usize)| {
        origin
            + vec2(
                (x as f32 + 0.5) * cell - 0.75,
                (y as f32 + 0.5) * cell - 0.75,
            )
    };
    p.circle_stroke(at(art.start), 3.4, Stroke::new(1.4, pal.text));
    p.circle_filled(at(art.end), 2.4, pal.text);
    p.circle_stroke(at(art.end), 4.4, Stroke::new(1.0, pal.text));
}

/// Ink from dark to light, one shade per purpose.
fn shade(pal: &Palette, purpose: Purpose) -> Color32 {
    const ALPHA: [f32; Purpose::COUNT] = [1.0, 0.74, 0.55, 0.4, 0.3, 0.21, 0.13];
    pal.text.gamma_multiply(ALPHA[purpose as usize])
}

fn traffic(ui: &mut Ui, s: &Scene, p: &PeerView) {
    let pal = s.pal;
    let w = ui.available_width().min(SIDE);
    for (label, parts, total) in [
        ("Received", p.traffic.recv, p.traffic.total_recv()),
        ("Sent", p.traffic.sent, p.traffic.total_sent()),
    ] {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).size(12.5).color(pal.muted));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(bytes(total)).font(mono(12.0)).color(pal.text));
            });
        });
        let (rect, _) = ui.allocate_exact_size(vec2(w, 9.0), Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 3, pal.well);
        if total > 0 {
            let mut x = rect.left();
            for purpose in Purpose::ALL {
                let n = parts[purpose as usize];
                if n == 0 {
                    continue;
                }
                let seg = rect.width() * (n as f64 / total as f64) as f32;
                let r = Rect::from_x_y_ranges(x..=(x + seg).min(rect.right()), rect.y_range());
                painter.rect_filled(r, 0, shade(&pal, purpose));
                x += seg;
            }
        }
        ui.add_space(4.0);
    }
    // The key, with both directions per purpose.
    egui::Grid::new("traffic-key")
        .num_columns(3)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for purpose in Purpose::ALL {
                let (r, t) = (
                    p.traffic.recv[purpose as usize],
                    p.traffic.sent[purpose as usize],
                );
                if r == 0 && t == 0 {
                    continue;
                }
                ui.horizontal(|ui| {
                    let (sw, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                    ui.painter().rect_filled(sw, 2, shade(&pal, purpose));
                    ui.label(RichText::new(purpose.label()).size(12.5).color(pal.text));
                });
                ui.label(
                    RichText::new(format!("↓ {}", bytes(r)))
                        .font(mono(11.5))
                        .color(pal.muted),
                );
                ui.label(
                    RichText::new(format!("↑ {}", bytes(t)))
                        .font(mono(11.5))
                        .color(pal.muted),
                );
                ui.end_row();
            }
        });
}

/// Outbound peers sharing a network group are the one thing here worth
/// a warning: a single operator is likelier to hold them all.
fn shared_groups(ui: &mut Ui, s: &Scene, peers: &[&PeerView]) {
    let mut outbound: HashMap<String, usize> = HashMap::new();
    for p in peers.iter().filter(|p| p.established && !p.inbound) {
        *outbound.entry(netgroup(p)).or_default() += 1;
    }
    let mut shared: Vec<(String, usize)> = outbound.into_iter().filter(|(_, n)| *n >= 2).collect();
    shared.sort();
    for (group, n) in shared {
        ui.label(
            RichText::new(format!(
                "{n} peers we dialed share {group}. Outbound peers in one network group are easier for a single operator to control; Core spreads them across groups."
            ))
            .size(13.0)
            .color(s.pal.alert),
        );
    }
}

/// Columns in the order they give way when the window narrows.
fn columns(width: f32) -> Vec<Col> {
    let all: [(Col, u8); 9] = [
        (
            Col {
                title: "Peer",
                width: None,
                right: false,
            },
            0,
        ),
        (
            Col {
                title: "Transport",
                width: Some(104.0),
                right: false,
            },
            1,
        ),
        (
            Col {
                title: "Erlay",
                width: Some(96.0),
                right: false,
            },
            4,
        ),
        (
            Col {
                title: "Direction",
                width: Some(96.0),
                right: false,
            },
            5,
        ),
        (
            Col {
                title: "Height at connect",
                width: Some(128.0),
                right: true,
            },
            6,
        ),
        (
            Col {
                title: "Ping",
                width: Some(72.0),
                right: true,
            },
            2,
        ),
        (
            Col {
                title: "Blocks",
                width: Some(68.0),
                right: true,
            },
            7,
        ),
        (
            Col {
                title: "Traffic",
                width: Some(108.0),
                right: true,
            },
            3,
        ),
        (
            Col {
                title: "Connected",
                width: Some(96.0),
                right: true,
            },
            2,
        ),
    ];
    let mut keep: Vec<(Col, u8)> = all.into_iter().collect();
    loop {
        let fixed: f32 = keep.iter().filter_map(|(c, _)| c.width).sum();
        if fixed + 220.0 <= width {
            break;
        }
        let Some(drop) = keep
            .iter()
            .enumerate()
            .filter(|(_, (_, rank))| *rank > 0)
            .max_by_key(|(_, (_, rank))| *rank)
            .map(|(i, _)| i)
        else {
            break;
        };
        keep.remove(drop);
    }
    keep.into_iter().map(|(c, _)| c).collect()
}

fn table(ui: &mut Ui, s: &Scene, peers: &[&PeerView], selected: &mut Option<u64>) {
    let pal = s.pal;
    let cols = columns(ui.available_width());
    let ranges = widgets::table_header(ui, &cols);
    for p in peers {
        let (rect, resp) = widgets::table_row(ui, 50.0, *selected == Some(p.id));
        if resp.clicked() {
            *selected = (*selected != Some(p.id)).then_some(p.id);
        }
        let painter = ui.painter();
        let (top, mid, low) = (rect.top() + 16.0, rect.center().y, rect.top() + 34.0);
        let dim = |c: Color32| {
            if p.established {
                c
            } else {
                c.gamma_multiply(0.55)
            }
        };
        for (col, cell) in cols.iter().zip(&ranges) {
            let w = cell.span();
            let one = |text: String, font, color| {
                put(
                    painter,
                    *cell,
                    mid,
                    fit(painter, text, font, dim(color), w),
                    col.right,
                );
            };
            let two = |a: String, fa, ca, b: String, fb, cb| {
                put(
                    painter,
                    *cell,
                    top,
                    fit(painter, a, fa, dim(ca), w),
                    col.right,
                );
                put(
                    painter,
                    *cell,
                    low,
                    fit(painter, b, fb, dim(cb), w),
                    col.right,
                );
            };
            match col.title {
                "Peer" => two(
                    p.addr.clone().unwrap_or_else(|| format!("peer {}", p.id)),
                    mono(12.5),
                    pal.text,
                    p.agent
                        .as_deref()
                        .map_or("unknown software".into(), agent_name),
                    body(12.0),
                    pal.muted,
                ),
                "Transport" if !p.established => one("Handshaking".into(), body(13.0), pal.muted),
                "Transport" if p.v2 => two(
                    "Encrypted".into(),
                    body(13.0),
                    pal.text,
                    "v2 · BIP324".into(),
                    body(11.5),
                    pal.faint,
                ),
                "Transport" => two(
                    "Plaintext".into(),
                    body(13.0),
                    pal.muted,
                    "v1".into(),
                    body(11.5),
                    pal.faint,
                ),
                "Erlay" if p.recon => two(
                    "Reconciling".into(),
                    body(13.0),
                    pal.text,
                    "BIP330".into(),
                    body(11.5),
                    pal.faint,
                ),
                "Erlay" => one("—".into(), body(13.0), pal.faint),
                "Direction" => one(
                    if p.inbound {
                        "They dialed"
                    } else {
                        "We dialed"
                    }
                    .into(),
                    body(13.0),
                    pal.text,
                ),
                "Height at connect" => one(
                    p.their_height
                        .filter(|h| *h > 0)
                        .map_or("—".into(), |h| thousands(h as u64)),
                    mono(12.5),
                    pal.text,
                ),
                "Ping" => one(
                    p.ping_ms.map_or("—".into(), |ms| format!("{ms:.0} ms")),
                    mono(12.5),
                    pal.text,
                ),
                "Blocks" => one(thousands(p.blocks_served as u64), mono(12.5), pal.text),
                "Traffic" => two(
                    format!("↓ {}", bytes(p.bytes_recv)),
                    mono(12.0),
                    pal.text,
                    format!("↑ {}", bytes(p.bytes_sent)),
                    mono(12.0),
                    pal.muted,
                ),
                "Connected" => one(span(p.connected_secs), body(13.0), pal.text),
                _ => {}
            }
        }
    }
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Height at connect is what each peer reported when it joined; peers don’t re-announce it.",
        )
        .size(12.5)
        .color(pal.faint),
    );
}
