//! Who the node is talking to, and how: encrypted (BIP324) or not,
//! reconciling transactions with Erlay (BIP330) or not.

use super::{Action, Scene, start_offer};
use crate::model::{PeerView, bytes, span, thousands};
use crate::session::agent_name;
use crate::theme::{self, body, font, mono};
use crate::widgets::{self, Col, fit, put};
use eframe::egui::{Color32, RichText, Ui, vec2};

pub fn show(ui: &mut Ui, s: &Scene) -> Option<Action> {
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
    summary(ui, s, &peers);
    ui.add_space(22.0);
    table(ui, s, &peers);
    None
}

fn summary(ui: &mut Ui, s: &Scene, peers: &[&PeerView]) {
    let est: Vec<&&PeerView> = peers.iter().filter(|p| p.established).collect();
    let n = est.len();
    let v2 = est.iter().filter(|p| p.v2).count();
    let recon = est.iter().filter(|p| p.recon).count();
    let inbound = est.iter().filter(|p| p.inbound).count();
    let recv: u64 = est.iter().map(|p| p.bytes_recv).sum();
    let sent: u64 = est.iter().map(|p| p.bytes_sent).sum();
    let mut pings: Vec<f64> = est.iter().filter_map(|p| p.ping_ms).collect();
    pings.sort_by(f64::total_cmp);
    let ping = pings
        .get(pings.len() / 2)
        .map_or("—".to_owned(), |ms| format!("{ms:.0} ms"));
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 40.0;
        stat(ui, s, "Connected", &n.to_string(), true);
        stat(ui, s, "Encrypted", &format!("{v2} of {n}"), false);
        stat(ui, s, "Reconciling with Erlay", &recon.to_string(), false);
        stat(ui, s, "Inbound", &inbound.to_string(), false);
        stat(ui, s, "Median ping", &ping, false);
        stat(ui, s, "Received", &bytes(recv), false);
        stat(ui, s, "Sent", &bytes(sent), false);
    });
}

fn stat(ui: &mut Ui, s: &Scene, label: &str, value: &str, lead: bool) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        widgets::label(ui, label);
        let size = if lead { 30.0 } else { 20.0 };
        ui.label(
            RichText::new(value)
                .font(font(theme::DISPLAY, size))
                .color(s.pal.text),
        );
    });
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
                width: Some(88.0),
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

fn table(ui: &mut Ui, s: &Scene, peers: &[&PeerView]) {
    let pal = s.pal;
    let cols = columns(ui.available_width());
    let ranges = widgets::table_header(ui, &cols);
    for p in peers {
        let rect = widgets::table_row(ui, 50.0);
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
                    if p.inbound { "Inbound" } else { "Outbound" }.into(),
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
        RichText::new("Height at connect is what each peer reported when it joined; peers don’t re-announce it.")
            .size(12.5)
            .color(pal.faint),
    );
    let _ = vec2;
}
