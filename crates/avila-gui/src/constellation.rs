//! The peer constellation: this node at the center and each peer placed
//! by what's true about it. Distance is ping (closer is faster); peers in
//! the same network group sit together (Core spreads outbound peers across
//! groups to resist eclipse attacks); a solid line is an encrypted link, a
//! dashed one plaintext, a doubled one reconciles with Erlay; a dot's size
//! is the blocks that peer delivered, hollow if it dialed us. When a block
//! connects, a pulse runs down the line of the peer that delivered it.
//!
//! It's a star by necessity: Bitcoin keeps the network's shape private,
//! so a node only knows its own links.

use crate::model::PeerView;
use crate::session::{agent_name, peer_name};
use crate::theme::{INK, Palette, mono};
use eframe::egui::{
    Align2, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke, TextureHandle, Ui, pos2, vec2,
};
use std::collections::HashMap;
use std::f32::consts::{PI, TAU};
use std::net::SocketAddr;

/// Pings at or under this sit on the inner ring, at or over `SLOW_MS`
/// on the outer; log scale between.
const FAST_MS: f64 = 10.0;
const SLOW_MS: f64 = 1_000.0;
const FADE_SECS: f64 = 1.2;
/// Past this many peers, addresses show only on hover.
const LABELLED: usize = 14;

/// What a peer looked like when last drawn — enough to fade it out.
#[derive(Clone)]
struct Look {
    label: String,
    inbound: bool,
    v2: bool,
    recon: bool,
    size: f32,
}

#[derive(Clone)]
struct Star {
    angle: f32,
    radius: f32,
    look: Look,
}

struct Ghost {
    star: Star,
    gone: f64,
}

#[derive(Default)]
pub struct Constellation {
    stars: HashMap<u64, Star>,
    ghosts: Vec<Ghost>,
    last: Option<f64>,
    animating: bool,
}

#[derive(Default)]
pub struct Outcome {
    pub clicked: Option<u64>,
    pub clicked_empty: bool,
}

/// Core's default network group: the /16 of an IPv4 address, the /32 of
/// an IPv6 one.
#[must_use]
pub fn netgroup(p: &PeerView) -> String {
    match p.addr.as_deref().and_then(|a| a.parse::<SocketAddr>().ok()) {
        Some(SocketAddr::V4(a)) => {
            let [x, y, ..] = a.ip().octets();
            format!("{x}.{y}.0.0/16")
        }
        Some(SocketAddr::V6(a)) => {
            let s = a.ip().segments();
            format!("{:x}:{:x}::/32", s[0], s[1])
        }
        None => "unknown".into(),
    }
}

/// An address without its port, as short as it can be said.
fn short_addr(p: &PeerView) -> String {
    match p.addr.as_deref().and_then(|a| a.parse::<SocketAddr>().ok()) {
        Some(a) => a.ip().to_string(),
        None => peer_name(p),
    }
}

fn dot_size(blocks: usize) -> f32 {
    (3.5 + 1.6 * (1.0 + blocks as f32).ln()).min(10.0)
}

/// The shortest signed turn from `a` to `b`.
fn turn(a: f32, b: f32) -> f32 {
    (b - a + PI).rem_euclid(TAU) - PI
}

impl Constellation {
    /// Still easing into place, fading, or pulsing: keep repainting.
    #[must_use]
    pub fn animating(&self) -> bool {
        self.animating
    }

    /// Draws the constellation `height` tall across the available width.
    /// `pulse` is the new-block pulse: who delivered it and its progress.
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        ui: &mut Ui,
        peers: &[&PeerView],
        selected: Option<u64>,
        pulse: Option<(Option<u64>, f32)>,
        now: f64,
        height: f32,
        swirl: Option<&TextureHandle>,
    ) -> Outcome {
        let pal = Palette::of(ui.ctx());
        let (rect, resp) =
            ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
        let center = rect.center();
        let outer = (rect.height() / 2.0 - 30.0)
            .min(rect.width() / 2.0 - 110.0)
            .max(60.0);
        let inner = outer * 0.3;
        let radius_for = |ping: Option<f64>| {
            let f = ping.map_or(1.0, |ms| {
                ((ms.max(1.0).log10() - FAST_MS.log10()) / (SLOW_MS.log10() - FAST_MS.log10()))
                    .clamp(0.0, 1.0)
            });
            inner + (outer - inner) * f as f32
        };

        // Where everyone belongs: grouped around the circle, a wider gap
        // between groups than within one.
        let mut order: Vec<(String, &PeerView)> = peers.iter().map(|p| (netgroup(p), *p)).collect();
        order.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
        // The circle opens at the top, where the rings are labelled: a
        // gap of `OPENING` steps, the first peer just past it.
        const OPENING: f32 = 1.6;
        let mut steps = Vec::with_capacity(order.len());
        for (i, (g, _)) in order.iter().enumerate() {
            let same = i > 0 && order[i - 1].0 == *g;
            steps.push(if i == 0 {
                0.0
            } else if same {
                1.0
            } else {
                1.9
            });
        }
        let total: f32 = steps.iter().sum::<f32>() + 2.0 * OPENING;
        let mut targets: HashMap<u64, (f32, f32)> = HashMap::new();
        let mut run = OPENING;
        for ((_, p), step) in order.iter().zip(&steps) {
            run += step;
            let angle = -PI / 2.0 + TAU * run / total;
            targets.insert(p.id, (angle, radius_for(p.ping_ms)));
        }

        // Ease toward the targets; newcomers grow out of the center and
        // leavers fade where they stood.
        let dt = self.last.map_or(0.0, |l| (now - l).clamp(0.0, 0.1));
        self.last = Some(now);
        let k = 1.0 - (-dt * 5.0).exp() as f32;
        let mut moving = false;
        for p in peers {
            let Some(&(angle, radius)) = targets.get(&p.id) else {
                continue;
            };
            let look = Look {
                label: short_addr(p),
                inbound: p.inbound,
                v2: p.v2,
                recon: p.recon,
                size: dot_size(p.blocks_served),
            };
            let star = self.stars.entry(p.id).or_insert(Star {
                angle,
                radius: 0.0,
                look: look.clone(),
            });
            let da = turn(star.angle, angle);
            let dr = radius - star.radius;
            star.angle += da * k;
            star.radius += dr * k;
            star.look = look;
            moving |= da.abs() > 0.002 || dr.abs() > 0.3;
        }
        let gone: Vec<u64> = self
            .stars
            .keys()
            .filter(|id| !targets.contains_key(id))
            .copied()
            .collect();
        for id in gone {
            if let Some(star) = self.stars.remove(&id) {
                self.ghosts.push(Ghost { star, gone: now });
            }
        }
        self.ghosts.retain(|g| now - g.gone < FADE_SECS);
        self.animating = moving || !self.ghosts.is_empty() || pulse.is_some();

        let at = |s: &Star| center + vec2(s.angle.cos(), s.angle.sin()) * s.radius;
        let p = ui.painter_at(rect);

        // Latency rings, labelled in the opening at the top.
        for (ms, label) in [(10.0, "10 ms"), (100.0, "100 ms"), (1_000.0, "1 s")] {
            let r = radius_for(Some(ms));
            p.circle_stroke(
                center,
                r,
                Stroke::new(1.0, pal.hairline.gamma_multiply(0.8)),
            );
            p.text(
                center - vec2(0.0, r),
                Align2::CENTER_CENTER,
                label,
                mono(10.0),
                pal.faint,
            );
        }

        // Groups with more than one peer get an arc outside the ring.
        let mut members: HashMap<&str, Vec<(u64, bool)>> = HashMap::new();
        for (g, peer) in &order {
            members
                .entry(g.as_str())
                .or_default()
                .push((peer.id, peer.inbound));
        }
        for (group, ids) in &members {
            if ids.len() < 2 {
                continue;
            }
            let angles: Vec<f32> = ids
                .iter()
                .filter_map(|(id, _)| self.stars.get(id).map(|s| s.angle))
                .collect();
            let Some(&first) = angles.first() else {
                continue;
            };
            let (mut lo, mut hi) = (0.0_f32, 0.0_f32);
            for a in &angles {
                let d = turn(first, *a);
                lo = lo.min(d);
                hi = hi.max(d);
            }
            let (lo, hi) = (first + lo - 0.09, first + hi + 0.09);
            let r = outer + 16.0;
            let shared_outbound = ids.iter().filter(|(_, inbound)| !inbound).count() >= 2;
            let color = if shared_outbound {
                pal.alert
            } else {
                pal.faint
            };
            let points: Vec<Pos2> = (0..=24)
                .map(|i| {
                    let a = lo + (hi - lo) * i as f32 / 24.0;
                    center + vec2(a.cos(), a.sin()) * r
                })
                .collect();
            p.add(Shape::line(points, Stroke::new(1.2, color)));
            let mid = (lo + hi) / 2.0;
            let anchor = if mid.cos() >= 0.0 {
                Align2::LEFT_CENTER
            } else {
                Align2::RIGHT_CENTER
            };
            p.text(
                center + vec2(mid.cos(), mid.sin()) * (r + 8.0),
                anchor,
                *group,
                mono(10.0),
                color,
            );
        }

        // Pointer: the nearest dot within reach.
        let hovered = resp.hover_pos().and_then(|pos| {
            self.stars
                .iter()
                .map(|(id, s)| (*id, at(s).distance(pos), s.look.size))
                .filter(|(_, d, size)| *d <= size + 7.0)
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(id, ..)| id)
        });

        let edge = |p: &eframe::egui::Painter, s: &Star, color: Color32, width: f32| {
            let dir = vec2(s.angle.cos(), s.angle.sin());
            let a = center + dir * 17.0;
            let b = at(s) - dir * (s.look.size + 3.0);
            if s.radius < 20.0 {
                return;
            }
            let stroke = Stroke::new(width, color);
            let normal = vec2(-dir.y, dir.x) * 1.8;
            let lines: Vec<[Pos2; 2]> = if s.look.recon {
                vec![[a + normal, b + normal], [a - normal, b - normal]]
            } else {
                vec![[a, b]]
            };
            for [from, to] in lines {
                if s.look.v2 {
                    p.line_segment([from, to], stroke);
                } else {
                    p.extend(Shape::dashed_line(&[from, to], stroke, 4.0, 3.5));
                }
            }
        };
        let dot = |p: &eframe::egui::Painter, s: &Star, ink: Color32, halo: bool| {
            let c = at(s);
            if halo {
                p.circle_filled(c, s.look.size + 6.0, ink.gamma_multiply(0.14));
            }
            if s.look.inbound {
                p.circle_filled(c, s.look.size, pal.canvas);
                p.circle_stroke(c, s.look.size - 0.75, Stroke::new(1.5, ink));
            } else {
                p.circle_filled(c, s.look.size, ink);
            }
        };

        for g in &self.ghosts {
            let fade = (1.0 - (now - g.gone) / FADE_SECS).clamp(0.0, 1.0) as f32;
            edge(&p, &g.star, pal.muted.gamma_multiply(0.5 * fade), 1.0);
        }
        for (id, s) in &self.stars {
            let lit = Some(*id) == selected || Some(*id) == hovered;
            let (color, width) = if lit {
                (pal.text, 1.6)
            } else {
                (pal.muted.gamma_multiply(0.6), 1.1)
            };
            edge(&p, s, color, width);
        }

        // The new block's trip: down the deliverer's line, then a ring
        // from the center — orange, because it's now proven here.
        if let Some((from, f)) = pulse {
            if let Some(s) = from.and_then(|id| self.stars.get(&id))
                && f < 0.55
            {
                let t = f / 0.55;
                let t = t * t * (3.0 - 2.0 * t);
                let pos = at(s) + (center - at(s)) * t;
                p.circle_filled(pos, 8.0, pal.signal.gamma_multiply(0.25));
                p.circle_filled(pos, 3.5, pal.signal);
            }
            if f >= 0.45 {
                let g = (f - 0.45) / 0.55;
                p.circle_stroke(
                    center,
                    16.0 + 24.0 * g,
                    Stroke::new(2.5 * (1.0 - g) + 0.5, pal.signal.gamma_multiply(1.0 - g)),
                );
            }
        }

        // This node: the logo itself.
        p.circle_filled(center, 15.0, pal.signal);
        if let Some(tex) = swirl {
            p.image(
                tex.id(),
                Rect::from_center_size(center, vec2(24.0, 24.0)),
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                INK,
            );
        }

        for g in &self.ghosts {
            let fade = (1.0 - (now - g.gone) / FADE_SECS).clamp(0.0, 1.0) as f32;
            dot(&p, &g.star, pal.text.gamma_multiply(fade * 0.6), false);
        }
        for (id, s) in &self.stars {
            let lit = Some(*id) == selected || Some(*id) == hovered;
            dot(&p, s, pal.text, lit);
        }
        // Labels in a fixed order (the lit peer first), each skipped if it
        // would sit on another label or dot — hover still names it.
        let label_all = self.stars.len() <= LABELLED;
        let mut taken: Vec<(u64, Rect)> = self
            .stars
            .iter()
            .map(|(id, s)| {
                (
                    *id,
                    Rect::from_center_size(at(s), vec2(1.0, 1.0) * (s.look.size * 2.0 + 2.0)),
                )
            })
            .collect();
        taken.push((u64::MAX, Rect::from_center_size(center, vec2(34.0, 34.0))));
        let mut ids: Vec<u64> = self.stars.keys().copied().collect();
        ids.sort_by_key(|id| (Some(*id) != selected && Some(*id) != hovered, *id));
        for id in ids {
            let Some(s) = self.stars.get(&id) else {
                continue;
            };
            let lit = Some(id) == selected || Some(id) == hovered;
            if !label_all && !lit {
                continue;
            }
            let color = if lit { pal.text } else { pal.muted };
            let galley = p.layout_no_wrap(s.look.label.clone(), mono(10.5), color);
            let dir = vec2(s.angle.cos(), s.angle.sin());
            let pos = at(s) + dir * (s.look.size + 7.0);
            let size = galley.size();
            let min = if dir.x >= 0.0 {
                pos - vec2(0.0, size.y / 2.0)
            } else {
                pos - vec2(size.x, size.y / 2.0)
            };
            let r = Rect::from_min_size(min, size);
            if !lit
                && taken
                    .iter()
                    .any(|(other, t)| *other != id && t.intersects(r))
            {
                continue;
            }
            p.galley(r.min, galley, color);
            taken.push((id, r));
        }

        let mut out = Outcome::default();
        if let Some(id) = hovered {
            if let Some(peer) = peers.iter().find(|p| p.id == id) {
                resp.clone().on_hover_ui(|ui| tooltip(ui, peer, &pal));
            }
            if resp.clicked() {
                out.clicked = Some(id);
            }
        } else if resp.clicked() {
            out.clicked_empty = true;
        }
        if hovered.is_some() {
            ui.ctx()
                .set_cursor_icon(eframe::egui::CursorIcon::PointingHand);
        }
        out
    }
}

fn tooltip(ui: &mut Ui, p: &PeerView, pal: &Palette) {
    ui.label(RichText::new(peer_name(p)).font(mono(12.5)).color(pal.text));
    if let Some(agent) = &p.agent {
        ui.label(RichText::new(agent_name(agent)).size(12.5).color(pal.muted));
    }
    let transport = if p.v2 { "Encrypted" } else { "Plaintext" };
    let ping = p
        .ping_ms
        .map_or("no ping yet".into(), |ms| format!("{ms:.0} ms"));
    let mut line = format!("{transport} · {ping}");
    if p.recon {
        line.push_str(" · Erlay");
    }
    ui.label(RichText::new(line).size(12.5).color(pal.muted));
    ui.label(
        RichText::new(format!("{} blocks delivered", p.blocks_served))
            .size(12.5)
            .color(pal.muted),
    );
}

/// The key to reading it, drawn with the same marks.
pub fn legend(ui: &mut Ui) {
    let pal = Palette::of(ui.ctx());
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let mark = |ui: &mut Ui, kind: u8| {
            let (r, _) = ui.allocate_exact_size(vec2(22.0, 14.0), Sense::hover());
            let p = ui.painter();
            let (a, b) = (r.left_center(), r.right_center());
            let s = Stroke::new(1.3, pal.muted);
            match kind {
                0 => {
                    p.line_segment([a, b], s);
                }
                1 => {
                    p.extend(Shape::dashed_line(&[a, b], s, 4.0, 3.0));
                }
                2 => {
                    p.line_segment([a - vec2(0.0, 1.8), b - vec2(0.0, 1.8)], s);
                    p.line_segment([a + vec2(0.0, 1.8), b + vec2(0.0, 1.8)], s);
                }
                3 => {
                    p.circle_filled(r.center(), 4.5, pal.text);
                }
                _ => {
                    p.circle_stroke(r.center(), 4.0, Stroke::new(1.5, pal.text));
                }
            }
        };
        for (kind, text) in [
            (0, "encrypted"),
            (1, "plaintext"),
            (2, "Erlay"),
            (3, "we dialed"),
            (4, "they dialed"),
        ] {
            mark(ui, kind);
            ui.label(RichText::new(text).size(12.5).color(pal.muted));
            ui.add_space(8.0);
        }
        ui.label(
            RichText::new("Closer is a faster ping; bigger dots delivered more blocks.")
                .size(12.5)
                .color(pal.faint),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::test_peer;

    #[test]
    fn netgroups_follow_core_defaults() {
        let mut p = test_peer(1);
        p.addr = Some("100.71.3.9:8333".into());
        assert_eq!(netgroup(&p), "100.71.0.0/16");
        p.addr = Some("[2001:db8:1f::a3]:8333".into());
        assert_eq!(netgroup(&p), "2001:db8::/32");
        p.addr = None;
        assert_eq!(netgroup(&p), "unknown");
    }

    #[test]
    fn turns_take_the_short_way_round() {
        assert!((turn(0.1, TAU - 0.1) + 0.2).abs() < 1e-5);
        assert!((turn(TAU - 0.1, 0.1) - 0.2).abs() < 1e-5);
    }
}
