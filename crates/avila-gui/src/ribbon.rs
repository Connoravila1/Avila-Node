//! The Trust Ribbon: the whole chain from genesis to the best header,
//! drawn to scale and shaded by how this machine knows each block —
//! proven here (solid orange), taken from a snapshot while the background
//! replay checks it (hatched), or known only by its header (empty).
//!
//! It follows `getvalidationreport` exactly: blocks above a snapshot's
//! base were connected normally and count as proven, as do the heights
//! the replay has reached; only the unreplayed prefix is assumed.
//!
//! The ruler is either blocks or proof-of-work. By work, each stretch is
//! as wide as the work its blocks carry — and since mining has grown so
//! much harder, the recent years dominate.

use crate::model::{ChainCurve, TrustView, percent, thousands, year_month, year_start};
use crate::theme::{Palette, mono};
use crate::widgets::{self, end_radius, hatch};
use eframe::egui::{Color32, Rect, Response, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2};
use serde::{Deserialize, Serialize};

const HALVING: u32 = 210_000;
const RADIUS: u8 = 5;
/// Room above the band for the year ruler.
const YEAR_ROW: f32 = 20.0;

/// Heights `(from, to]`: `to - from` blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub from: u32,
    pub to: u32,
}

impl Span {
    fn blocks(self) -> u32 {
        self.to.saturating_sub(self.from)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    /// The chain's known extent: the best header, or the tip if higher.
    pub top: u32,
    pub proven: Vec<Span>,
    pub assumed: Option<Span>,
    pub pending: Option<Span>,
}

impl Coverage {
    #[must_use]
    pub fn of(t: &TrustView) -> Self {
        let top = t.headers.max(t.connected);
        let mut proven = Vec::new();
        let mut assumed = None;
        match &t.snapshot {
            Some(s) if !s.proven && s.base <= t.connected => {
                let replayed = s.replayed.min(s.base);
                proven.push(Span {
                    from: 0,
                    to: replayed,
                });
                if replayed < s.base {
                    assumed = Some(Span {
                        from: replayed,
                        to: s.base,
                    });
                }
                if t.connected > s.base {
                    proven.push(Span {
                        from: s.base,
                        to: t.connected,
                    });
                }
            }
            _ => proven.push(Span {
                from: 0,
                to: t.connected,
            }),
        }
        let pending = (top > t.connected).then_some(Span {
            from: t.connected,
            to: top,
        });
        Self {
            top,
            proven,
            assumed,
            pending,
        }
    }

    #[must_use]
    pub fn proven_blocks(&self) -> u32 {
        self.proven.iter().map(|s| s.blocks()).sum()
    }

    #[must_use]
    pub fn assumed_blocks(&self) -> u32 {
        self.assumed.map_or(0, Span::blocks)
    }

    #[must_use]
    pub fn pending_blocks(&self) -> u32 {
        self.pending.map_or(0, Span::blocks)
    }

    /// The proven share of the whole known chain, measured by `ruler`.
    #[must_use]
    pub fn proven_share(&self, ruler: &Ruler) -> f64 {
        self.proven.iter().map(|s| ruler.width(*s)).sum()
    }

    #[must_use]
    pub fn assumed_share(&self, ruler: &Ruler) -> f64 {
        self.assumed.map_or(0.0, |s| ruler.width(s))
    }

    #[must_use]
    pub fn pending_share(&self, ruler: &Ruler) -> f64 {
        self.pending.map_or(0.0, |s| ruler.width(s))
    }
}

/// How the ribbon measures the chain.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Scale {
    #[default]
    Blocks,
    Work,
}

/// Maps heights onto `0..=1` along the ribbon.
pub struct Ruler<'a> {
    top: u32,
    curve: Option<(&'a ChainCurve, f64)>,
}

impl<'a> Ruler<'a> {
    /// By work only when the curve can measure it; blocks otherwise.
    #[must_use]
    pub fn new(top: u32, scale: Scale, curve: &'a ChainCurve) -> Self {
        let curve = (scale == Scale::Work)
            .then(|| curve.work_at(top).map(|total| (curve, total)))
            .flatten()
            .filter(|(_, total)| *total > 0.0);
        Self { top, curve }
    }

    #[must_use]
    pub fn by_work(&self) -> bool {
        self.curve.is_some()
    }

    #[must_use]
    pub fn at(&self, height: u32) -> f64 {
        if self.top == 0 {
            return 0.0;
        }
        match self.curve {
            Some((curve, total)) => curve.work_at(height).map_or(0.0, |w| w / total),
            None => f64::from(height) / f64::from(self.top),
        }
        .clamp(0.0, 1.0)
    }

    #[must_use]
    pub fn width(&self, span: Span) -> f64 {
        self.at(span.to) - self.at(span.from)
    }
}

pub struct Options {
    /// Height of the band itself.
    pub band: f32,
    /// Label the halvings under the band (they are always notched).
    pub halvings: bool,
    /// A calendar ruler above the band.
    pub years: bool,
    pub scale: Scale,
    /// Progress `0..1` of the new-block pulse at the tip, if one is running.
    pub pulse: Option<f32>,
}

pub fn show(ui: &mut Ui, trust: &TrustView, curve: &ChainCurve, opts: &Options) -> Response {
    let pal = Palette::of(ui.ctx());
    let cov = Coverage::of(trust);
    let ruler = Ruler::new(cov.top, opts.scale, curve);
    let width = ui.available_width();
    let years_row = if opts.years && !curve.is_empty() {
        YEAR_ROW
    } else {
        0.0
    };
    let axis_rows = 2.0 * 17.0;
    let (rect, resp) = ui.allocate_exact_size(
        vec2(width, years_row + opts.band + 12.0 + axis_rows),
        Sense::hover(),
    );
    let band = Rect::from_min_size(rect.min + vec2(0.0, years_row), vec2(width, opts.band));
    let p = ui.painter();
    p.rect(
        band,
        RADIUS,
        pal.well,
        Stroke::new(1.0, pal.hairline),
        StrokeKind::Inside,
    );
    if cov.top == 0 {
        return resp;
    }
    let x = |h: u32| band.left() + band.width() * ruler.at(h) as f32;
    // A segment's rect, at least `min` wide so a sliver stays visible.
    let seg = |span: Span, min: f32| {
        let (mut l, mut r) = (x(span.from), x(span.to));
        if r - l < min {
            r = (l + min).min(band.right());
            l = r - min;
        }
        Rect::from_x_y_ranges(l..=r, band.y_range())
    };
    let ends = |r: Rect| {
        end_radius(
            RADIUS,
            r.left() <= band.left() + 0.5,
            r.right() >= band.right() - 0.5,
        )
    };

    for span in cov.proven.iter().filter(|s| s.blocks() > 0) {
        let r = seg(*span, 2.0);
        p.rect_filled(r, ends(r), pal.signal);
    }
    if let Some(span) = cov.assumed {
        let r = seg(span, 3.0);
        p.rect_filled(
            r,
            ends(r),
            pal.signal_alpha(if pal.dark { 0.16 } else { 0.20 }),
        );
        hatch(p, r, pal.signal, 6.0, 1.6);
    }
    if let Some(span) = cov.pending {
        let r = seg(span, 3.0);
        p.rect_stroke(r, ends(r), Stroke::new(1.0, pal.muted), StrokeKind::Inside);
    }
    // Halvings notch the band: the chain's own ruler.
    let mut k = 1;
    while k * HALVING < cov.top {
        p.vline(
            x(k * HALVING),
            band.y_range(),
            Stroke::new(1.0, pal.canvas.gamma_multiply(0.75)),
        );
        k += 1;
    }
    let replay = trust.snapshot.as_ref().filter(|s| !s.proven);
    if let Some(s) = replay {
        let hx = x(s.replayed.min(s.base));
        p.vline(
            hx,
            (band.top() - 5.0)..=(band.bottom() + 5.0),
            Stroke::new(2.0, pal.text),
        );
    }
    if let Some(f) = opts.pulse.filter(|f| (0.0..1.0).contains(f)) {
        let c = pos2(x(trust.connected).min(band.right() - 2.0), band.center().y);
        let fade = 1.0 - f;
        p.circle_stroke(
            c,
            5.0 + 20.0 * f,
            Stroke::new(0.5 + 2.0 * fade, pal.signal.gamma_multiply(fade)),
        );
    }
    if years_row > 0.0 {
        year_ruler(ui, curve, band, &x, &pal);
    }

    // Axis labels: two rows under the band, placed by priority, skipped
    // when there's no room rather than overlapping.
    let p = ui.painter();
    let mut marks: Vec<(f32, String, Color32, Option<bool>)> = vec![
        (band.left(), "genesis".into(), pal.muted, Some(false)),
        (
            band.right(),
            thousands(cov.top.into()),
            pal.muted,
            Some(true),
        ),
    ];
    if let Some(s) = replay {
        let r = s.replayed.min(s.base);
        marks.push((
            x(r),
            format!("replay {}", thousands(r.into())),
            pal.text,
            None,
        ));
    }
    if let Some(s) = &trust.snapshot {
        marks.push((
            x(s.base),
            format!("snapshot {}", thousands(s.base.into())),
            pal.muted,
            None,
        ));
    }
    if opts.halvings {
        let mut k = 1;
        while k * HALVING < cov.top {
            marks.push((x(k * HALVING), format!("halving {k}"), pal.faint, None));
            k += 1;
        }
    }
    let mut placed: [Vec<Rect>; 2] = [Vec::new(), Vec::new()];
    for (mx, text, color, right) in marks {
        let right = right.unwrap_or(mx > band.center().x);
        let galley = p.layout_no_wrap(text, mono(11.5), color);
        let w = galley.size().x;
        let left = if right { mx - w } else { mx };
        let left = left.clamp(band.left(), band.right() - w);
        for (row, taken) in placed.iter_mut().enumerate() {
            let top = band.bottom() + 10.0 + 17.0 * row as f32;
            let r = Rect::from_min_size(pos2(left, top), galley.size());
            if taken
                .iter()
                .any(|t| t.expand2(vec2(10.0, 0.0)).intersects(r))
            {
                continue;
            }
            if mx > band.left() + 1.0 && mx < band.right() - 1.0 {
                p.vline(
                    mx,
                    (band.bottom() + 1.0)..=(band.bottom() + 6.0),
                    Stroke::new(1.0, pal.muted),
                );
            }
            p.galley(r.min, galley, color);
            taken.push(r);
            break;
        }
    }
    resp
}

/// Years along the top edge, wherever there's room for them.
fn year_ruler(ui: &Ui, curve: &ChainCurve, band: Rect, x: &dyn Fn(u32) -> f32, pal: &Palette) {
    let (Some(first), Some(tip)) = (curve.time_at(0), curve.tip()) else {
        return;
    };
    let p = ui.painter();
    let (from, _) = year_month(first as i64);
    let (to, _) = year_month(i64::from(tip.time));
    let mut last_right = f32::NEG_INFINITY;
    for year in from + 1..=to {
        let Some(h) = curve.height_at_time(year_start(year) as f64) else {
            continue;
        };
        let mx = x(h.round() as u32);
        let galley = p.layout_no_wrap(year.to_string(), mono(10.5), pal.faint);
        let left = mx - galley.size().x / 2.0;
        if left < last_right + 10.0 || left + galley.size().x > band.right() {
            continue;
        }
        p.vline(
            mx,
            (band.top() - 5.0)..=(band.top() - 1.0),
            Stroke::new(1.0, pal.hairline),
        );
        let top = band.top() - YEAR_ROW;
        last_right = left + galley.size().x;
        p.galley(pos2(left, top), galley, pal.faint);
    }
}

/// Swatches with measures, for whichever states the chain is in: block
/// counts by blocks, shares of the chain's work by work.
pub fn legend(ui: &mut Ui, trust: &TrustView, ruler: &Ruler) {
    let pal = Palette::of(ui.ctx());
    let cov = Coverage::of(trust);
    let measure = |blocks: u32, share: f64| {
        if ruler.by_work() {
            percent(share)
        } else {
            thousands(blocks.into())
        }
    };
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 7.0;
        let item = |ui: &mut Ui, kind: u8, text: &str, value: String| {
            let (r, _) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
            let p = ui.painter();
            match kind {
                0 => {
                    p.rect_filled(r, 3, pal.signal);
                }
                1 => {
                    p.rect_filled(r, 3, pal.signal_alpha(0.2));
                    hatch(p, r, pal.signal, 4.0, 1.4);
                }
                _ => {
                    p.rect(
                        r,
                        3,
                        pal.well,
                        Stroke::new(1.0, pal.muted),
                        StrokeKind::Inside,
                    );
                }
            }
            ui.label(RichText::new(text).size(13.0).color(pal.text));
            ui.label(RichText::new(value).font(mono(12.5)).color(pal.muted));
            ui.add_space(16.0);
        };
        item(
            ui,
            0,
            "Proven here",
            measure(cov.proven_blocks(), cov.proven_share(ruler)),
        );
        if cov.assumed_blocks() > 0 {
            item(
                ui,
                1,
                "Assumed from the snapshot",
                measure(cov.assumed_blocks(), cov.assumed_share(ruler)),
            );
        }
        if cov.pending_blocks() > 0 {
            item(
                ui,
                2,
                "Headers only",
                measure(cov.pending_blocks(), cov.pending_share(ruler)),
            );
        }
    });
}

/// Blocks or work: the ribbon's ruler.
pub fn scale_toggle(ui: &mut Ui, scale: &mut Scale) -> bool {
    widgets::segmented(
        ui,
        scale,
        &[(Scale::Blocks, "By blocks"), (Scale::Work, "By work")],
    )
}

/// A thin progress bar in the ribbon's own language.
pub fn replay_bar(ui: &mut Ui, done: u32, of: u32, width: f32) {
    let pal = Palette::of(ui.ctx());
    let (r, _) = ui.allocate_exact_size(vec2(width, 8.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(r, 4, pal.signal_alpha(0.2));
    hatch(p, r, pal.signal, 5.0, 1.3);
    if of > 0 {
        let f = (f64::from(done.min(of)) / f64::from(of)) as f32;
        let fill = Rect::from_min_size(r.min, vec2(r.width() * f, r.height()));
        p.rect_filled(fill, end_radius(4, true, f >= 0.999), pal.signal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CurvePoint, SnapshotView};

    fn trust(connected: u32, headers: u32, snapshot: Option<(u32, u32, bool)>) -> TrustView {
        TrustView {
            connected,
            headers,
            snapshot: snapshot.map(|(base, replayed, proven)| SnapshotView {
                base,
                base_hash: String::new(),
                expected_utxo_hash: String::new(),
                replayed,
                proven,
            }),
            verified_fraction: 0.0,
        }
    }

    #[test]
    fn coverage_matches_the_validation_report() {
        let c = Coverage::of(&trust(935_184, 935_186, Some((910_000, 612_400, false))));
        assert_eq!(c.top, 935_186);
        assert_eq!(c.proven_blocks(), 612_400 + 25_184);
        assert_eq!(c.assumed_blocks(), 297_600);
        assert_eq!(c.pending_blocks(), 2);
        // The node's verified_heights: (connected - base) + replayed.
        assert_eq!(c.proven_blocks(), (935_184 - 910_000) + 612_400);
    }

    #[test]
    fn a_proven_snapshot_or_none_is_all_proven() {
        let flat = ChainCurve::default();
        for snap in [None, Some((910_000, 910_000, true))] {
            let c = Coverage::of(&trust(935_184, 935_184, snap));
            assert_eq!(c.proven_blocks(), 935_184);
            assert_eq!(c.assumed, None);
            assert_eq!(c.pending, None);
            let ruler = Ruler::new(c.top, Scale::Blocks, &flat);
            assert!((c.proven_share(&ruler) - 1.0).abs() < 1e-12);
        }
    }

    #[test]
    fn syncing_from_genesis_is_proven_then_pending() {
        let c = Coverage::of(&trust(385_112, 935_186, None));
        assert_eq!(
            c.proven,
            vec![Span {
                from: 0,
                to: 385_112
            }]
        );
        assert_eq!(
            c.pending,
            Some(Span {
                from: 385_112,
                to: 935_186
            })
        );
        let flat = ChainCurve::default();
        let empty = Coverage::of(&trust(0, 0, None));
        assert_eq!(
            empty.proven_share(&Ruler::new(0, Scale::Blocks, &flat)),
            0.0
        );
    }

    #[test]
    fn the_work_ruler_weighs_heavy_blocks_more() {
        // Blocks 0..100 carry 1 each, 100..200 carry 9 each.
        let curve = ChainCurve::new(vec![
            CurvePoint {
                height: 0,
                work: 0.0,
                time: 0,
            },
            CurvePoint {
                height: 100,
                work: 100.0,
                time: 100,
            },
            CurvePoint {
                height: 200,
                work: 1_000.0,
                time: 200,
            },
        ]);
        let c = Coverage::of(&trust(100, 200, None));
        let blocks = Ruler::new(c.top, Scale::Blocks, &curve);
        let work = Ruler::new(c.top, Scale::Work, &curve);
        assert!(work.by_work() && !blocks.by_work());
        assert!((c.proven_share(&blocks) - 0.5).abs() < 1e-12);
        assert!((c.proven_share(&work) - 0.1).abs() < 1e-12);
        // Without a curve, "by work" falls back to blocks.
        assert!(!Ruler::new(c.top, Scale::Work, &ChainCurve::default()).by_work());
    }
}
