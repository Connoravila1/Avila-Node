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

use crate::model::{ChainCurve, TrustView, month_year, percent, thousands, year_month, year_start};
use crate::theme::{Palette, mono};
use crate::widgets::{self, end_radius, hatch};
use eframe::egui::{
    Align2, Color32, Rect, Response, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};
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

    /// The height at fraction `f` along the ruler (the inverse of
    /// [`Self::at`]).
    #[must_use]
    pub fn height_at(&self, f: f64) -> f64 {
        let f = f.clamp(0.0, 1.0);
        match self.curve {
            Some((curve, total)) => curve
                .height_at_work(f * total)
                .unwrap_or(0.0)
                .min(f64::from(self.top)),
            None => f * f64::from(self.top),
        }
    }

    #[must_use]
    pub fn width(&self, span: Span) -> f64 {
        self.at(span.to) - self.at(span.from)
    }
}

/// The visible slice of a zoomable ribbon, as fractions of its ruler.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct View {
    pub lo: f64,
    pub hi: f64,
}

impl Default for View {
    fn default() -> Self {
        Self { lo: 0.0, hi: 1.0 }
    }
}

impl View {
    #[must_use]
    pub fn zoomed(&self) -> bool {
        self.lo > 1e-9 || self.hi < 1.0 - 1e-9
    }

    fn span(&self) -> f64 {
        (self.hi - self.lo).max(1e-12)
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

/// Where a height stands, in the ribbon's words.
fn status(trust: &TrustView, height: u32) -> &'static str {
    let assumed = trust
        .snapshot
        .as_ref()
        .filter(|s| !s.proven && s.base <= trust.connected)
        .is_some_and(|s| height > s.replayed.min(s.base) && height <= s.base);
    if height == 0 {
        "Genesis"
    } else if assumed {
        "Assumed from the snapshot"
    } else if height <= trust.connected {
        "Proven here"
    } else if height <= trust.headers {
        "Headers only"
    } else {
        "Not known yet"
    }
}

/// Draws the ribbon. With `view`, it zooms: scroll to zoom around the
/// pointer, drag to pan, double-click to see the whole chain again.
/// Hovering anywhere reads out the block there. `recent` supplies hashes
/// for the newest blocks.
pub fn show(
    ui: &mut Ui,
    trust: &TrustView,
    curve: &ChainCurve,
    recent: &[(u32, String)],
    opts: &Options,
    view: Option<&mut View>,
) -> Response {
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
    let sense = if view.is_some() {
        Sense::click_and_drag()
    } else {
        Sense::hover()
    };
    let (rect, resp) =
        ui.allocate_exact_size(vec2(width, years_row + opts.band + 12.0 + axis_rows), sense);
    let band = Rect::from_min_size(rect.min + vec2(0.0, years_row), vec2(width, opts.band));

    // Zoom and pan, before anything is drawn with the view.
    let mut v = View::default();
    if let Some(view) = view {
        if cov.top > 24 {
            steer(ui, &resp, band, view, &ruler, cov.top);
        }
        v = *view;
    }
    let fx = |f: f64| band.left() + band.width() * ((f - v.lo) / v.span()) as f32;
    let x = |h: u32| fx(ruler.at(h));

    let p = ui.painter().with_clip_rect(band.expand2(vec2(1.0, 8.0)));
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
    // A segment's rect, at least `min` wide so a sliver stays visible,
    // and cut to what's in view.
    let seg = |span: Span, min: f32| {
        let (mut l, mut r) = (x(span.from), x(span.to));
        if r - l < min {
            r = l + min;
            l = r - min;
        }
        let (l, r) = (l.max(band.left()), r.min(band.right()));
        (r > l).then(|| Rect::from_x_y_ranges(l..=r, band.y_range()))
    };
    let ends = |r: Rect| {
        end_radius(
            RADIUS,
            r.left() <= band.left() + 0.5,
            r.right() >= band.right() - 0.5,
        )
    };
    for span in cov.proven.iter().filter(|s| s.blocks() > 0) {
        if let Some(r) = seg(*span, 2.0) {
            p.rect_filled(r, ends(r), pal.signal);
            if pal.chunky {
                chunks(&p, r, &pal);
            }
        }
    }
    if let Some(r) = cov.assumed.and_then(|span| seg(span, 3.0)) {
        p.rect_filled(
            r,
            ends(r),
            pal.signal_alpha(if pal.dark { 0.16 } else { 0.20 }),
        );
        hatch(&p, r, pal.signal, 6.0, 1.6);
    }
    if let Some(r) = cov.pending.and_then(|span| seg(span, 3.0)) {
        p.rect_stroke(r, ends(r), Stroke::new(1.0, pal.muted), StrokeKind::Inside);
    }
    // Close in, the blocks themselves: a seam between each, and their
    // heights once there's room to write them.
    let (first, last) = (ruler.height_at(v.lo), ruler.height_at(v.hi));
    let px_per_block = band.width() / (last - first).max(1.0) as f32;
    if px_per_block >= 5.0 {
        let seam = Stroke::new(1.0, pal.canvas.gamma_multiply(0.9));
        for h in (first.floor() as u32)..=(last.ceil() as u32).min(cov.top) {
            let at = x(h);
            if at > band.left() + 0.5 && at < band.right() - 0.5 {
                p.vline(at, band.y_range(), seam);
            }
            // A height only where its own cell can hold it.
            if h > 0 && px_per_block >= 58.0 {
                let mid = (x(h - 1) + at) / 2.0;
                p.text(
                    pos2(mid, band.center().y),
                    Align2::CENTER_CENTER,
                    thousands(h.into()),
                    mono(10.0),
                    pal.canvas,
                );
            }
        }
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
        p.vline(
            x(s.replayed.min(s.base)),
            (band.top() - 5.0)..=(band.bottom() + 5.0),
            Stroke::new(2.0, pal.text),
        );
    }
    if let Some(f) = opts.pulse.filter(|f| (0.0..1.0).contains(f)) {
        let c = pos2(x(trust.connected).min(band.right() - 2.0), band.center().y);
        let fade = 1.0 - f;
        ui.painter().circle_stroke(
            c,
            5.0 + 20.0 * f,
            Stroke::new(0.5 + 2.0 * fade, pal.signal.gamma_multiply(fade)),
        );
    }
    if years_row > 0.0 {
        year_ruler(ui, curve, band, &x, &pal);
    }

    // Axis labels: two rows under the band, placed by priority, skipped
    // when there's no room rather than overlapping. Zoomed in, the ends
    // of the view take the place of genesis and the tip.
    let p = ui.painter();
    let inside = |mx: f32| mx >= band.left() - 0.5 && mx <= band.right() + 0.5;
    let mut marks: Vec<(f32, String, Color32, Option<bool>)> = if v.zoomed() {
        vec![
            (
                band.left(),
                thousands(first.round() as u64),
                pal.muted,
                Some(false),
            ),
            (
                band.right(),
                thousands(last.round() as u64),
                pal.muted,
                Some(true),
            ),
        ]
    } else {
        vec![
            (band.left(), "genesis".into(), pal.muted, Some(false)),
            (
                band.right(),
                thousands(cov.top.into()),
                pal.muted,
                Some(true),
            ),
        ]
    };
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
        if !inside(mx) {
            continue;
        }
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

    // The reading under the pointer.
    let Some(pos) = resp
        .hover_pos()
        .filter(|pos| band.x_range().contains(pos.x))
    else {
        return resp;
    };
    let f = v.lo + f64::from((pos.x - band.left()) / band.width()) * v.span();
    // Block h fills (h-1, h], so the block under the pointer rounds up.
    let height = ruler.height_at(f).ceil() as u32;
    ui.painter().vline(
        pos.x,
        (band.top() - 3.0)..=(band.bottom() + 3.0),
        Stroke::new(1.0, pal.text.gamma_multiply(0.7)),
    );
    let when = curve.time_at(height).map(|t| month_year(t as i64));
    let hash = recent
        .iter()
        .find(|(h, _)| *h == height)
        .map(|(_, hash)| hash.clone());
    let work = ruler.by_work().then(|| percent(f));
    resp.on_hover_ui_at_pointer(|ui| {
        ui.label(
            RichText::new(format!("Block {}", thousands(height.into())))
                .font(mono(12.5))
                .color(pal.text),
        );
        ui.label(
            RichText::new(status(trust, height))
                .size(13.0)
                .color(pal.text),
        );
        if let Some(when) = when {
            ui.label(
                RichText::new(format!("Mined around {when}"))
                    .size(12.5)
                    .color(pal.muted),
            );
        }
        if let Some(work) = work {
            ui.label(
                RichText::new(format!("{work} of the chain’s work comes before it"))
                    .size(12.5)
                    .color(pal.muted),
            );
        }
        if let Some(hash) = hash {
            ui.label(crate::widgets::hash_job(&hash, 11.5, &pal, Some(16)));
        }
    })
}

/// The XP skin's progress bar: a sheen along the top, and the fill cut
/// into chunks.
fn chunks(p: &eframe::egui::Painter, r: Rect, pal: &Palette) {
    let sheen = Rect::from_min_size(r.min, vec2(r.width(), r.height() * 0.4));
    p.rect_filled(sheen, 0, Color32::WHITE.gamma_multiply(0.22));
    let mut x = r.left() + 9.0;
    while x < r.right() - 1.0 {
        let gap = Rect::from_x_y_ranges(x..=(x + 2.0).min(r.right()), r.y_range());
        p.rect_filled(gap, 0, pal.well);
        x += 11.0;
    }
}

/// Applies this frame's scroll (zoom around the pointer), pinch, drag
/// (pan) and double-click (reset) to `view`.
fn steer(ui: &Ui, resp: &Response, band: Rect, view: &mut View, ruler: &Ruler, top: u32) {
    if resp.double_clicked() {
        *view = View::default();
        return;
    }
    // Closest zoom: a couple of dozen blocks at the tip.
    let min_span = ruler
        .width(Span {
            from: top.saturating_sub(24),
            to: top,
        })
        .max(1e-9);
    if resp.hovered() {
        let (scroll, pinch) = ui.input(|i| (i.smooth_scroll_delta.y, i.zoom_delta()));
        let factor = (-f64::from(scroll) * 0.004).exp() / f64::from(pinch);
        if (factor - 1.0).abs() > 1e-6
            && let Some(pos) = resp.hover_pos()
        {
            let span = view.span();
            let at = f64::from(((pos.x - band.left()) / band.width()).clamp(0.0, 1.0));
            let anchor = view.lo + span * at;
            let new_span = (span * factor).clamp(min_span, 1.0);
            let lo = (anchor - at * new_span).clamp(0.0, 1.0 - new_span);
            *view = View {
                lo,
                hi: lo + new_span,
            };
            // The page mustn't scroll too.
            ui.ctx()
                .input_mut(|i| i.smooth_scroll_delta = eframe::egui::Vec2::ZERO);
        }
    }
    if resp.dragged() {
        let span = view.span();
        let dx = f64::from(resp.drag_delta().x / band.width()) * span;
        let lo = (view.lo - dx).clamp(0.0, 1.0 - span);
        *view = View { lo, hi: lo + span };
    }
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
        if mx < band.left() || mx > band.right() {
            continue;
        }
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
