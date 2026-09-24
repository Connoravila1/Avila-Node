//! Small painters every screen shares. Buttons and controls are drawn by
//! hand so they carry the palette exactly, focus ring included.

use crate::model::work_zeros;
use crate::theme::{self, Palette, font, mono};
use eframe::egui::{
    self, Color32, CornerRadius, CursorIcon, Mesh, Painter, Pos2, Rect, Response, RichText, Sense,
    Shape, Stroke, StrokeKind, TextFormat, Ui, Vec2, pos2, text::LayoutJob, vec2,
};

// ---------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------

/// A quiet label over a value or a group of controls.
pub fn label(ui: &mut Ui, text: &str) -> Response {
    let pal = Palette::of(ui.ctx());
    ui.label(
        RichText::new(text)
            .font(font(theme::MEDIUM, 12.5))
            .color(pal.muted),
    )
}

/// A section heading with an optional note beside it, over a hairline.
pub fn section(ui: &mut Ui, title: &str, note: Option<&str>) {
    let pal = Palette::of(ui.ctx());
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(title)
                .font(font(theme::TITLE, 19.0))
                .color(pal.text),
        );
        if let Some(note) = note {
            ui.add_space(4.0);
            ui.label(RichText::new(note).size(13.0).color(pal.muted));
        }
    });
    hairline(ui);
    ui.add_space(6.0);
}

pub fn hairline(ui: &mut Ui) {
    let pal = Palette::of(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        Stroke::new(1.0, pal.hairline),
    );
}

/// A block hash with its leading zeros dimmed — the proof of work made
/// visible. `keep` limits how many digits after the zeros are shown.
#[must_use]
pub fn hash_job(hash: &str, size: f32, pal: &Palette, keep: Option<usize>) -> LayoutJob {
    let zeros = work_zeros(hash).min(hash.len());
    let rest = &hash[zeros..];
    let rest = match keep {
        Some(n) if rest.len() > n => format!("{}…", &rest[..n]),
        _ => rest.to_owned(),
    };
    let mut job = LayoutJob::default();
    job.append(
        &hash[..zeros],
        0.0,
        TextFormat::simple(mono(size), pal.faint),
    );
    job.append(&rest, 0.0, TextFormat::simple(mono(size), pal.text));
    job
}

/// A hash as a selectable label (click to copy).
pub fn hash_label(ui: &mut Ui, hash: &str, size: f32, keep: Option<usize>) -> Response {
    let pal = Palette::of(ui.ctx());
    let resp = ui
        .add(egui::Label::new(hash_job(hash, size, &pal, keep)).sense(Sense::click()))
        .on_hover_cursor(CursorIcon::Copy)
        .on_hover_text("Copy the full hash");
    if resp.clicked() {
        ui.ctx().copy_text(hash.to_owned());
    }
    resp.context_menu(|ui| {
        if ui.button("Copy hash").clicked() {
            ui.ctx().copy_text(hash.to_owned());
            ui.close();
        }
    });
    resp
}

// ---------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The one main action on screen: ink on ash.
    Primary,
    /// Everything else: an outline.
    Quiet,
}

pub fn button(ui: &mut Ui, text: &str, kind: Kind) -> Response {
    let pal = Palette::of(ui.ctx());
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        font(theme::MEDIUM, 13.5),
        Color32::PLACEHOLDER,
    );
    let size = vec2(galley.size().x + 30.0, 34.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let hot = resp.hovered() || resp.has_focus();
        let down = resp.is_pointer_button_down_on();
        let (fill, fg, stroke) = match kind {
            Kind::Primary => {
                let lift = if down {
                    0.22
                } else if hot {
                    0.12
                } else {
                    0.0
                };
                (
                    pal.text.lerp_to_gamma(pal.canvas, lift),
                    pal.canvas,
                    Stroke::NONE,
                )
            }
            Kind::Quiet => (
                if down {
                    pal.hairline
                } else if hot {
                    pal.well
                } else {
                    Color32::TRANSPARENT
                },
                pal.text,
                Stroke::new(1.0, if hot { pal.faint } else { pal.hairline }),
            ),
        };
        let p = ui.painter();
        p.rect(rect, 7, fill, stroke, StrokeKind::Inside);
        p.galley(rect.center() - galley.size() / 2.0, galley, fg);
        focus_ring(ui, &resp, rect, 9);
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// A row of mutually exclusive choices. Returns whether it changed.
pub fn segmented<T: Copy + PartialEq>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let pal = Palette::of(ui.ctx());
    let f = font(theme::MEDIUM, 13.0);
    let galleys: Vec<_> = options
        .iter()
        .map(|(_, text)| {
            ui.painter()
                .layout_no_wrap((*text).to_owned(), f.clone(), Color32::PLACEHOLDER)
        })
        .collect();
    let pad = 14.0;
    let widths: Vec<f32> = galleys.iter().map(|g| g.size().x + pad * 2.0).collect();
    let total = vec2(widths.iter().sum::<f32>() + 6.0, 34.0);
    let (track, _) = ui.allocate_exact_size(total, Sense::hover());
    ui.painter().rect_filled(track, 8, pal.well);
    let mut changed = false;
    let mut x = track.left() + 3.0;
    for ((option, galley), w) in options.iter().zip(galleys).zip(widths) {
        let rect = Rect::from_min_size(pos2(x, track.top() + 3.0), vec2(w, track.height() - 6.0));
        x += w;
        let id = ui.id().with(("segment", x as i32, track.top() as i32));
        let resp = ui
            .interact(rect, id, Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        let selected = option.0 == *value;
        if resp.clicked() && !selected {
            *value = option.0;
            changed = true;
        }
        let p = ui.painter();
        if selected {
            p.rect(
                rect,
                6,
                pal.raised,
                Stroke::new(1.0, pal.hairline),
                StrokeKind::Inside,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, 6, pal.hairline.gamma_multiply(0.5));
        }
        let color = if selected { pal.text } else { pal.muted };
        p.galley(rect.center() - galley.size() / 2.0, galley, color);
        focus_ring(ui, &resp, rect, 8);
    }
    changed
}

fn focus_ring(ui: &Ui, resp: &Response, rect: Rect, radius: u8) {
    if resp.has_focus() {
        let pal = Palette::of(ui.ctx());
        ui.painter().rect_stroke(
            rect.expand(2.5),
            radius,
            Stroke::new(1.5, pal.signal_text),
            StrokeKind::Outside,
        );
    }
}

/// A reading like `3 h 12 min ago` or `23,266 transactions`: numerals in
/// the display face, words small beside them, all on one baseline.
pub fn figure(ui: &mut Ui, value: &str, unit: &str, size: f32) -> Response {
    let ink = Palette::of(ui.ctx()).text;
    figure_in(ui, value, unit, size, ink)
}

/// [`figure`] with its numerals in `ink`.
pub fn figure_in(ui: &mut Ui, value: &str, unit: &str, size: f32, ink: Color32) -> Response {
    let pal = Palette::of(ui.ctx());
    let numeral = |c: char| c.is_ascii_digit() || ",.%—".contains(c);
    let any_numeral = value.chars().any(numeral);
    let mut runs: Vec<(String, bool)> = Vec::new();
    for c in value.chars() {
        let big = !any_numeral || numeral(c) || (c == ' ' && runs.last().is_some_and(|r| r.1));
        match runs.last_mut() {
            Some((text, b)) if *b == big => text.push(c),
            _ => runs.push((c.to_string(), big)),
        }
    }
    if !unit.is_empty() {
        runs.push((format!(" {unit}"), false));
    }
    let galleys: Vec<_> = runs
        .into_iter()
        .map(|(text, big)| {
            let (f, color) = if big {
                (font(theme::DISPLAY, size), ink)
            } else {
                (
                    egui::FontId::proportional((size * 0.4).max(13.0)),
                    pal.muted,
                )
            };
            ui.painter().layout_no_wrap(text, f, color)
        })
        .collect();
    let baseline = |g: &egui::Galley| {
        g.rows
            .first()
            .and_then(|r| r.row.glyphs.first())
            .map_or(g.size().y, |glyph| glyph.pos.y)
    };
    let top = galleys.iter().map(|g| baseline(g)).fold(0.0, f32::max);
    let width: f32 = galleys.iter().map(|g| g.size().x).sum();
    let height = galleys
        .iter()
        .map(|g| top - baseline(g) + g.size().y)
        .fold(0.0, f32::max);
    let (rect, resp) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let mut x = rect.left();
    for g in galleys {
        let y = rect.top() + top - baseline(&g);
        let w = g.size().x;
        ui.painter().galley(pos2(x, y), g, pal.text);
        x += w;
    }
    resp
}

/// An invitation to act where there's nothing to show yet.
pub fn empty(ui: &mut Ui, title: &str, body: &str) {
    let pal = Palette::of(ui.ctx());
    ui.add_space(8.0);
    ui.label(
        RichText::new(title)
            .font(font(theme::TITLE, 22.0))
            .color(pal.text),
    );
    ui.add_space(2.0);
    ui.label(RichText::new(body).size(14.0).color(pal.muted));
    ui.add_space(12.0);
}

// ---------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------

/// Diagonal hatching across `rect`. Stripes are anchored to the screen,
/// not the rect, so they stay put while the rect's edges move.
pub fn hatch(painter: &Painter, rect: Rect, color: Color32, gap: f32, width: f32) {
    if rect.width() <= 0.0 {
        return;
    }
    let p = painter.with_clip_rect(rect.intersect(painter.clip_rect()));
    let h = rect.height();
    let start = rect.left() - h;
    let mut x = start - start.rem_euclid(gap);
    while x < rect.right() {
        p.line_segment(
            [pos2(x, rect.bottom()), pos2(x + h, rect.top())],
            Stroke::new(width, color),
        );
        x += gap;
    }
}

/// A sparkline of `values` (oldest first) with a soft area beneath it.
/// Describes the sample at an index of a sparkline's series, on hover.
pub type Readout<'a> = &'a dyn Fn(usize) -> String;

pub fn sparkline(
    ui: &mut Ui,
    values: &[f64],
    size: Vec2,
    color: Color32,
    readout: Option<Readout>,
) -> Response {
    let pal = Palette::of(ui.ctx());
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    let p = ui.painter();
    p.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, pal.hairline),
    );
    let max = rect.width().max(2.0) as usize;
    let shown = downsample(values, max);
    if shown.len() < 2 {
        return resp;
    }
    let lo = shown.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = shown.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = hi - lo;
    let inner = rect.shrink2(vec2(0.0, 3.0));
    let n = shown.len() - 1;
    let points: Vec<Pos2> = shown
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = inner.left() + inner.width() * i as f32 / n as f32;
            let f = if span > 0.0 {
                ((v - lo) / span) as f32
            } else {
                0.5
            };
            pos2(x, inner.bottom() - f * inner.height())
        })
        .collect();
    let mut area = Mesh::default();
    let under = color.gamma_multiply(if pal.dark { 0.16 } else { 0.12 });
    for (i, pt) in points.iter().enumerate() {
        area.colored_vertex(*pt, under);
        area.colored_vertex(pos2(pt.x, rect.bottom()), under.gamma_multiply(0.0));
        if i > 0 {
            let k = (i * 2) as u32;
            area.add_triangle(k - 2, k - 1, k);
            area.add_triangle(k - 1, k, k + 1);
        }
    }
    p.add(Shape::mesh(area));
    let last = points[n];
    // The sample under the pointer: a hairline, a dot, and its reading.
    let hovered = resp.hover_pos().map(|pos| {
        let f = ((pos.x - inner.left()) / inner.width()).clamp(0.0, 1.0);
        (f * n as f32).round() as usize
    });
    if let Some(i) = hovered {
        p.vline(points[i].x, rect.y_range(), Stroke::new(1.0, pal.faint));
    }
    p.add(Shape::line(points.clone(), Stroke::new(1.5, color)));
    p.circle_filled(last, 2.5, color);
    match (hovered, readout) {
        (Some(i), Some(describe)) => {
            p.circle_filled(points[i], 3.5, color);
            // Downsampled index back to the series' own.
            let original = if values.len() <= max {
                i
            } else {
                (i + 1) * values.len() / max - 1
            };
            resp.on_hover_text_at_pointer(describe(original))
        }
        _ => resp,
    }
}

/// Keeps the last value of each of `max` buckets.
fn downsample(values: &[f64], max: usize) -> Vec<f64> {
    if values.len() <= max || max < 2 {
        return values.to_vec();
    }
    (0..max)
        .map(|i| values[(i + 1) * values.len() / max - 1])
        .collect()
}

/// A column of a painted table.
pub struct Col {
    pub title: &'static str,
    /// Fixed width; `None` takes whatever is left.
    pub width: Option<f32>,
    /// Numbers align right.
    pub right: bool,
}

/// Lays the columns across the available width, paints their titles,
/// and returns each column's x range (inset by the cell padding).
/// Lays the columns across the available width, paints their titles
/// (with an arrow on the sorted one: up ascending, down descending), and
/// returns each column's x range (inset by the cell padding) and the
/// index of a title clicked this frame.
pub fn table_header(
    ui: &mut Ui,
    cols: &[Col],
    sorted: Option<(usize, bool)>,
) -> (Vec<egui::Rangef>, Option<usize>) {
    let pal = Palette::of(ui.ctx());
    let width = ui.available_width();
    let fixed: f32 = cols.iter().filter_map(|c| c.width).sum();
    let flex = cols.iter().filter(|c| c.width.is_none()).count().max(1) as f32;
    let spare = ((width - fixed) / flex).max(0.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, 28.0), Sense::hover());
    let mut x = rect.left();
    let mut ranges = Vec::with_capacity(cols.len());
    let mut clicked = None;
    for (i, c) in cols.iter().enumerate() {
        let w = c.width.unwrap_or(spare);
        let whole = Rect::from_x_y_ranges(x..=(x + w), rect.y_range());
        let cell = egui::Rangef::new(x + 10.0, x + w - 10.0);
        x += w;
        let resp = ui
            .interact(whole, ui.id().with(("column", i)), Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if resp.clicked() {
            clicked = Some(i);
        }
        let on = sorted.filter(|(col, _)| *col == i);
        let color = if on.is_some() || resp.hovered() {
            pal.text
        } else {
            pal.muted
        };
        let galley = fit(
            ui.painter(),
            c.title.to_owned(),
            font(theme::MEDIUM, 12.0),
            color,
            cell.span() - 12.0,
        );
        let title_w = galley.size().x;
        put(ui.painter(), cell, rect.center().y, galley, c.right);
        if let Some((_, descending)) = on {
            // A small triangle beside the title.
            let tx = if c.right {
                cell.max - title_w - 9.0
            } else {
                cell.min + title_w + 9.0
            };
            let cy = rect.center().y;
            let pts = if descending {
                vec![
                    pos2(tx - 3.5, cy - 2.0),
                    pos2(tx + 3.5, cy - 2.0),
                    pos2(tx, cy + 2.5),
                ]
            } else {
                vec![
                    pos2(tx - 3.5, cy + 2.0),
                    pos2(tx + 3.5, cy + 2.0),
                    pos2(tx, cy - 2.5),
                ]
            };
            ui.painter()
                .add(Shape::convex_polygon(pts, pal.text, Stroke::NONE));
        }
        ranges.push(cell);
    }
    ui.painter().hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, pal.hairline),
    );
    (ranges, clicked)
}

/// A clickable table row with a hairline under it; the selected row
/// carries a mark at its left edge.
pub fn table_row(ui: &mut Ui, height: f32, selected: bool) -> (Rect, Response) {
    let pal = Palette::of(ui.ctx());
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    if selected {
        ui.painter().rect_filled(rect, 0, pal.well);
        ui.painter().vline(
            rect.left() + 1.0,
            rect.y_range(),
            Stroke::new(2.0, pal.text),
        );
    } else if resp.hovered() {
        ui.painter()
            .rect_filled(rect, 0, pal.well.gamma_multiply(0.6));
    }
    ui.painter().hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, pal.hairline.gamma_multiply(0.6)),
    );
    (rect, resp.on_hover_cursor(CursorIcon::PointingHand))
}

/// Single-line text that fits `width`, elided with an ellipsis.
pub fn fit(
    painter: &Painter,
    text: String,
    font_id: egui::FontId,
    color: Color32,
    width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::simple_singleline(text, font_id, color);
    job.wrap = egui::text::TextWrapping::truncate_at_width(width.max(1.0));
    painter.layout_job(job)
}

/// Paints `galley` in a cell, vertically centred on `y`.
pub fn put(
    painter: &Painter,
    cell: egui::Rangef,
    y: f32,
    galley: std::sync::Arc<egui::Galley>,
    right: bool,
) {
    let x = if right {
        cell.max - galley.size().x
    } else {
        cell.min
    };
    painter.galley(
        pos2(x, y - galley.size().y / 2.0),
        galley,
        Color32::PLACEHOLDER,
    );
}

/// Corner radii for a segment that may touch either end of a band.
#[must_use]
pub fn end_radius(r: u8, left: bool, right: bool) -> CornerRadius {
    CornerRadius {
        nw: if left { r } else { 0 },
        sw: if left { r } else { 0 },
        ne: if right { r } else { 0 },
        se: if right { r } else { 0 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downsampling_keeps_the_newest_value() {
        let v: Vec<f64> = (0..900).map(f64::from).collect();
        let d = downsample(&v, 200);
        assert_eq!(d.len(), 200);
        assert_eq!(d.last(), Some(&899.0));
        assert_eq!(downsample(&v[..10], 200).len(), 10);
    }

    #[test]
    fn hash_jobs_split_zeros_from_the_rest() {
        let job = hash_job(
            "0000000000000000000108970acb",
            12.0,
            &Palette::DARK,
            Some(4),
        );
        assert_eq!(job.text, format!("{}1089…", "0".repeat(19)));
        assert_eq!(job.sections.len(), 2);
    }
}
