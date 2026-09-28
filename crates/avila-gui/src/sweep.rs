//! Blocksweeper: minesweeper on a block template. Somebody slipped bad
//! transactions into the block you're building — flag every one of them
//! and reveal the rest, or you broadcast an invalid block and the
//! network rejects it.
//!
//! One kindness from the real node: while a game is running, each block
//! that lands on your tip flags a bad transaction for you.

use crate::model::thousands;
use crate::pages::Scene;
use crate::prefs::Prefs;
use crate::theme::{self, MONO_MEDIUM, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, Color32, CursorIcon, Key, Layout, Modifiers, Painter, Pos2, Rect, RichText,
    Sense, Stroke, StrokeKind, Ui, UiBuilder, Vec2, pos2, vec2,
};
use std::time::Instant;

/// `(name, cols, rows, bad txs)` — the board grows with the stakes.
pub const TIERS: [(&str, usize, usize, usize); 3] = [
    ("Signet", 9, 9, 10),
    ("Testnet", 16, 16, 40),
    ("Mainnet", 24, 20, 85),
];

const CELL: f32 = 26.0;
const FLOAT_SECS: f32 = 1.4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Board shown, mines not yet placed (first click is always safe).
    Fresh,
    Playing,
    Won,
    Lost,
}

#[derive(Clone, Copy, Default)]
struct Cell {
    mine: bool,
    open: bool,
    flag: bool,
    adj: u8,
    /// The bad tx that was clicked.
    boom: bool,
    /// Flagged by a real block landing while you played.
    gifted: bool,
}

/// Words that rise and fade off the board.
struct Float {
    at: Vec2,
    text: String,
    color: Color32,
    age: f32,
}

pub struct Sweep {
    pub open: bool,
    tier: usize,
    cells: Vec<Cell>,
    cols: usize,
    rows: usize,
    mines: usize,
    state: State,
    flags: usize,
    opened: usize,
    /// Seconds the board has been under play.
    clock: f32,
    /// The pretend height this template is for, when the node knows.
    height: Option<u32>,
    /// The last real block a gift was granted on.
    gifted_at: Option<f64>,
    floats: Vec<Float>,
    seed: u64,
    last: Option<Instant>,
}

impl Default for Sweep {
    fn default() -> Self {
        Self {
            open: false,
            tier: 1,
            cells: Vec::new(),
            cols: 0,
            rows: 0,
            mines: 0,
            state: State::Fresh,
            flags: 0,
            opened: 0,
            clock: 0.0,
            height: None,
            gifted_at: None,
            floats: Vec::new(),
            seed: 0x5EED_5EED,
            last: None,
        }
    }
}

impl Sweep {
    #[must_use]
    pub fn animating(&self) -> bool {
        self.open && (self.state == State::Playing || !self.floats.is_empty())
    }

    /// Back to the shelf.
    pub fn shelve(&mut self) {
        self.open = false;
    }

    /// A fresh board for `tier`; `height` is the block you're building,
    /// when the node knows it.
    pub fn play(&mut self, tier: usize, height: Option<u32>) {
        let (_, cols, rows, mines) = TIERS[tier];
        *self = Self {
            open: true,
            tier,
            cells: vec![Cell::default(); cols * rows],
            cols,
            rows,
            mines,
            seed: self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
            height,
            ..Self::default()
        };
    }

    /// Opens a board mid-game (for screenshots).
    pub fn demo(&mut self) {
        self.play(1, Some(915_233));
        self.state = State::Playing;
        self.clock = 34.0;
        self.place(10); // pretend the first click was at index 10
        // Reveal a carved-out corner and drop a few flags.
        for i in [10, 11, 12, 19, 20, 21, 28, 29, 30, 37, 38, 39] {
            self.reveal(i);
        }
        for i in 0..self.cells.len() {
            if self.cells[i].mine && self.flags < 6 {
                self.cells[i].flag = true;
                self.flags += 1;
            }
        }
        self.say(
            vec2(160.0, 60.0),
            "your node found a block — flagged one",
            Color32::from_rgb(80, 160, 220),
        );
    }

    /// A uniform draw in `[0, 1)` (SplitMix64).
    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1_u64 << 24) as f32
    }

    fn at(&self, col: isize, row: isize) -> Option<usize> {
        if col < 0 || row < 0 || col >= self.cols as isize || row >= self.rows as isize {
            return None;
        }
        Some(row as usize * self.cols + col as usize)
    }

    fn neighbors(&self, i: usize) -> impl Iterator<Item = usize> {
        let (col, row) = (i % self.cols, i / self.cols);
        let mut out = Vec::with_capacity(8);
        for dr in -1..=1 {
            for dc in -1..=1 {
                if dr == 0 && dc == 0 {
                    continue;
                }
                if let Some(n) = self.at(col as isize + dc, row as isize + dr) {
                    out.push(n);
                }
            }
        }
        out.into_iter()
    }

    /// Lays the mines after the first reveal — `safe` and everything
    /// touching it stay clean, so an opener always opens a pocket.
    fn place(&mut self, safe: usize) {
        let keep: Vec<usize> = self.neighbors(safe).chain(std::iter::once(safe)).collect();
        let mut want = self.mines.min(self.cells.len().saturating_sub(keep.len()));
        while want > 0 {
            let i = (self.rand() * self.cells.len() as f32) as usize % self.cells.len();
            if self.cells[i].mine || keep.contains(&i) {
                continue;
            }
            self.cells[i].mine = true;
            want -= 1;
        }
        for i in 0..self.cells.len() {
            self.cells[i].adj = self.neighbors(i).filter(|&n| self.cells[n].mine).count() as u8;
        }
    }

    fn reveal(&mut self, i: usize) {
        if self.cells[i].open || self.cells[i].flag {
            return;
        }
        self.cells[i].open = true;
        self.opened += 1;
        if self.cells[i].adj == 0 && !self.cells[i].mine {
            let mut stack: Vec<usize> = self.neighbors(i).collect();
            while let Some(n) = stack.pop() {
                let c = &mut self.cells[n];
                if c.open || c.flag {
                    continue;
                }
                c.open = true;
                self.opened += 1;
                if c.adj == 0 && !c.mine {
                    stack.extend(self.neighbors(n));
                }
            }
        }
    }

    /// A left click on `i` — reveal, or chord off a satisfied number.
    fn dig(&mut self, i: usize, at: Vec2) {
        if self.state == State::Fresh {
            self.place(i);
            self.state = State::Playing;
        }
        if self.state != State::Playing {
            return;
        }
        let cell = self.cells[i];
        if cell.flag {
            return;
        }
        if cell.open {
            // Chord: a satisfied number reveals its covered neighbors.
            let flagged = self.neighbors(i).filter(|&n| self.cells[n].flag).count();
            if flagged == cell.adj as usize && cell.adj > 0 {
                let cover: Vec<usize> = self
                    .neighbors(i)
                    .filter(|&n| !self.cells[n].open && !self.cells[n].flag)
                    .collect();
                for n in cover {
                    if self.cells[n].mine {
                        return self.trip(n, at);
                    }
                    self.reveal(n);
                }
                self.check_win(at);
            }
            return;
        }
        if cell.mine {
            return self.trip(i, at);
        }
        self.reveal(i);
        self.check_win(at);
    }

    fn trip(&mut self, i: usize, at: Vec2) {
        self.cells[i].open = true;
        self.cells[i].boom = true;
        self.state = State::Lost;
        // Show every bad tx, and the flags that were wrong.
        for c in &mut self.cells {
            if c.mine {
                c.open = true;
            }
        }
        self.say(at, "invalid tx!", Color32::from_rgb(220, 60, 40));
    }

    fn check_win(&mut self, at: Vec2) {
        if self.state == State::Playing && self.opened + self.mines == self.cells.len() {
            self.state = State::Won;
            self.say(at, "block accepted", Color32::from_rgb(60, 170, 90));
        }
    }

    fn flag(&mut self, i: usize, at: Vec2) {
        if self.state != State::Playing {
            return;
        }
        let c = &mut self.cells[i];
        if c.open {
            return;
        }
        c.flag = !c.flag;
        c.gifted = false;
        self.flags = if c.flag {
            self.flags + 1
        } else {
            self.flags.saturating_sub(1)
        };
        if c.flag {
            self.say(
                at - vec2(0.0, 14.0),
                "not in my block",
                Color32::from_rgb(150, 120, 60),
            );
        }
    }

    /// The node's hello: a real block just landed, so it flags one bad
    /// transaction still hiding. `seen` is the tip's session time.
    pub fn gift(&mut self, seen: f64) {
        if self.state != State::Playing || self.gifted_at == Some(seen) {
            return;
        }
        self.gifted_at = Some(seen);
        let hidden: Vec<usize> = (0..self.cells.len())
            .filter(|&i| self.cells[i].mine && !self.cells[i].flag)
            .collect();
        if hidden.is_empty() {
            return;
        }
        let i = hidden[(self.rand() * hidden.len() as f32) as usize % hidden.len()];
        self.cells[i].flag = true;
        self.cells[i].gifted = true;
        self.flags += 1;
        let (col, row) = (i % self.cols, i / self.cols);
        self.say(
            vec2(col as f32 * CELL + CELL / 2.0, row as f32 * CELL - 10.0),
            "your node flagged this one",
            Color32::from_rgb(80, 160, 220),
        );
    }

    fn say(&mut self, at: Vec2, text: impl Into<String>, color: Color32) {
        self.floats.push(Float {
            at,
            text: text.into(),
            color,
            age: 0.0,
        });
    }

    fn step(&mut self, dt: f32) {
        for f in &mut self.floats {
            f.age += dt;
        }
        self.floats.retain(|f| f.age < FLOAT_SECS);
        if self.state == State::Playing {
            self.clock += dt;
        }
    }
}

/// Number colors, closer to the classic set than to the palette — the
/// board is a little artifact of its own.
fn digit_color(n: u8, pal: &Palette) -> Color32 {
    let rgb = Color32::from_rgb;
    match n {
        1 => rgb(56, 96, 220),
        2 => rgb(36, 150, 72),
        3 => rgb(214, 58, 44),
        4 => rgb(124, 62, 170),
        5 => rgb(196, 110, 20),
        6 => rgb(30, 148, 158),
        7 => pal.text,
        _ => pal.muted,
    }
}

fn cell_rect(board: Rect, col: usize, row: usize) -> Rect {
    Rect::from_min_size(
        board.min + vec2(col as f32 * CELL, row as f32 * CELL),
        vec2(CELL, CELL),
    )
}

/// The whole open view: header, board, the hint line.
pub fn show(ui: &mut Ui, s: &Scene, game: &mut Sweep, prefs: &mut Prefs) {
    let pal = s.pal;
    let escape = ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
    let mut leave = escape;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Blocksweeper")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        if let Some(h) = game.height {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("building block {}", thousands(h.into())))
                        .font(mono(12.5))
                        .color(pal.muted),
                );
            });
        }
    });
    ui.add_space(8.0);

    // The board's own header: bad txs left, the clock, the tier picker.
    ui.horizontal(|ui| {
        let left = game.mines.saturating_sub(game.flags);
        ui.label(
            RichText::new(format!("{left} bad txs left"))
                .font(font(theme::MEDIUM, 14.5))
                .color(pal.text),
        );
        ui.add_space(16.0);
        ui.label(
            RichText::new(format!("{:.0}s", game.clock))
                .font(mono(14.5))
                .color(pal.text),
        );
        ui.add_space(16.0);
        for (t, (name, ..)) in TIERS.iter().enumerate() {
            if ui
                .selectable_label(game.tier == t, *name)
                .on_hover_cursor(CursorIcon::PointingHand)
                .clicked()
            {
                game.play(t, game.height);
            }
        }
        if prefs.sweep_best[game.tier] > 0 {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("best {}s", prefs.sweep_best[game.tier]))
                        .font(mono(12.5))
                        .color(pal.muted),
                );
            });
        }
    });
    ui.add_space(10.0);

    board(ui, &pal, game, prefs);
    ui.add_space(10.0);
    ui.label(
        RichText::new(
            "Click to include a transaction; right-click (or F) to flag a bad one. A satisfied number clicks its own neighbors. While you play, each real block your node connects flags one for you. Esc goes back.",
        )
        .size(12.5)
        .color(pal.faint),
    );
    if leave {
        game.shelve();
    }
}

fn board(ui: &mut Ui, pal: &Palette, game: &mut Sweep, prefs: &mut Prefs) {
    let w = game.cols as f32 * CELL;
    let h = game.rows as f32 * CELL;
    let (rect, resp) = ui.allocate_exact_size(vec2(w.max(ui.available_width()), h), Sense::click());
    // Center the board inside what it was given.
    let board = Rect::from_min_size(pos2(rect.center().x - w / 2.0, rect.top()), vec2(w, h));

    let now = Instant::now();
    let dt = game
        .last
        .map_or(0.0, |l| now.duration_since(l).as_secs_f32());
    game.last = Some(now);
    game.step(dt.min(0.1));

    let hover = resp.hover_pos().filter(|p| board.contains(*p)).map(|p| {
        (
            ((p.x - board.left()) / CELL) as usize,
            ((p.y - board.top()) / CELL) as usize,
        )
    });
    if resp.hovered()
        && ui.input(|i| i.key_pressed(Key::F))
        && let Some((c, r)) = hover
    {
        let i = r * game.cols + c;
        let at = cell_rect(board, c, r).center() - board.min;
        game.flag(i, at);
    }
    let (cols, rows) = (game.cols, game.rows);
    let click = |pos: Pos2| {
        let c = ((pos.x - board.left()) / CELL) as usize;
        let r = ((pos.y - board.top()) / CELL) as usize;
        (c.min(cols - 1), r.min(rows - 1))
    };
    if resp.clicked()
        && let Some(pos) = resp.interact_pointer_pos()
        && board.contains(pos)
    {
        let (c, r) = click(pos);
        let i = r * game.cols + c;
        let at = cell_rect(board, c, r).center() - board.min;
        game.dig(i, at);
    }
    if resp.secondary_clicked()
        && let Some(pos) = resp.interact_pointer_pos()
        && board.contains(pos)
    {
        let (c, r) = click(pos);
        let i = r * game.cols + c;
        let at = cell_rect(board, c, r).center() - board.min;
        game.flag(i, at);
    }
    let new_best = game.state == State::Won
        && (prefs.sweep_best[game.tier] == 0
            || (game.clock.ceil() as u32) < prefs.sweep_best[game.tier]);
    if new_best {
        prefs.sweep_best[game.tier] = game.clock.ceil() as u32;
    }

    // ---- draw ----
    let p = ui.painter_at(rect);
    p.rect_filled(board.expand(6.0), 12, pal.well);
    for r in 0..game.rows {
        for c in 0..game.cols {
            let i = r * game.cols + c;
            let cell = game.cells[i];
            let cr = cell_rect(board, c, r).shrink(1.0);
            if cell.open {
                p.rect_filled(cr, 3, pal.canvas.gamma_multiply(0.75));
                if cell.mine {
                    mine(&p, cr, pal, cell.boom);
                } else if cell.adj > 0 {
                    p.text(
                        cr.center(),
                        Align2::CENTER_CENTER,
                        cell.adj.to_string(),
                        font(MONO_MEDIUM, CELL * 0.52),
                        digit_color(cell.adj, pal),
                    );
                }
            } else {
                let hot =
                    hover == Some((c, r)) && matches!(game.state, State::Fresh | State::Playing);
                p.rect_filled(
                    cr,
                    3,
                    if hot {
                        pal.raised.lerp_to_gamma(pal.signal, 0.16)
                    } else {
                        pal.raised
                    },
                );
                p.rect_stroke(cr, 3, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
                if cell.flag {
                    flag(&p, cr, pal, cell.gifted);
                }
            }
        }
    }
    for f in &game.floats {
        let t = f.age / FLOAT_SECS;
        let at = board.min + f.at - vec2(0.0, 26.0 * t);
        let fade = 1.0 - t * t;
        let galley = p.layout_no_wrap(f.text.clone(), font(theme::MEDIUM, 13.5), f.color);
        let pill = Rect::from_center_size(at, galley.size() + vec2(18.0, 10.0));
        p.rect_filled(pill, 8, pal.raised.gamma_multiply(fade));
        p.rect_stroke(
            pill,
            8,
            Stroke::new(1.0, pal.hairline.gamma_multiply(fade)),
            StrokeKind::Inside,
        );
        p.galley(
            at - galley.size() / 2.0,
            galley,
            f.color.gamma_multiply(fade),
        );
    }
    match game.state {
        State::Won | State::Lost => end_card(ui, board, pal, game, new_best),
        _ => {}
    }
}

/// A flag — yours in the signal color, the node's in blue.
fn flag(p: &Painter, cr: Rect, pal: &Palette, gifted: bool) {
    let pole = cr.left() + cr.width() * 0.36;
    let color = if gifted {
        Color32::from_rgb(80, 160, 220)
    } else {
        pal.signal
    };
    p.line_segment(
        [pos2(pole, cr.top() + 5.0), pos2(pole, cr.bottom() - 4.0)],
        Stroke::new(1.6, pal.muted),
    );
    let tri = |a: Pos2, b: Pos2, c: Pos2| {
        p.add(eframe::egui::Shape::convex_polygon(
            vec![a, b, c],
            color,
            Stroke::NONE,
        ))
    };
    tri(
        pos2(pole + 1.0, cr.top() + 4.5),
        pos2(cr.right() - 5.0, cr.top() + 8.0),
        pos2(pole + 1.0, cr.top() + 12.0),
    );
}

/// A bad transaction: a dark coin with a crack.
fn mine(p: &Painter, cr: Rect, pal: &Palette, boom: bool) {
    let c = cr.center();
    if boom {
        p.rect_filled(cr, 3, pal.alert.gamma_multiply(0.25));
    }
    let r = cr.width() * 0.30;
    p.circle_filled(c, r, Color32::from_rgb(74, 48, 32));
    p.circle_stroke(c, r - 1.0, Stroke::new(1.6, pal.alert));
    // The crack.
    p.line_segment(
        [c + vec2(-r * 0.5, -r * 0.6), c + vec2(0.0, 0.0)],
        Stroke::new(1.3, Color32::from_rgb(255, 220, 200)),
    );
    p.line_segment(
        [c + vec2(0.0, 0.0), c + vec2(r * 0.55, -r * 0.2)],
        Stroke::new(1.3, Color32::from_rgb(255, 220, 200)),
    );
    p.line_segment(
        [c + vec2(0.0, 0.0), c + vec2(-r * 0.1, r * 0.7)],
        Stroke::new(1.3, Color32::from_rgb(255, 220, 200)),
    );
}

/// The verdict, in the board's middle — with the way back in.
fn end_card(ui: &mut Ui, board: Rect, pal: &Palette, game: &mut Sweep, new_best: bool) {
    let r = Rect::from_center_size(board.center(), vec2(360.0, 214.0));
    let p = ui.painter_at(board);
    p.rect_filled(board.expand(6.0), 12, pal.well.gamma_multiply(0.72));
    p.rect_filled(
        r.translate(vec2(0.0, 3.0)),
        14,
        Color32::from_black_alpha(30),
    );
    p.rect_filled(r, 14, pal.raised);
    p.rect_stroke(r, 14, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
    let (title, body, color) = match game.state {
        State::Won => {
            let t = game.clock.ceil() as u32;
            let note = if new_best {
                format!("cleared in {t}s — a new best")
            } else {
                format!("cleared in {t}s")
            };
            (
                "Block accepted",
                format!("{} · relayed to your peers", note),
                pal.signal_text,
            )
        }
        _ => (
            "Rejected",
            "You broadcast an invalid block.\nThe network dropped it — and so did your subsidy."
                .to_owned(),
            pal.alert,
        ),
    };
    p.text(
        r.center_top() + vec2(0.0, 30.0),
        Align2::CENTER_CENTER,
        title,
        font(theme::TITLE, 26.0),
        color,
    );
    p.text(
        r.center_top() + vec2(0.0, 66.0),
        Align2::CENTER_CENTER,
        body,
        theme::body(13.0),
        pal.muted,
    );
    let row_rect = Rect::from_min_max(
        r.left_bottom() + vec2(24.0, -56.0),
        r.right_bottom() - vec2(24.0, 18.0),
    );
    let mut row = ui.new_child(
        UiBuilder::new()
            .max_rect(row_rect)
            .layout(Layout::left_to_right(Align::Center)),
    );
    if widgets::button(&mut row, "Another template", Button::Primary).clicked() {
        game.play(game.tier, game.height);
    }
    row.add_space(8.0);
    if widgets::button(&mut row, "Back to the toybox", Button::Quiet).clicked() {
        game.shelve();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn playing() -> Sweep {
        let mut g = Sweep::default();
        g.play(0, None);
        g.state = State::Playing;
        g.place(0);
        g
    }

    #[test]
    fn the_first_click_is_always_safe() {
        let mut g = Sweep::default();
        g.play(1, None);
        let first = 137;
        g.dig(first, Vec2::ZERO);
        assert!(g.cells[first].open);
        assert!(!g.cells[first].mine);
        assert!(g.state == State::Playing || g.state == State::Won);
        assert_eq!(g.cells.iter().filter(|c| c.mine).count(), g.mines);
    }

    #[test]
    fn a_mine_ends_the_block() {
        let mut g = playing();
        let m = (0..g.cells.len()).find(|&i| g.cells[i].mine).unwrap_or(1);
        g.dig(m, Vec2::ZERO);
        assert_eq!(g.state, State::Lost);
        assert!(g.cells[m].boom);
    }

    #[test]
    fn flagging_every_mine_and_opening_the_rest_wins() {
        let mut g = playing();
        for i in 0..g.cells.len() {
            if g.cells[i].mine {
                if !g.cells[i].flag {
                    g.flag(i, Vec2::ZERO);
                }
            } else if !g.cells[i].open {
                g.reveal(i);
            }
        }
        g.check_win(Vec2::ZERO);
        assert_eq!(g.state, State::Won);
    }

    #[test]
    fn a_new_block_gifts_a_flag() {
        let mut g = playing();
        let before = g.flags;
        g.gift(10.0);
        assert_eq!(g.flags, before + 1);
        // Once per block.
        g.gift(10.0);
        assert_eq!(g.flags, before + 1);
        g.gift(11.0);
        assert_eq!(g.flags, before + 2);
    }
}
