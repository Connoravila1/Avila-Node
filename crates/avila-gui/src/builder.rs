//! Block Builder: pack the mempool. Transactions fall with a feerate
//! on them; when a row fills, the block is sealed and its fees are
//! yours. The stack reaching the top means the mempool won.

use crate::model::thousands;
use crate::prefs::Prefs;
use crate::theme::{self, MONO_MEDIUM, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, Color32, Key, Layout, Modifiers, Painter, Pos2, Rect, RichText, Sense, Stroke,
    StrokeKind, Ui, pos2, vec2,
};
use std::time::Instant;

const COLS: usize = 10;
const ROWS: usize = 20;
const CELL: f32 = 24.0;
const FLOAT_SECS: f32 = 1.4;
/// A cell counts as this many vbytes when the block is sealed.
const VBYTES: u64 = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Playing,
    Paused,
    Over,
}

/// The seven transaction shapes, as cell offsets in a 3×3 (4×4 for the
/// coinbase-sized one) box.
const PIECES: [(&[(i32, i32)], usize); 7] = [
    (&[(0, 1), (1, 1), (2, 1), (3, 1)], 4), // the sweeping four-op return
    (&[(1, 0), (0, 1), (1, 1), (2, 1)], 3), // T
    (&[(1, 0), (2, 0), (0, 1), (1, 1)], 3), // S
    (&[(0, 0), (1, 0), (1, 1), (2, 1)], 3), // Z
    (&[(0, 0), (0, 1), (1, 1), (2, 1)], 3), // J
    (&[(2, 0), (0, 1), (1, 1), (2, 1)], 3), // L
    (&[(1, 1), (2, 1), (1, 2), (2, 2)], 4), // O — the multisig square
];

#[derive(Clone, Copy)]
struct Piece {
    kind: usize,
    rot: u8,
    at: (i32, i32),
    /// Its feerate, sat/vB — color and worth.
    fee: u8,
}

impl Piece {
    fn cells(&self) -> [(i32, i32); 4] {
        let (base, n) = PIECES[self.kind];
        let mut out = [(0, 0); 4];
        for (i, &(x, y)) in base.iter().enumerate() {
            let (mut cx, mut cy) = (x, y);
            for _ in 0..self.rot {
                (cx, cy) = (n as i32 - 1 - cy, cx);
            }
            out[i] = (self.at.0 + cx, self.at.1 + cy);
        }
        out
    }
}

struct Float {
    at: Pos2,
    text: String,
    color: Color32,
    age: f32,
}

pub struct Builder {
    pub open: bool,
    state: State,
    /// fee+1 per filled cell, 0 when empty.
    grid: [[u8; COLS]; ROWS],
    cur: Piece,
    next: Piece,
    bag: Vec<usize>,
    score: u64,
    sealed: u32,
    /// Rows mid-flash after sealing, with their age.
    flash: Vec<(usize, f32)>,
    fall: f32,
    floats: Vec<Float>,
    new_best: bool,
    seed: u64,
    last: Option<Instant>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            open: false,
            state: State::Playing,
            grid: [[0; COLS]; ROWS],
            cur: Piece {
                kind: 0,
                rot: 0,
                at: (4, 0),
                fee: 1,
            },
            next: Piece {
                kind: 1,
                rot: 0,
                at: (0, 0),
                fee: 1,
            },
            bag: Vec::new(),
            score: 0,
            sealed: 0,
            flash: Vec::new(),
            fall: 0.0,
            floats: Vec::new(),
            new_best: false,
            seed: 0xB10C_55EED,
            last: None,
        }
    }
}

impl Builder {
    #[must_use]
    pub fn animating(&self) -> bool {
        self.open && (self.state == State::Playing || !self.floats.is_empty())
    }

    pub fn shelve(&mut self) {
        self.open = false;
    }

    pub fn play(&mut self) {
        let seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        *self = Self {
            open: true,
            seed,
            ..Self::default()
        };
        self.next = self.draw_piece();
        self.cur = self.draw_piece();
    }

    /// A mid-game pose, for screenshots.
    pub fn demo(&mut self) {
        self.play();
        self.score = 2_841_500;
        self.sealed = 11;
        // A believable mid-stack: uneven columns, a couple of gaps.
        let plan: &[&[u8]] = &[
            &[5, 6, 7, 8, 9],
            &[4, 5, 6, 7],
            &[3, 4, 6, 7, 8],
            &[2, 3, 5, 6],
            &[1, 2, 4, 5, 6, 8],
            &[0, 1, 3, 4],
            &[0, 2, 3, 5],
            &[1, 2, 4],
            &[0, 1, 6],
            &[0, 3],
            &[1],
        ];
        for (depth, cols) in plan.iter().enumerate() {
            for &c in cols.iter() {
                let r = ROWS - 1 - depth;
                self.grid[r][c as usize] = 1 + ((depth * 7 + c as usize) % 90) as u8;
            }
        }
    }

    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1_u64 << 24) as f32
    }

    /// The next tx off the pile — a 7-bag, like every decent mempool.
    fn draw_piece(&mut self) -> Piece {
        if self.bag.is_empty() {
            self.bag = (0..7).collect();
            // Fisher–Yates on our own stream.
            for i in (1..7).rev() {
                let j = (self.rand() * (i + 1) as f32) as usize;
                self.bag.swap(i, j);
            }
        }
        let kind = self.bag.pop().unwrap_or(0);
        Piece {
            kind,
            rot: 0,
            at: (4, 0),
            fee: 1 + (self.rand() * self.rand() * 98.0) as u8,
        }
    }

    fn fits(&self, cells: &[(i32, i32); 4]) -> bool {
        cells.iter().all(|&(x, y)| {
            (0..COLS as i32).contains(&x)
                && y < ROWS as i32
                && (y < 0 || self.grid[y as usize][x as usize] == 0)
        })
    }

    /// Pop the coming piece; top out if it can't even spawn.
    fn advance(&mut self) {
        self.cur = Piece {
            kind: self.next.kind,
            rot: 0,
            at: (4, 0),
            fee: self.next.fee,
        };
        self.next = self.draw_piece();
        if !self.fits(&self.cur.cells()) {
            self.state = State::Over;
        }
    }

    /// Lock the current piece where it sits, seal any full rows.
    fn lock(&mut self, origin: Pos2) {
        let cells = self.cur.cells();
        for (x, y) in cells {
            if y < 0 {
                self.state = State::Over;
                return;
            }
            self.grid[y as usize][x as usize] = self.cur.fee.saturating_add(1);
        }
        let mut kept = 0;
        let mut gain = 0_u64;
        for r in 0..ROWS {
            if self.grid[r].iter().all(|&c| c > 0) {
                gain += self.grid[r]
                    .iter()
                    .map(|&c| u64::from(c.saturating_sub(1)) * VBYTES)
                    .sum::<u64>();
                kept += 1;
                self.flash.push((r, 0.0));
                self.grid[r] = [0; COLS];
            }
        }
        if kept > 0 {
            // Rows above each sealed one slide down together.
            let mut write = ROWS;
            for r in (0..ROWS).rev() {
                if self.flash.iter().any(|&(f, _)| f == r) {
                    continue;
                }
                write -= 1;
                self.grid[write] = self.grid[r];
            }
            for r in 0..write {
                self.grid[r] = [0; COLS];
            }
            self.flash.clear();
            self.flash.push((usize::MAX, 0.0));
            self.score += gain;
            self.sealed += kept as u32;
            self.say(
                origin + vec2(CELL * 5.0, 60.0),
                format!("block sealed — +{} sats in fees", thousands(gain)),
                Color32::from_rgb(60, 170, 90),
            );
        }
        self.advance();
    }

    fn say(&mut self, at: Pos2, text: impl Into<String>, color: Color32) {
        self.floats.push(Float {
            at,
            text: text.into(),
            color,
            age: 0.0,
        });
    }

    fn rotate(&mut self) {
        // A one-cell nudge stands in for real wall kicks.
        for kick in [0, -1, 1, -2, 2] {
            let p = Piece {
                kind: self.cur.kind,
                rot: (self.cur.rot + 1) % 4,
                at: (self.cur.at.0 + kick, self.cur.at.1),
                fee: self.cur.fee,
            };
            if self.fits(&p.cells()) {
                self.cur = p;
                return;
            }
        }
    }

    fn shift(&mut self, dx: i32) {
        let p = Piece {
            at: (self.cur.at.0 + dx, self.cur.at.1),
            ..self.cur
        };
        if self.fits(&p.cells()) {
            self.cur = p;
        }
    }

    /// Gravity and the soft drop share this: one row down, or lock.
    fn down(&mut self, origin: Pos2) {
        let p = Piece {
            at: (self.cur.at.0, self.cur.at.1 + 1),
            ..self.cur
        };
        if self.fits(&p.cells()) {
            self.cur = p;
        } else {
            self.lock(origin);
        }
    }

    fn hard_drop(&mut self, origin: Pos2) {
        self.cur.at.1 = self.landing();
        self.lock(origin);
    }

    /// Where the piece rests if it falls — the ghost's row.
    fn landing(&self) -> i32 {
        let mut y = self.cur.at.1;
        loop {
            let c = Piece {
                kind: self.cur.kind,
                rot: self.cur.rot,
                at: (self.cur.at.0, y + 1),
                fee: self.cur.fee,
            };
            if !self.fits(&c.cells()) {
                return y;
            }
            y += 1;
        }
    }

    fn step(&mut self, dt: f32, origin: Pos2, soft: bool) {
        for f in &mut self.floats {
            f.age += dt;
        }
        self.floats.retain(|f| f.age < FLOAT_SECS);
        for (_, age) in &mut self.flash {
            *age += dt;
        }
        self.flash.retain(|&(_, a)| a < 0.5);
        if self.state != State::Playing {
            return;
        }
        let pace = ((0.62 - 0.03 * self.sealed as f32).max(0.12)) / if soft { 8.0 } else { 1.0 };
        self.fall += dt;
        while self.fall >= pace && self.state == State::Playing {
            self.fall -= pace;
            self.down(origin);
        }
    }
}

/// A cell's fill: deeper orange the richer the feerate.
fn fee_fill(fee: u8, pal: &Palette) -> Color32 {
    let t = (f32::from(fee) / 99.0).clamp(0.0, 1.0);
    pal.signal.lerp_to_gamma(pal.well, 1.0 - t * 0.9 - 0.06)
}

/// The whole open view: header, the well, the hint line.
pub fn show(ui: &mut Ui, pal: &Palette, game: &mut Builder, prefs: &mut Prefs) {
    let (space, escape) = ui.input_mut(|i| {
        (
            i.consume_key(Modifiers::NONE, Key::Space),
            i.consume_key(Modifiers::NONE, Key::Escape),
        )
    });
    let mut leave = escape;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Block Builder")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if game.state == State::Paused
                && widgets::button(ui, "Resume", Button::Primary).clicked()
            {
                game.state = State::Playing;
            }
        });
    });
    ui.add_space(12.0);

    let w = COLS as f32 * CELL;
    let h = ROWS as f32 * CELL;
    let (rect, _resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), h + 12.0), Sense::hover());
    let board = Rect::from_min_size(
        pos2(rect.center().x - (w + 150.0) / 2.0, rect.top() + 6.0),
        vec2(w, h),
    );
    let side = Rect::from_min_max(
        pos2(board.right() + 18.0, board.top()),
        pos2(rect.right().min(board.right() + 150.0), board.bottom()),
    );
    let origin = board.min;

    let keys = ui.input(|i| {
        let mut m = 0;
        if i.key_pressed(Key::ArrowLeft) || i.key_pressed(Key::A) {
            m = -1;
        }
        if i.key_pressed(Key::ArrowRight) || i.key_pressed(Key::D) {
            m = 1;
        }
        (
            m,
            i.key_down(Key::ArrowDown) || i.key_down(Key::S),
            i.key_pressed(Key::ArrowUp) || i.key_pressed(Key::W) || i.key_pressed(Key::X),
        )
    });
    if game.state == State::Playing {
        if keys.0 != 0 {
            game.shift(keys.0);
        }
        if keys.2 {
            game.rotate();
        }
    }
    match game.state {
        State::Playing if space => game.hard_drop(origin),
        State::Paused if space => game.state = State::Playing,
        State::Over if space => game.play(),
        _ => {}
    }

    let now = Instant::now();
    let dt = game
        .last
        .map_or(0.0, |l| now.duration_since(l).as_secs_f32());
    game.last = Some(now);
    if dt > 0.5 && game.state == State::Playing {
        game.state = State::Paused;
    }
    game.step(dt.min(0.1), origin, keys.1);
    if game.state == State::Over && game.score > prefs.builder_best {
        prefs.builder_best = game.score;
        game.new_best = true;
    }

    let p = ui.painter_at(rect);
    draw(&p, board, side, pal, game, prefs.builder_best);
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "← → move · ↑ rotates · ↓ soft-drops · Space hard-drops · Esc for the toybox. Deeper orange pays more. Fill a row to seal the block.",
        )
        .size(12.5)
        .color(pal.faint),
    );
    if leave {
        game.shelve();
    }
}

fn draw(p: &Painter, board: Rect, side: Rect, pal: &Palette, game: &Builder, best: u64) {
    p.rect_filled(board.expand(6.0), 12, pal.well);
    for c in 1..COLS {
        p.vline(
            board.left() + c as f32 * CELL,
            board.y_range(),
            Stroke::new(1.0, pal.hairline.gamma_multiply(0.35)),
        );
    }
    for r in 1..ROWS {
        p.hline(
            board.x_range(),
            board.top() + r as f32 * CELL,
            Stroke::new(1.0, pal.hairline.gamma_multiply(0.35)),
        );
    }
    // The sealing flash runs the board's width.
    for &(r, age) in &game.flash {
        let row = if r == usize::MAX { ROWS / 2 } else { r };
        let a = (1.0 - age / 0.5).clamp(0.0, 1.0);
        p.rect_filled(
            Rect::from_min_size(
                board.min + vec2(0.0, row as f32 * CELL),
                vec2(board.width(), CELL),
            ),
            0,
            Color32::WHITE.gamma_multiply(0.35 * a),
        );
    }
    for (r, row) in game.grid.iter().enumerate() {
        for (c, &fee) in row.iter().enumerate() {
            if fee == 0 {
                continue;
            }
            cell(
                p,
                board.min + vec2(c as f32 * CELL, r as f32 * CELL),
                fee - 1,
                pal,
            );
        }
    }
    // The ghost: where this tx lands.
    let drop = game.landing() - game.cur.at.1;
    if drop > 0 {
        for (x, y) in game.cur.cells() {
            let gy = y + drop;
            if gy >= 0 {
                let r = Rect::from_min_size(
                    board.min + vec2(x as f32 * CELL, gy as f32 * CELL) + vec2(3.0, 3.0),
                    vec2(CELL - 6.0, CELL - 6.0),
                );
                p.rect_stroke(
                    r,
                    3,
                    Stroke::new(1.2, fee_fill(game.cur.fee, pal).gamma_multiply(0.7)),
                    StrokeKind::Inside,
                );
            }
        }
    }
    for (x, y) in game.cur.cells() {
        if y >= 0 {
            cell(
                p,
                board.min + vec2(x as f32 * CELL, y as f32 * CELL),
                game.cur.fee,
                pal,
            );
        }
    }
    // The falling tx's feerate, on it.
    let cc = game.cur.cells();
    let cx = (cc.iter().map(|c| c.0).min().unwrap_or(0) + cc.iter().map(|c| c.0).max().unwrap_or(0))
        as f32
        / 2.0;
    let cy = (cc.iter().map(|c| c.1).min().unwrap_or(0) + cc.iter().map(|c| c.1).max().unwrap_or(0))
        as f32
        / 2.0;
    if cy >= 0.0 {
        p.text(
            board.min + vec2((cx + 0.5) * CELL, (cy + 0.5) * CELL),
            Align2::CENTER_CENTER,
            format!("{}", game.cur.fee),
            mono(9.5),
            pal.on_signal(),
        );
    }
    for f in &game.floats {
        let t = f.age / FLOAT_SECS;
        p.text(
            f.at - vec2(0.0, 24.0 * t),
            Align2::CENTER_CENTER,
            &f.text,
            font(theme::MEDIUM, 13.0),
            f.color.gamma_multiply(1.0 - t * t),
        );
    }

    // Side panel: score, blocks sealed, next tx.
    p.text(
        side.left_top() + vec2(0.0, 6.0),
        Align2::LEFT_TOP,
        "fees collected",
        theme::body(11.5),
        pal.faint,
    );
    p.text(
        side.left_top() + vec2(0.0, 24.0),
        Align2::LEFT_TOP,
        format!("{}", thousands(game.score)),
        font(MONO_MEDIUM, 20.0),
        pal.text,
    );
    p.text(
        side.left_top() + vec2(0.0, 52.0),
        Align2::LEFT_TOP,
        format!("{} blocks sealed", game.sealed),
        theme::body(12.0),
        pal.muted,
    );
    p.text(
        side.left_top() + vec2(0.0, 74.0),
        Align2::LEFT_TOP,
        format!("best {}", thousands(best)),
        mono(11.5),
        pal.faint,
    );
    p.text(
        side.left_top() + vec2(0.0, 108.0),
        Align2::LEFT_TOP,
        "next tx",
        theme::body(11.5),
        pal.faint,
    );
    let next_box = Rect::from_min_size(side.left_top() + vec2(0.0, 128.0), vec2(96.0, 84.0));
    p.rect_filled(next_box, 8, pal.well);
    let (base, n) = PIECES[game.next.kind];
    let s = 18.0;
    let x0 = next_box.center().x - n as f32 * s / 2.0;
    let y0 = next_box.center().y - s;
    for &(x, y) in base {
        cell(
            p,
            pos2(x0 + x as f32 * s, y0 + y as f32 * s),
            game.next.fee,
            pal,
        );
    }
    p.text(
        next_box.center_bottom() - vec2(0.0, 6.0),
        Align2::CENTER_CENTER,
        format!("{} sat/vB", game.next.fee),
        mono(10.5),
        pal.muted,
    );

    match game.state {
        State::Paused => veil(p, board, pal, "Paused", "Space to go on"),
        State::Over => veil(
            p,
            board,
            pal,
            "The mempool won",
            &format!(
                "{} sats in {} blocks{} — Space for another shift",
                thousands(game.score),
                game.sealed,
                if game.new_best { " · a new best" } else { "" }
            ),
        ),
        State::Playing => {}
    }
}

fn cell(p: &Painter, at: Pos2, fee: u8, pal: &Palette) {
    let r = Rect::from_min_size(at + vec2(1.5, 1.5), vec2(CELL - 3.0, CELL - 3.0));
    p.rect_filled(r, 4, fee_fill(fee, pal));
    p.rect_stroke(
        r,
        4,
        Stroke::new(1.0, pal.hairline.gamma_multiply(0.8)),
        StrokeKind::Inside,
    );
}

fn veil(p: &Painter, board: Rect, pal: &Palette, title: &str, sub: &str) {
    p.rect_filled(board.expand(6.0), 12, pal.well.gamma_multiply(0.72));
    p.text(
        board.center() - vec2(0.0, 14.0),
        Align2::CENTER_CENTER,
        title,
        font(theme::TITLE, 30.0),
        if title == "Paused" {
            pal.text
        } else {
            pal.alert
        },
    );
    p.text(
        board.center() + vec2(0.0, 16.0),
        Align2::CENTER_CENTER,
        sub,
        theme::body(13.0),
        pal.muted,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn playing() -> Builder {
        let mut b = Builder::default();
        b.play();
        b
    }

    #[test]
    fn a_full_row_seals_and_pays() {
        let mut b = playing();
        for c in 1..COLS {
            b.grid[ROWS - 1][c] = 40;
        }
        // Drop the square into the last slot and an easy lock.
        b.cur = Piece {
            kind: 6,
            rot: 0,
            at: (-1, ROWS as i32 - 3),
            fee: 10,
        };
        let before = b.score;
        b.lock(Pos2::ZERO);
        assert!(b.score > before, "sealing a block pays fees");
        assert_eq!(b.sealed, 1);
    }

    #[test]
    fn locking_out_of_bounds_ends_the_shift() {
        let mut b = playing();
        b.cur.at = (4, -2);
        b.lock(Pos2::ZERO);
        assert_eq!(b.state, State::Over);
    }

    #[test]
    fn a_bag_deals_each_shape_once() {
        // An empty bag refills shuffled, then empties one of each.
        let mut b = Builder::default();
        let mut kinds: Vec<usize> = (0..7).map(|_| b.draw_piece().kind).collect();
        kinds.sort();
        assert_eq!(kinds, (0..7).collect::<Vec<_>>());
    }
}
