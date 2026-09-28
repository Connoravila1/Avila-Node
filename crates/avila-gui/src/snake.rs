//! Chain Snake: the snake is the blockchain. Every sat you eat mines a
//! block onto the tail — the subsidy halves as you go — and every so
//! often a reorg orphans the last few. Hit a wall or your own chain and
//! it's invalid; the network moves on without you.

use crate::model::btc;
use crate::prefs::Prefs;
use crate::theme::{self, MONO_MEDIUM, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, Color32, Key, Layout, Modifiers, Painter, Pos2, Rect, RichText, Sense, Stroke,
    StrokeKind, Ui, pos2, vec2,
};
use std::collections::VecDeque;
use std::time::Instant;

const COLS: i32 = 22;
const ROWS: i32 = 15;
const CELL: f32 = 28.0;
const FLOAT_SECS: f32 = 1.3;
/// Seconds between reorgs, give or take.
const REORG_EVERY: f32 = 26.0;
/// A block's subsidy at the game's era zero — the real era four pays
/// 3.125 BTC, and this game halves from there.
const SUBSIDY: u64 = 312_500_000;
/// Blocks mined per era in here — a halving lands fast at toy scale.
const ERA_LEN: u32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Ready,
    Playing,
    Paused,
    Over,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct Pos {
    x: i32,
    y: i32,
}

/// A block shaken loose by a reorg, fading where it fell.
struct Ghost {
    at: Pos,
    age: f32,
}

struct Float {
    at: Pos2,
    text: String,
    color: Color32,
    age: f32,
}

pub struct Snake {
    pub open: bool,
    state: State,
    /// Head first; each carries its height label.
    body: VecDeque<(Pos, u32)>,
    dir: Pos,
    queued: Pos,
    food: Pos,
    score: u64,
    mined: u32,
    acc: f32,
    reorg_in: f32,
    ghosts: Vec<Ghost>,
    floats: Vec<Float>,
    new_best: bool,
    seed: u64,
    last: Option<Instant>,
}

impl Default for Snake {
    fn default() -> Self {
        Self {
            open: false,
            state: State::Ready,
            body: VecDeque::new(),
            dir: Pos { x: 1, y: 0 },
            queued: Pos { x: 1, y: 0 },
            food: Pos::default(),
            score: 0,
            mined: 0,
            acc: 0.0,
            reorg_in: REORG_EVERY,
            ghosts: Vec::new(),
            floats: Vec::new(),
            new_best: false,
            seed: 0xCAFE_0173,
            last: None,
        }
    }
}

impl Snake {
    #[must_use]
    pub fn animating(&self) -> bool {
        self.open
            && (matches!(self.state, State::Playing)
                || !self.ghosts.is_empty()
                || !self.floats.is_empty())
    }

    pub fn shelve(&mut self) {
        self.open = false;
    }

    /// A fresh chain, extended from `base` — the node's tip when it's
    /// running, so you're literally building on your own chain.
    pub fn play(&mut self, base: u32) {
        let seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        *self = Self {
            open: true,
            state: State::Playing,
            seed,
            ..Self::default()
        };
        for i in 0..4 {
            self.body.push_back((
                Pos {
                    x: 6 - i,
                    y: ROWS / 2,
                },
                base + (3 - i) as u32,
            ));
        }
        self.drop_food();
    }

    /// A mid-game pose, for screenshots — a staircase climbing right,
    /// with the head left enough to still have runway.
    pub fn demo(&mut self) {
        self.play(918_800);
        for i in 0..8 {
            let head = self.body[0];
            self.body.push_front((
                Pos {
                    x: head.0.x + 1,
                    y: head.0.y - (i % 2),
                },
                head.1 + 1,
            ));
        }
        self.mined = 9;
        self.score = 2_846_000_000;
        self.ghosts.push(Ghost {
            at: Pos { x: 4, y: 9 },
            age: 0.4,
        });
    }

    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1_u64 << 24) as f32
    }

    fn drop_food(&mut self) {
        for _ in 0..200 {
            let at = Pos {
                x: (self.rand() * COLS as f32) as i32,
                y: (self.rand() * ROWS as f32) as i32,
            };
            if !self.body.iter().any(|(b, _)| *b == at) {
                self.food = at;
                return;
            }
        }
    }

    /// The subsidy a freshly mined block pays this era.
    fn subsidy(&self) -> u64 {
        SUBSIDY >> (self.mined / ERA_LEN).min(8)
    }

    fn say(&mut self, at: Pos2, text: impl Into<String>, color: Color32) {
        self.floats.push(Float {
            at,
            text: text.into(),
            color,
            age: 0.0,
        });
    }

    /// One move: the head advances; the tail follows unless a block was
    /// just mined. Returns the score when the run ends.
    fn tick(&mut self, origin: Pos2) -> Option<u64> {
        self.dir = self.queued;
        let head = self.body.front().copied()?;
        let next = Pos {
            x: head.0.x + self.dir.x,
            y: head.0.y + self.dir.y,
        };
        let ate = next == self.food;
        if next.x < 0
            || next.y < 0
            || next.x >= COLS
            || next.y >= ROWS
            || self
                .body
                .iter()
                .take(if ate {
                    usize::MAX
                } else {
                    self.body.len().saturating_sub(1)
                })
                .any(|(b, _)| *b == next)
        {
            self.state = State::Over;
            self.say(
                origin + center(next).to_vec2(),
                "chain invalid",
                Color32::from_rgb(220, 60, 40),
            );
            return Some(self.score);
        }
        if ate {
            let pay = self.subsidy();
            self.score += pay;
            self.mined += 1;
            self.say(
                origin + center(next).to_vec2(),
                format!("+{}", btc(pay as i64)),
                Color32::from_rgb(60, 170, 90),
            );
            self.body.push_front((next, head.1 + 1));
            self.drop_food();
        } else {
            self.body.push_front((next, head.1));
            self.body.pop_back();
        }
        None
    }

    /// A reorg: the newest few tail blocks fall off as ghosts.
    fn reorg(&mut self, origin: Pos2) {
        let keep = self.body.len().saturating_sub(3).max(5);
        let mut lost = 0_u32;
        while self.body.len() > keep && lost < 3 {
            let (at, _) = self.body.pop_back().unwrap_or_default();
            self.ghosts.push(Ghost { at, age: 0.0 });
            lost += 1;
        }
        if lost > 0 {
            let tail = self.body.back().map(|(b, _)| *b).unwrap_or_default();
            self.say(
                origin + center(tail).to_vec2(),
                format!("reorg — {lost} orphaned"),
                Color32::from_rgb(220, 120, 40),
            );
        }
    }

    fn step(&mut self, dt: f32, origin: Pos2) -> Option<u64> {
        for g in &mut self.ghosts {
            g.age += dt;
        }
        self.ghosts.retain(|g| g.age < 2.2);
        for f in &mut self.floats {
            f.age += dt;
        }
        self.floats.retain(|f| f.age < FLOAT_SECS);
        if self.state != State::Playing {
            return None;
        }
        self.acc += dt;
        self.reorg_in -= dt;
        if self.reorg_in <= 0.0 {
            self.reorg_in = REORG_EVERY * (0.7 + 0.6 * self.rand());
            self.reorg(origin);
        }
        let pace = (0.16 - 0.004 * self.mined as f32).max(0.07);
        let mut end = None;
        while self.acc >= pace && self.state == State::Playing {
            self.acc -= pace;
            end = end.or(self.tick(origin));
        }
        end
    }
}

fn center(at: Pos) -> Pos2 {
    pos2(
        at.x as f32 * CELL + CELL / 2.0,
        at.y as f32 * CELL + CELL / 2.0,
    )
}

/// The whole open view: header, the field, the hint line.
pub fn show(ui: &mut Ui, pal: &Palette, game: &mut Snake, prefs: &mut Prefs) {
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
            RichText::new("Chain Snake")
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
        pos2(rect.center().x - w / 2.0, rect.top() + 6.0),
        vec2(w, h),
    );
    let origin = board.min;

    // Steering — never straight back into your own neck.
    let want = ui.input(|i| {
        if i.key_pressed(Key::ArrowLeft) || i.key_pressed(Key::A) {
            Some(Pos { x: -1, y: 0 })
        } else if i.key_pressed(Key::ArrowRight) || i.key_pressed(Key::D) {
            Some(Pos { x: 1, y: 0 })
        } else if i.key_pressed(Key::ArrowUp) || i.key_pressed(Key::W) {
            Some(Pos { x: 0, y: -1 })
        } else if i.key_pressed(Key::ArrowDown) || i.key_pressed(Key::S) {
            Some(Pos { x: 0, y: 1 })
        } else {
            None
        }
    });
    if let Some(w) = want
        && game.state == State::Playing
        && (w.x != -game.dir.x || w.y != -game.dir.y)
    {
        game.queued = w;
    }
    match game.state {
        State::Playing if space => game.state = State::Paused,
        State::Paused if space => game.state = State::Playing,
        State::Over if space => {
            let base = game.body.front().map(|(_, h)| *h).unwrap_or(0);
            game.play(base)
        }
        _ => {}
    }

    let now = Instant::now();
    let dt = game
        .last
        .map_or(0.0, |l| now.duration_since(l).as_secs_f32());
    game.last = Some(now);
    if dt > 0.5 {
        game.state = match game.state {
            State::Playing => State::Paused,
            s => s,
        };
    }
    let p = ui.painter_at(board);
    if let Some(score) = game.step(dt.min(0.1), origin) {
        if score > prefs.snake_best {
            prefs.snake_best = score;
            game.new_best = true;
        }
    }

    draw(&p, board, pal, game, prefs.snake_best);
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Arrows or WASD. Each sat mines a block onto your chain; the subsidy halves every era. Reorgs shake the tail loose. Space pauses; Esc goes back to the toybox.",
        )
        .size(12.5)
        .color(pal.faint),
    );
    if leave {
        game.shelve();
    }
}

fn draw(p: &Painter, board: Rect, pal: &Palette, game: &Snake, best: u64) {
    p.rect_filled(board.expand(6.0), 12, pal.well);
    // Faint grid lines, like a block template's rows.
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
    for g in &game.ghosts {
        let f = (1.0 - g.age / 2.2).clamp(0.0, 1.0);
        let r = Rect::from_center_size(
            board.min + center(g.at).to_vec2(),
            vec2(CELL - 6.0, CELL - 6.0),
        );
        p.rect_stroke(
            r,
            4,
            Stroke::new(1.4, pal.alert.gamma_multiply(0.6 * f)),
            StrokeKind::Inside,
        );
        p.text(
            r.center(),
            Align2::CENTER_CENTER,
            "✕",
            mono(13.0),
            pal.alert.gamma_multiply(f),
        );
    }
    // The sat, glowing gently.
    let at = board.min + center(game.food).to_vec2();
    p.circle_filled(at, CELL * 0.34, pal.signal_alpha(0.22));
    p.circle_filled(at, CELL * 0.24, pal.signal);
    p.text(at, Align2::CENTER_CENTER, "₿", mono(12.0), pal.on_signal());
    // The chain itself, newest block brightest.
    let n = game.body.len().max(1) as f32;
    for (i, (b, h)) in game.body.iter().enumerate() {
        let t = 1.0 - i as f32 / n;
        let r = Rect::from_center_size(
            board.min + center(*b).to_vec2(),
            vec2(CELL - 5.0, CELL - 5.0),
        );
        let fill = if i == 0 {
            pal.signal
        } else {
            pal.text.lerp_to_gamma(pal.well, 1.0 - t * 0.85 - 0.1)
        };
        p.rect_filled(r, 5, fill);
        p.rect_stroke(
            r,
            5,
            Stroke::new(1.0, pal.hairline.gamma_multiply(0.8)),
            StrokeKind::Inside,
        );
        if i == 0 {
            p.text(
                r.center(),
                Align2::CENTER_CENTER,
                format!("{h}"),
                mono(8.5),
                pal.on_signal(),
            );
        }
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
    // Scoreboard.
    p.text(
        board.left_top() + vec2(8.0, 8.0),
        Align2::LEFT_TOP,
        btc(game.score as i64),
        font(MONO_MEDIUM, 17.0),
        pal.text,
    );
    p.text(
        board.left_top() + vec2(8.0, 30.0),
        Align2::LEFT_TOP,
        format!(
            "era {} · subsidy {}",
            game.mined / ERA_LEN + 4,
            btc(game.subsidy() as i64)
        ),
        theme::body(11.5),
        pal.muted,
    );
    p.text(
        board.right_top() - vec2(8.0, -8.0),
        Align2::RIGHT_TOP,
        format!("Best {}", btc(best as i64)),
        mono(12.5),
        pal.muted,
    );
    if game.state == State::Paused {
        veil(p, board, pal, "Paused", "Space to go on");
    }
    if game.state == State::Over {
        veil(
            p,
            board,
            pal,
            "Chain invalid",
            &format!(
                "{}{} — Space for a fresh chain",
                btc(game.score as i64),
                if game.new_best { " · a new best" } else { "" }
            ),
        );
    }
}

fn veil(p: &Painter, board: Rect, pal: &Palette, title: &str, sub: &str) {
    p.rect_filled(board.expand(6.0), 12, pal.well.gamma_multiply(0.72));
    p.text(
        board.center() - vec2(0.0, 14.0),
        Align2::CENTER_CENTER,
        title,
        font(theme::TITLE, 30.0),
        if title == "Chain invalid" {
            pal.alert
        } else {
            pal.text
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

    fn playing() -> Snake {
        let mut s = Snake::default();
        s.play(100);
        s
    }

    #[test]
    fn eating_mines_a_block_and_pays_the_subsidy() {
        let mut s = playing();
        let head = s.body[0];
        s.food = Pos {
            x: head.0.x + 1,
            y: head.0.y,
        };
        let before = s.body.len();
        s.tick(Pos2::ZERO);
        assert_eq!(s.body.len(), before + 1);
        assert_eq!(s.score, SUBSIDY);
        assert_eq!(s.body[0].1, head.1 + 1);
    }

    #[test]
    fn a_wall_invalidates_the_chain() {
        let mut s = playing();
        for _ in 0..20 {
            s.tick(Pos2::ZERO);
        }
        assert_eq!(s.state, State::Over);
    }

    #[test]
    fn the_subsidy_halves_each_era() {
        let mut s = playing();
        assert_eq!(s.subsidy(), SUBSIDY);
        s.mined = ERA_LEN;
        assert_eq!(s.subsidy(), SUBSIDY / 2);
        s.mined = ERA_LEN * 9;
        assert_eq!(s.subsidy(), SUBSIDY >> 8);
    }

    #[test]
    fn a_reorg_orphans_the_tail() {
        let mut s = playing();
        // Grow the chain past five, so the reorg has tail to take.
        for _ in 0..4 {
            let head = s.body[0];
            s.body.push_front((
                Pos {
                    x: head.0.x + 1,
                    y: head.0.y,
                },
                head.1 + 1,
            ));
        }
        s.reorg(Pos2::ZERO);
        assert_eq!(s.body.len(), 5);
        assert!(!s.ghosts.is_empty());
    }
}
