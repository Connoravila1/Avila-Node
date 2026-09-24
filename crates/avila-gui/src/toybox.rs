//! The toybox: things that are only for fun, shown when Settings says so.
//! Nothing here touches the node. Everything is drawn in code with the
//! fonts the app already carries — no images, sounds or dependencies —
//! so it adds next to nothing to the download.
//!
//! Shitcoin Defense: the bitcoin sits in the middle; shitcoins close in
//! from every side, faster and more often as time goes on. You walk the
//! ring around it with a shield and laser eyes. One gets through, the
//! game's over. There is no winning, only a best score.

use crate::pages::Scene;
use crate::prefs::Prefs;
use crate::theme::{self, Palette, Skin, font, mono};
use crate::widgets;
use eframe::egui::{
    self, Align2, Color32, Key, Pos2, RichText, Sense, Shape, Stroke, Ui, Vec2, vec2,
};
use std::f32::consts::{FRAC_PI_2, PI, TAU};
use std::time::Instant;

const ARENA_HEIGHT: f32 = 440.0;
/// The bitcoin's radius, the ring the guardian walks, and its size.
const CORE: f32 = 30.0;
const ORBIT: f32 = 96.0;
const BODY: f32 = 11.0;
/// Half the shield's width, radians.
const SHIELD: f32 = 0.36;
const COIN: f32 = 13.0;
/// How fast the guardian walks the ring, radians a second.
const WALK: f32 = 3.8;
/// Seconds of play per difficulty level.
const LEVEL_SECS: f32 = 18.0;
const POP_SECS: f32 = 0.45;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Ready,
    Playing,
    Paused,
    Over,
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Drifts straight in.
    Plain,
    /// Pumps in fast.
    Pump,
    /// Zigzags around the ring as it comes.
    Wobbly,
}

impl Kind {
    fn look(self) -> (Color32, &'static str) {
        match self {
            Self::Plain => (Color32::from_rgb(121, 82, 48), "💩"),
            Self::Pump => (Color32::from_rgb(40, 120, 88), "🚀"),
            Self::Wobbly => (Color32::from_rgb(112, 72, 150), "🐸"),
        }
    }
}

struct Shitcoin {
    angle: f32,
    dist: f32,
    speed: f32,
    kind: Kind,
    phase: f32,
}

/// A blocked shitcoin's last moment: where, and how long ago.
struct Pop {
    angle: f32,
    dist: f32,
    age: f32,
}

pub struct Game {
    state: State,
    angle: f32,
    coins: Vec<Shitcoin>,
    pops: Vec<Pop>,
    score: u32,
    time: f32,
    next_spawn: f32,
    seed: u64,
    last: Option<Instant>,
    /// When the mouse last steered; keys take over after a moment.
    steered: Option<Instant>,
    /// Plays itself, badly: always walking toward the nearest shitcoin.
    autopilot: bool,
}

impl Default for Game {
    fn default() -> Self {
        Self {
            state: State::Ready,
            angle: -FRAC_PI_2,
            coins: Vec::new(),
            pops: Vec::new(),
            score: 0,
            time: 0.0,
            next_spawn: 0.8,
            seed: 0x5EED_B17C,
            last: None,
            steered: None,
            autopilot: false,
        }
    }
}

fn dir(angle: f32) -> Vec2 {
    vec2(angle.cos(), angle.sin())
}

/// The shortest signed turn from `a` to `b`.
fn turn(a: f32, b: f32) -> f32 {
    (b - a + PI).rem_euclid(TAU) - PI
}

impl Game {
    /// Whether the arena needs every frame drawn.
    #[must_use]
    pub fn animating(&self) -> bool {
        self.state == State::Playing || !self.pops.is_empty()
    }

    /// Starts a game that plays itself (for screenshots).
    pub fn demo(&mut self) {
        self.start();
        self.autopilot = true;
    }

    fn start(&mut self) {
        *self = Self {
            state: State::Playing,
            seed: self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
            ..Self::default()
        };
    }

    /// A uniform draw in `[0, 1)` (SplitMix64).
    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1_u64 << 24) as f32
    }

    fn spawn(&mut self, far: f32) {
        let level = self.time / LEVEL_SECS;
        let roll = self.rand();
        let kind = if level > 3.0 && roll < 0.25 {
            Kind::Wobbly
        } else if level > 1.5 && roll < 0.45 {
            Kind::Pump
        } else {
            Kind::Plain
        };
        let base = 46.0 + 9.0 * level;
        let speed =
            base * match kind {
                Kind::Plain => 1.0,
                Kind::Pump => 1.7,
                Kind::Wobbly => 0.9,
            } * (0.85 + 0.3 * self.rand());
        let angle = self.rand() * TAU;
        let phase = self.rand() * TAU;
        self.coins.push(Shitcoin {
            angle,
            dist: far,
            speed,
            kind,
            phase,
        });
    }

    /// Advances play by `dt` seconds. `steer` is −1..1 from the keys;
    /// `aim` is an angle to walk toward (the mouse). Returns the final
    /// score if a shitcoin got through.
    fn step(&mut self, dt: f32, steer: f32, aim: Option<f32>, far: f32) -> Option<u32> {
        self.time += dt;
        let reach = WALK * dt;
        self.angle += match aim {
            Some(target) => turn(self.angle, target).clamp(-reach * 1.6, reach * 1.6),
            None => steer * reach,
        };
        self.angle = self.angle.rem_euclid(TAU);

        self.next_spawn -= dt;
        if self.next_spawn <= 0.0 {
            self.spawn(far);
            let level = self.time / LEVEL_SECS;
            self.next_spawn = (1.35 * 0.9_f32.powf(level)).max(0.3) * (0.7 + 0.6 * self.rand());
        }
        let t = self.time;
        for c in &mut self.coins {
            c.dist -= c.speed * dt;
            if let Kind::Wobbly = c.kind {
                c.angle += (t * 2.6 + c.phase).sin() * 0.9 * dt;
            }
        }
        // The shield and the guardian both stop a shitcoin at the ring.
        let guard = self.angle;
        let before = self.coins.len();
        let mut popped = Vec::new();
        self.coins.retain(|c| {
            let at_ring = (c.dist - ORBIT).abs() <= COIN + BODY + 4.0;
            let facing = turn(guard, c.angle).abs() <= SHIELD + COIN / ORBIT;
            let blocked = at_ring && facing;
            if blocked {
                popped.push(Pop {
                    angle: c.angle,
                    dist: c.dist,
                    age: 0.0,
                });
            }
            !blocked
        });
        self.score += (before - self.coins.len()) as u32;
        self.pops.extend(popped);
        for p in &mut self.pops {
            p.age += dt;
        }
        self.pops.retain(|p| p.age < POP_SECS);
        if self.coins.iter().any(|c| c.dist <= CORE + COIN * 0.6) {
            self.state = State::Over;
            return Some(self.score);
        }
        None
    }
}

pub fn show(ui: &mut Ui, s: &Scene, game: &mut Game, prefs: &mut Prefs) {
    let pal = s.pal;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Toybox")
                .font(font(theme::TITLE, 19.0))
                .color(pal.text),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("just for fun; nothing in here touches your node")
                .size(13.0)
                .color(pal.muted),
        );
    });
    widgets::hairline(ui);
    ui.add_space(14.0);

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Shitcoin Defense")
                .font(font(theme::MEDIUM, 15.0))
                .color(pal.text),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("Best {}", prefs.game_best))
                    .font(mono(13.0))
                    .color(pal.muted),
            );
        });
    });
    ui.add_space(6.0);
    arena(ui, &pal, game, prefs);
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Walk the ring with ← → or A D, or point with the mouse. Space or a click starts, pauses and goes on.",
        )
        .size(12.5)
        .color(pal.faint),
    );

    ui.add_space(30.0);
    widgets::section(ui, "Skins", Some("the whole node, while the toybox is on"));
    widgets::segmented(
        ui,
        &mut prefs.skin,
        &[
            (Skin::Standard, "Normal"),
            (Skin::Xp, "Windows XP"),
            (Skin::Julia, "Julia"),
        ],
    );
    ui.add_space(6.0);
    let about = match prefs.skin {
        Skin::Standard => "Ink on ash, with orange for what this machine has proven.",
        Skin::Xp => {
            "Beige windows, a blue bar, a green Start button, and a chunky green progress bar for the chain."
        }
        Skin::Julia => "Everything pink, with hearts where the lights are.",
    };
    ui.label(RichText::new(about).size(13.0).color(pal.muted));
}

fn arena(ui: &mut Ui, pal: &Palette, game: &mut Game, prefs: &mut Prefs) {
    let (rect, resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), ARENA_HEIGHT), Sense::click());
    let c = rect.center();
    // A round field inside the frame: every shitcoin comes the same
    // distance, materializing at its edge.
    let field = (rect.height().min(rect.width()) / 2.0 - 10.0).max(ORBIT + 40.0);
    let far = field + COIN;

    let (steer, space) = ui.input(|i| {
        let left = i.key_down(Key::ArrowLeft) || i.key_down(Key::A);
        let right = i.key_down(Key::ArrowRight) || i.key_down(Key::D);
        (
            f32::from(u8::from(right)) - f32::from(u8::from(left)),
            i.key_pressed(Key::Space),
        )
    });
    if resp.hovered() && ui.input(|i| i.pointer.delta() != Vec2::ZERO) {
        game.steered = Some(Instant::now());
    }
    let aim = if game.autopilot {
        game.coins
            .iter()
            .min_by(|a, b| a.dist.total_cmp(&b.dist))
            .map(|coin| coin.angle)
    } else {
        resp.hover_pos()
            .filter(|_| steer == 0.0)
            .filter(|_| {
                game.steered
                    .is_some_and(|t| t.elapsed().as_secs_f32() < 1.5)
            })
            .map(|pos| (pos - c).angle())
    };
    let go = space || resp.clicked();

    let now = Instant::now();
    let dt = game
        .last
        .map_or(0.0, |l| now.duration_since(l).as_secs_f32());
    game.last = Some(now);
    // Away from the page mid-game: pause rather than lose while gone.
    if game.state == State::Playing && dt > 0.5 {
        game.state = State::Paused;
    }
    match game.state {
        State::Ready | State::Over if go => game.start(),
        State::Paused if go => game.state = State::Playing,
        State::Playing if go => game.state = State::Paused,
        State::Playing => {
            if let Some(score) = game.step(dt.min(0.05), steer, aim, far) {
                prefs.game_best = prefs.game_best.max(score);
            }
        }
        _ => {
            for p in &mut game.pops {
                p.age += dt.min(0.05);
            }
            game.pops.retain(|p| p.age < POP_SECS);
        }
    }

    let p = ui.painter_at(rect);
    p.rect_filled(rect, 14, pal.well);
    p.circle_filled(c, field, pal.canvas.gamma_multiply(0.55));
    p.circle_stroke(c, ORBIT, Stroke::new(1.0, pal.hairline));

    for coin in &game.coins {
        let at = c + dir(coin.angle) * coin.dist;
        let (fill, glyph) = coin.kind.look();
        // Out of the fog at the field's edge.
        let seen = ((far - coin.dist) / 24.0).clamp(0.0, 1.0);
        p.circle_filled(at, COIN, fill.gamma_multiply(seen));
        p.circle_stroke(
            at,
            COIN - 0.75,
            Stroke::new(
                1.5,
                fill.lerp_to_gamma(Color32::BLACK, 0.35)
                    .gamma_multiply(seen),
            ),
        );
        p.text(
            at,
            Align2::CENTER_CENTER,
            glyph,
            egui::FontId::proportional(13.0),
            Color32::from_rgb(255, 244, 228).gamma_multiply(seen),
        );
    }
    for pop in &game.pops {
        let f = pop.age / POP_SECS;
        let at = c + dir(pop.angle) * pop.dist;
        p.circle_stroke(
            at,
            COIN + 22.0 * f,
            Stroke::new(2.0 * (1.0 - f) + 0.5, pal.signal.gamma_multiply(1.0 - f)),
        );
        p.text(
            at - vec2(0.0, 18.0 + 16.0 * f),
            Align2::CENTER_CENTER,
            "+1",
            mono(12.0),
            pal.text.gamma_multiply(1.0 - f),
        );
    }

    // The bitcoin.
    let ink = if Skin::current() == Skin::Standard {
        theme::INK
    } else {
        Color32::WHITE
    };
    p.circle_filled(c, CORE + 5.0, pal.signal_alpha(0.22));
    p.circle_filled(c, CORE, pal.signal);
    p.text(c, Align2::CENTER_CENTER, "₿", mono(34.0), ink);

    // The guardian: a shield out front, and laser eyes.
    let out = dir(game.angle);
    let g = c + out * ORBIT;
    let shield: Vec<Pos2> = (0..=16)
        .map(|i| {
            let a = game.angle - SHIELD + 2.0 * SHIELD * i as f32 / 16.0;
            c + dir(a) * (ORBIT + BODY + 5.0)
        })
        .collect();
    p.add(Shape::line(shield, Stroke::new(4.5, pal.text)));
    p.circle_filled(g, BODY, pal.text);
    let side = vec2(-out.y, out.x);
    let laser = Color32::from_rgb(255, 48, 48);
    for sgn in [-1.0, 1.0] {
        let eye = g + out * 4.0 + side * 3.8 * sgn;
        p.circle_filled(eye, 1.9, laser);
        p.line_segment(
            [eye, eye + out * 9.0],
            Stroke::new(1.3, laser.gamma_multiply(0.55)),
        );
    }

    // The score, and whatever the moment calls for.
    p.text(
        rect.left_top() + vec2(16.0, 14.0),
        Align2::LEFT_TOP,
        format!("Blocked {}", game.score),
        mono(14.0),
        pal.text,
    );
    let low = rect.center_bottom() - vec2(0.0, 58.0);
    let (title, line) = match game.state {
        State::Ready => (
            "Shitcoin Defense",
            "Keep them off the bitcoin. Space or click to play.".to_owned(),
        ),
        State::Paused => ("Paused", "Space or click to go on.".to_owned()),
        State::Over => (
            "A shitcoin got through",
            format!(
                "{} blocked · best {} · Space or click to play again",
                game.score, prefs.game_best
            ),
        ),
        State::Playing => return,
    };
    let title_color = if game.state == State::Over {
        pal.alert
    } else {
        pal.text
    };
    p.text(
        low,
        Align2::CENTER_CENTER,
        title,
        font(theme::TITLE, 22.0),
        title_color,
    );
    p.text(
        low + vec2(0.0, 28.0),
        Align2::CENTER_CENTER,
        line,
        font(theme::MEDIUM, 13.5),
        pal.muted,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shield_facing_a_shitcoin_stops_it() {
        let mut g = Game::default();
        g.start();
        g.next_spawn = 1e9;
        g.angle = 0.0;
        g.coins.push(Shitcoin {
            angle: 0.05,
            dist: ORBIT + 20.0,
            speed: 60.0,
            kind: Kind::Plain,
            phase: 0.0,
        });
        for _ in 0..30 {
            assert_eq!(g.step(0.02, 0.0, None, 500.0), None);
        }
        assert_eq!(g.score, 1);
        assert!(g.coins.is_empty());
    }

    #[test]
    fn one_behind_the_guardian_ends_the_game() {
        let mut g = Game::default();
        g.start();
        g.next_spawn = 1e9;
        g.angle = 0.0;
        g.coins.push(Shitcoin {
            angle: PI,
            dist: ORBIT + 20.0,
            speed: 120.0,
            kind: Kind::Plain,
            phase: 0.0,
        });
        let mut end = None;
        for _ in 0..200 {
            end = end.or(g.step(0.02, 0.0, None, 500.0));
        }
        assert_eq!(end, Some(0));
        assert_eq!(g.state, State::Over);
    }

    #[test]
    fn it_gets_harder() {
        let mut g = Game::default();
        g.start();
        g.time = 0.0;
        g.spawn(500.0);
        let early = g.coins[0].speed;
        g.coins.clear();
        g.time = 10.0 * LEVEL_SECS;
        for _ in 0..20 {
            g.spawn(500.0);
        }
        let late = g.coins.iter().map(|c| c.speed).fold(f32::MAX, f32::min);
        assert!(late > early * 1.8, "{early} → {late}");
    }
}
