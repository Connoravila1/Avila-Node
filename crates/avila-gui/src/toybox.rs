//! The toybox: things that are only for fun, shown when Settings says so.
//! Nothing here touches the node, and everything is drawn in code, so it
//! adds next to nothing to the download.
//!
//! The page is a shelf: the game, then the skins. Shitcoin Defense opens
//! only when you press Play. The bitcoin sits in the middle and coins fly
//! at it from every side: turn the shield to knock the shitcoins away,
//! and let the sats through to be stacked. Three shitcoins in and it's
//! over. It comes in waves, each faster and busier than the last.

use crate::pages::Scene;
use crate::prefs::Prefs;
use crate::theme::{self, MONO_MEDIUM, Palette, Skin, font, mono};
use crate::widgets::{self, Kind as Button};
use crate::{julia, model::thousands, xp};
use eframe::egui::{
    Align, Align2, Color32, CornerRadius, CursorIcon, Id, Key, Layout, Modifiers, Painter, Pos2,
    Rect, RichText, Sense, Shape, Stroke, StrokeKind, Ui, UiBuilder, Vec2, pos2, vec2,
};
use std::f32::consts::{FRAC_PI_2, PI, TAU};
use std::time::Instant;

const ARENA_HEIGHT: f32 = 480.0;
/// The bitcoin's radius, the shield's ring, and half the shield's width
/// in radians.
const CORE: f32 = 30.0;
const RING: f32 = 104.0;
const SHIELD: f32 = 0.44;
/// How fast the shield turns: toward the pointer, and on the keys.
const TURN_AIM: f32 = 13.0;
const TURN_KEYS: f32 = 5.5;
const LIVES: u8 = 3;
const WAVE_SECS: f32 = 24.0;
/// "3, 2, 1": a beat each.
const COUNTDOWN: f32 = 2.4;
const BANNER: f32 = 2.2;
/// A halving slows the shitcoins this long.
const SLOW: f32 = 6.0;
const SHAKE: f32 = 0.35;
const FLASH: f32 = 0.16;
const GLOW: f32 = 0.5;
const FLOAT_SECS: f32 = 0.9;

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Ready,
    /// Seconds left of "3, 2, 1".
    Countdown(f32),
    Playing,
    Paused,
    Over,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// Drifts straight in.
    Scam,
    /// Rockets in.
    Pump,
    /// Weaves from side to side.
    Rug,
    /// Big and slow, and takes two knocks.
    Hype,
    /// Spirals in.
    Meme,
    /// Let these in: they're stacked.
    Sats,
    /// Let it in and every shitcoin slows down for a while.
    Halving,
}

impl Kind {
    /// Shitcoins are knocked away; sats and halvings are let in.
    fn bad(self) -> bool {
        !matches!(self, Self::Sats | Self::Halving)
    }

    fn radius(self) -> f32 {
        match self {
            Self::Hype => 16.0,
            Self::Sats => 10.5,
            Self::Halving => 12.5,
            _ => 13.5,
        }
    }

    /// Speed, as a share of the wave's.
    fn pace(self) -> f32 {
        match self {
            Self::Pump => 1.75,
            Self::Hype => 0.72,
            Self::Rug => 0.95,
            Self::Meme | Self::Sats => 0.88,
            Self::Halving => 0.8,
            Self::Scam => 1.0,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Scam => "SCAM",
            Self::Pump => "PUMP",
            Self::Rug => "RUG",
            Self::Hype => "HYPE",
            Self::Meme => "MEME",
            Self::Sats => "₿",
            Self::Halving => "½",
        }
    }

    /// Fill and rim. Every shitcoin is some shade of mud.
    fn colors(self, pal: &Palette) -> (Color32, Color32) {
        let rgb = Color32::from_rgb;
        match self {
            Self::Scam => (rgb(128, 88, 54), rgb(82, 54, 30)),
            Self::Pump => (rgb(154, 98, 46), rgb(98, 58, 22)),
            Self::Rug => (rgb(112, 86, 72), rgb(70, 52, 42)),
            Self::Hype => (rgb(96, 66, 44), rgb(204, 164, 76)),
            Self::Meme => (rgb(132, 86, 100), rgb(84, 50, 64)),
            Self::Sats => (pal.signal, pal.signal.lerp_to_gamma(Color32::WHITE, 0.4)),
            Self::Halving => (pal.raised, pal.signal),
        }
    }
}

/// What a wave is called, as it arrives.
fn wave_name(wave: u32) -> &'static str {
    match wave {
        1 => "A wild scam appears",
        2 => "Pump season",
        3 => "Rug pulls",
        4 => "Peak hype",
        5 => "Meme mania",
        _ => "Altseason",
    }
}

struct Coin {
    kind: Kind,
    angle: f32,
    dist: f32,
    speed: f32,
    phase: f32,
    /// Knocks it can still take.
    hits: u8,
    /// Outward speed after a knock that didn't finish it.
    knock: f32,
}

/// How an effect is colored, settled when it's drawn.
#[derive(Clone, Copy)]
enum Tone {
    Coin(Kind),
    Good,
    Bad,
    Quiet,
}

impl Tone {
    fn color(self, pal: &Palette) -> Color32 {
        match self {
            Self::Coin(kind) => kind.colors(pal).0,
            Self::Good => pal.signal_text,
            Self::Bad => pal.alert,
            Self::Quiet => pal.muted,
        }
    }
}

/// A shard or glint flying off something, relative to the center.
struct Spark {
    at: Vec2,
    vel: Vec2,
    age: f32,
    life: f32,
    size: f32,
    tone: Tone,
}

/// Words that rise and fade: points, and what just happened.
struct Float {
    at: Vec2,
    text: String,
    tone: Tone,
    age: f32,
}

enum Hit {
    Shield,
    Core,
}

pub struct Game {
    /// The game is on screen, rather than the shelf.
    open: bool,
    state: State,
    angle: f32,
    coins: Vec<Coin>,
    sparks: Vec<Spark>,
    floats: Vec<Float>,
    score: u32,
    combo: u32,
    lives: u8,
    blocked: u32,
    stacked: u32,
    wave: u32,
    wave_time: f32,
    /// Seconds each effect has left.
    banner: f32,
    slow: f32,
    shake: f32,
    flash: f32,
    glow: f32,
    next_spawn: f32,
    new_best: bool,
    seed: u64,
    last: Option<Instant>,
    /// When the mouse last steered; the keys take over after a moment.
    steered: Option<Instant>,
    /// Plays itself: always turning to the nearest shitcoin.
    autopilot: bool,
}

impl Default for Game {
    fn default() -> Self {
        Self {
            open: false,
            state: State::Ready,
            angle: -FRAC_PI_2,
            coins: Vec::new(),
            sparks: Vec::new(),
            floats: Vec::new(),
            score: 0,
            combo: 0,
            lives: LIVES,
            blocked: 0,
            stacked: 0,
            wave: 1,
            wave_time: 0.0,
            banner: 0.0,
            slow: 0.0,
            shake: 0.0,
            flash: 0.0,
            glow: 0.0,
            next_spawn: 0.6,
            new_best: false,
            seed: 0x5EED_B17C,
            last: None,
            steered: None,
            autopilot: false,
        }
    }
}

fn dir(angle: f32) -> Vec2 {
    Vec2::angled(angle)
}

/// The shortest signed turn from `a` to `b`.
fn turn(a: f32, b: f32) -> f32 {
    (b - a + PI).rem_euclid(TAU) - PI
}

impl Game {
    /// Whether the arena needs every frame drawn.
    #[must_use]
    pub fn animating(&self) -> bool {
        self.open
            && (matches!(self.state, State::Playing | State::Countdown(_))
                || !self.sparks.is_empty()
                || !self.floats.is_empty())
    }

    /// Whether a finished game is on screen.
    #[must_use]
    pub fn over(&self) -> bool {
        self.open && self.state == State::Over
    }

    /// Opens the game playing itself (for screenshots).
    pub fn demo(&mut self) {
        self.play();
        self.state = State::Playing;
        self.wave = 3;
        self.autopilot = true;
    }

    /// Opens a finished game (for screenshots).
    pub fn demo_over(&mut self) {
        self.play();
        self.state = State::Over;
        self.score = 1_240;
        self.wave = 4;
        self.blocked = 96;
        self.stacked = 7;
        self.lives = 0;
    }

    /// Back to the shelf, with nothing in progress (for screenshots).
    pub fn shelve(&mut self) {
        *self = Self {
            seed: self.seed,
            ..Self::default()
        };
    }

    /// A fresh game, counting in.
    fn play(&mut self) {
        *self = Self {
            open: true,
            state: State::Countdown(COUNTDOWN),
            seed: self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
            ..Self::default()
        };
    }

    fn pause(&mut self) {
        if matches!(self.state, State::Playing | State::Countdown(_)) {
            self.state = State::Paused;
        }
    }

    /// Back to the shelf; a game in play waits, paused.
    fn leave(&mut self) {
        self.pause();
        self.open = false;
    }

    /// A uniform draw in `[0, 1)` (SplitMix64).
    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1_u64 << 24) as f32
    }

    /// The score multiplier: up one for every five in a row, to five.
    fn mult(&self) -> u32 {
        (1 + self.combo / 5).min(5)
    }

    fn spawn(&mut self, far: f32) {
        // Each kind's weight, and the wave it first turns up in.
        let table = [
            (Kind::Scam, 10.0, 1),
            (Kind::Pump, 5.0, 2),
            (Kind::Rug, 4.0, 3),
            (Kind::Hype, 3.0, 4),
            (Kind::Meme, 3.0, 5),
            (Kind::Sats, 3.5, 1),
            (Kind::Halving, 0.7, 3),
        ];
        let w = self.wave;
        let total: f32 = table.iter().filter(|t| w >= t.2).map(|t| t.1).sum();
        let mut roll = self.rand() * total;
        let mut kind = Kind::Scam;
        for (k, weight, from) in table {
            if w < from {
                continue;
            }
            if roll < weight {
                kind = k;
                break;
            }
            roll -= weight;
        }
        if kind == Kind::Halving
            && (self.slow > 0.0 || self.coins.iter().any(|c| c.kind == Kind::Halving))
        {
            kind = Kind::Scam;
        }
        let base = 58.0 + 8.0 * (w - 1) as f32 + 0.5 * self.wave_time;
        let speed = base * kind.pace() * (0.9 + 0.2 * self.rand());
        let angle = self.rand() * TAU;
        let phase = self.rand() * TAU;
        self.coins.push(Coin {
            kind,
            angle,
            dist: far,
            speed,
            phase,
            hits: if kind == Kind::Hype { 2 } else { 1 },
            knock: 0.0,
        });
    }

    /// Seconds to the next coin: shorter each wave, and through a wave.
    fn interval(&mut self) -> f32 {
        let base = (1.1 * 0.87_f32.powf((self.wave - 1) as f32)).max(0.28);
        base * (1.0 - 0.25 * self.wave_time / WAVE_SECS) * (0.7 + 0.6 * self.rand())
    }

    fn burst(&mut self, at: Vec2, tone: Tone, n: usize, speed: f32) {
        for _ in 0..n {
            let a = self.rand() * TAU;
            let v = speed * (0.4 + 0.8 * self.rand());
            let life = 0.35 + 0.35 * self.rand();
            let size = 2.0 + 2.5 * self.rand();
            self.sparks.push(Spark {
                at,
                vel: dir(a) * v,
                age: 0.0,
                life,
                size,
                tone,
            });
        }
    }

    fn say(&mut self, at: Vec2, text: impl Into<String>, tone: Tone) {
        self.floats.push(Float {
            at,
            text: text.into(),
            tone,
            age: 0.0,
        });
    }

    /// Effects run down whether or not the game is.
    fn fade(&mut self, dt: f32) {
        for s in &mut self.sparks {
            s.at += s.vel * dt;
            s.vel *= (1.0 - 2.8 * dt).max(0.0);
            s.age += dt;
        }
        self.sparks.retain(|s| s.age < s.life);
        for f in &mut self.floats {
            f.age += dt;
        }
        self.floats.retain(|f| f.age < FLOAT_SECS);
        self.shake = (self.shake - dt).max(0.0);
        self.flash = (self.flash - dt).max(0.0);
        self.glow = (self.glow - dt).max(0.0);
    }

    /// Advances the game by `dt` seconds. `steer` is −1..1 from the keys;
    /// `aim` is an angle to turn toward (the pointer). Returns the final
    /// score when the game ends.
    fn step(&mut self, dt: f32, steer: f32, aim: Option<f32>, far: f32) -> Option<u32> {
        self.fade(dt);
        match self.state {
            State::Countdown(t) if t - dt <= 0.0 => {
                self.state = State::Playing;
                self.banner = BANNER;
                return None;
            }
            State::Countdown(t) => {
                self.state = State::Countdown(t - dt);
                return None;
            }
            State::Playing => {}
            _ => return None,
        }
        let reach = match aim {
            Some(target) => turn(self.angle, target).clamp(-TURN_AIM * dt, TURN_AIM * dt),
            None => steer * TURN_KEYS * dt,
        };
        self.angle = (self.angle + reach).rem_euclid(TAU);

        self.wave_time += dt;
        if self.wave_time >= WAVE_SECS {
            self.wave += 1;
            self.wave_time = 0.0;
            self.banner = BANNER;
            // A breath between waves.
            self.next_spawn = self.next_spawn.max(1.6);
        }
        self.banner = (self.banner - dt).max(0.0);
        self.slow = (self.slow - dt).max(0.0);

        self.next_spawn -= dt;
        if self.next_spawn <= 0.0 {
            self.spawn(far);
            self.next_spawn = self.interval();
        }
        let t = self.wave as f32 * 97.0 + self.wave_time;
        let slow = if self.slow > 0.0 { 0.5 } else { 1.0 };
        for c in &mut self.coins {
            let pace = if c.kind.bad() { slow } else { 1.0 };
            if c.knock > 0.0 {
                c.dist += c.knock * dt;
                c.knock = (c.knock - 520.0 * dt).max(0.0);
                continue;
            }
            c.dist -= c.speed * pace * dt;
            match c.kind {
                Kind::Rug => c.angle += (t * 3.2 + c.phase).sin() * 1.2 * dt,
                Kind::Meme => c.angle += if c.phase < PI { 0.8 } else { -0.8 } * pace * dt,
                _ => {}
            }
        }

        let mut hits = Vec::new();
        for (i, c) in self.coins.iter().enumerate() {
            if c.knock > 0.0 {
                continue;
            }
            let r = c.kind.radius();
            if c.dist <= CORE + r * 0.4 {
                hits.push((i, Hit::Core));
            } else if c.dist - r <= RING + 3.0
                && c.dist + r >= RING - 4.0
                && turn(self.angle, c.angle).abs() <= SHIELD + r / RING
            {
                hits.push((i, Hit::Shield));
            }
        }
        for (i, hit) in hits.into_iter().rev() {
            self.resolve(i, hit);
        }
        (self.state == State::Over).then_some(self.score)
    }

    fn resolve(&mut self, i: usize, hit: Hit) {
        let (kind, hits, at) = {
            let c = &self.coins[i];
            (c.kind, c.hits, dir(c.angle) * c.dist)
        };
        match (hit, kind.bad()) {
            (Hit::Shield, true) if hits > 1 => {
                let c = &mut self.coins[i];
                c.hits -= 1;
                c.knock = 280.0;
                self.flash = FLASH;
                self.burst(at, Tone::Coin(kind), 5, 90.0);
                self.say(at, "crack", Tone::Quiet);
            }
            (Hit::Shield, true) => {
                self.coins.remove(i);
                self.combo += 1;
                self.blocked += 1;
                let points = 10 * self.mult();
                self.score += points;
                self.flash = FLASH;
                self.burst(at, Tone::Coin(kind), 9, 150.0);
                self.say(at, format!("+{points}"), Tone::Good);
            }
            (Hit::Shield, false) => {
                self.coins.remove(i);
                self.combo = 0;
                self.burst(at, Tone::Quiet, 6, 80.0);
                self.say(at, "those were sats!", Tone::Quiet);
            }
            (Hit::Core, true) => {
                self.coins.remove(i);
                self.lives = self.lives.saturating_sub(1);
                self.combo = 0;
                self.shake = SHAKE;
                self.burst(at, Tone::Bad, 14, 170.0);
                self.say(at, "−1", Tone::Bad);
                if self.lives == 0 {
                    self.state = State::Over;
                }
            }
            (Hit::Core, false) => {
                self.coins.remove(i);
                self.glow = GLOW;
                self.burst(at, Tone::Good, 8, 90.0);
                if kind == Kind::Halving {
                    self.slow = SLOW;
                    self.score += 50;
                    self.say(at, "Halving! Everything slows", Tone::Good);
                } else {
                    self.stacked += 1;
                    self.combo += 1;
                    let points = 20 * self.mult();
                    self.score += points;
                    self.say(at, format!("+{points} sats"), Tone::Good);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// The shelf
// ---------------------------------------------------------------------

const SKINS: [(Skin, &str, &str); 3] = [
    (
        Skin::Standard,
        "Normal",
        "Ink on ash; orange for what's proven",
    ),
    (Skin::Xp, "Windows XP", "The whole desktop, Luna blue"),
    (Skin::Julia, "Julia", "Pink, hearts and a bow on top"),
];

pub fn show(ui: &mut Ui, s: &Scene, game: &mut Game, prefs: &mut Prefs) {
    if game.open {
        play_view(ui, &s.pal, game, prefs);
    } else {
        shelf(ui, &s.pal, game, prefs);
    }
}

fn shelf(ui: &mut Ui, pal: &Palette, game: &mut Game, prefs: &mut Prefs) {
    ui.label(
        RichText::new("Toybox")
            .font(font(theme::TITLE, 26.0))
            .color(pal.text),
    );
    ui.label(
        RichText::new("Just for fun. Nothing in here touches your node.")
            .size(13.5)
            .color(pal.muted),
    );
    ui.add_space(22.0);
    widgets::section(ui, "Games", None);
    ui.add_space(6.0);
    game_card(ui, pal, game, prefs);
    ui.add_space(30.0);
    widgets::section(
        ui,
        "Skins",
        Some("the whole node wears it while the toybox is on"),
    );
    ui.add_space(6.0);
    skin_cards(ui, pal, prefs);
}

/// A card on the shelf.
fn card(p: &Painter, rect: Rect, pal: &Palette, lit: bool) {
    p.rect_filled(rect, 14, pal.raised);
    p.rect_stroke(
        rect,
        14,
        Stroke::new(
            if lit { 2.0 } else { 1.0 },
            if lit { pal.signal } else { pal.hairline },
        ),
        StrokeKind::Inside,
    );
}

fn game_card(ui: &mut Ui, pal: &Palette, game: &mut Game, prefs: &Prefs) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, 196.0), Sense::hover());
    card(ui.painter(), rect, pal, false);
    let art = Rect::from_min_size(
        rect.min + vec2(12.0, 12.0),
        vec2((width * 0.34).clamp(170.0, 280.0), rect.height() - 24.0),
    );
    poster(ui.painter(), art, pal);
    let text = Rect::from_min_max(
        pos2(art.right() + 24.0, rect.top() + 18.0),
        rect.max - vec2(20.0, 16.0),
    );
    let mut col = ui.new_child(
        UiBuilder::new()
            .max_rect(text)
            .layout(Layout::top_down(Align::Min)),
    );
    col.label(
        RichText::new("Shitcoin Defense")
            .font(font(theme::TITLE, 21.0))
            .color(pal.text),
    );
    col.add_space(2.0);
    col.label(
        RichText::new(
            "Shitcoins fly at the bitcoin from every side. Turn your shield to knock them away, and let the sats through. Three get in and it's over.",
        )
        .size(13.5)
        .color(pal.muted),
    );
    col.add_space(6.0);
    col.label(
        RichText::new(format!("Best {}", thousands(prefs.game_best.into())))
            .font(mono(13.0))
            .color(pal.text),
    );
    col.add_space(10.0);
    col.horizontal(|ui| {
        if game.state == State::Paused {
            if widgets::button(ui, "Resume", Button::Primary).clicked() {
                game.open = true;
            }
            if widgets::button(ui, "New game", Button::Quiet).clicked() {
                game.play();
            }
        } else if widgets::button(ui, "Play", Button::Primary).clicked() {
            game.play();
        }
    });
}

/// The game's box art: the bitcoin, the shield, and what's coming.
fn poster(p: &Painter, r: Rect, pal: &Palette) {
    let clip = p.with_clip_rect(r);
    clip.rect_filled(r, 10, pal.well);
    let c = r.center() + vec2(0.0, 6.0);
    let scale = (r.height() / 250.0).min(r.width() / 300.0);
    clip.circle_stroke(c, RING * scale, Stroke::new(1.0, pal.hairline));
    let ring = RING * scale;
    for (kind, angle, dist) in [
        (Kind::Scam, -2.5, 1.55),
        (Kind::Pump, -0.35, 1.2),
        (Kind::Rug, 2.55, 1.5),
        (Kind::Sats, 2.05, 1.12),
    ] {
        coin(
            &clip,
            c + dir(angle) * ring * dist,
            kind,
            false,
            1.0,
            pal,
            dir(angle),
        );
    }
    // A shitcoin mid-knock, in pieces.
    let knocked = c + dir(-1.2) * (ring + 12.0);
    for (dx, dy) in [
        (-9.0, -6.0),
        (8.0, -10.0),
        (12.0, 4.0),
        (-4.0, 9.0),
        (2.0, -14.0),
    ] {
        clip.circle_filled(knocked + vec2(dx, dy), 2.4, Kind::Scam.colors(pal).0);
    }
    shield(&clip, c, -1.2, ring, pal, 1.0);
    bitcoin(&clip, c, CORE * scale.max(0.7), pal, 0.0);
}

fn skin_cards(ui: &mut Ui, pal: &Palette, prefs: &mut Prefs) {
    let gap = 16.0;
    let width = ui.available_width();
    let w = ((width - 2.0 * gap) / 3.0).max(150.0);
    let shot_h = (w * 0.56).round();
    let (row, _) = ui.allocate_exact_size(vec2(width, shot_h + 76.0), Sense::hover());
    for (i, (skin, name, blurb)) in SKINS.iter().enumerate() {
        let r = Rect::from_min_size(
            row.min + vec2(i as f32 * (w + gap), 0.0),
            vec2(w, row.height()),
        );
        let resp = ui
            .interact(r, Id::new(("skin-card", i)), Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if resp.clicked() {
            prefs.skin = *skin;
        }
        let wearing = prefs.skin == *skin;
        let p = ui.painter();
        card(p, r, pal, wearing || resp.hovered());
        let shot = Rect::from_min_size(r.min + vec2(10.0, 10.0), vec2(w - 20.0, shot_h));
        preview(p, shot, *skin);
        let y = shot.bottom() + 12.0;
        p.text(
            pos2(r.left() + 14.0, y),
            Align2::LEFT_TOP,
            *name,
            font(theme::MEDIUM, 14.5),
            pal.text,
        );
        let (status, color) = if wearing {
            ("Wearing", pal.signal_text)
        } else if resp.hovered() {
            ("Wear it", pal.text)
        } else {
            (*blurb, pal.muted)
        };
        let status = widgets::fit(
            p,
            status.to_owned(),
            theme::body(12.5),
            color,
            r.width() - 28.0,
        );
        p.galley(pos2(r.left() + 14.0, y + 22.0), status, color);
        if resp.has_focus() {
            p.rect_stroke(
                r.expand(2.5),
                16,
                Stroke::new(1.5, pal.signal_text),
                StrokeKind::Outside,
            );
        }
    }
}

/// A skin in miniature: a little window in its clothes.
fn preview(p: &Painter, r: Rect, skin: Skin) {
    let clip = p.with_clip_rect(r);
    let rgb = Color32::from_rgb;
    let bar = |x: f32, y: f32, w: f32, h: f32, color: Color32| {
        clip.rect_filled(
            Rect::from_min_size(
                r.min + vec2(x, y) * r.size() / vec2(100.0, 56.0),
                vec2(w, h) * r.size() / vec2(100.0, 56.0),
            ),
            2,
            color,
        );
    };
    match skin {
        Skin::Standard => {
            let pal = Palette::LIGHT;
            clip.rect_filled(r, 8, pal.canvas);
            clip.rect_filled(
                Rect::from_min_size(r.min, vec2(r.width() * 0.12, r.height())),
                CornerRadius {
                    nw: 8,
                    sw: 8,
                    ne: 0,
                    se: 0,
                },
                theme::SIGNAL,
            );
            clip.circle_filled(r.min + vec2(r.width() * 0.06, 10.0), 4.0, theme::INK);
            bar(18.0, 7.0, 30.0, 4.0, pal.text);
            bar(18.0, 16.0, 44.0, 7.0, pal.text);
            bar(18.0, 29.0, 74.0, 7.0, pal.well);
            bar(18.0, 29.0, 50.0, 7.0, theme::SIGNAL);
            bar(18.0, 42.0, 22.0, 3.0, pal.faint);
            bar(46.0, 42.0, 22.0, 3.0, pal.faint);
            bar(74.0, 42.0, 18.0, 3.0, pal.faint);
        }
        Skin::Xp => {
            clip.rect_filled(r, 8, rgb(236, 233, 216));
            xp::gradient(
                &clip,
                Rect::from_min_size(r.min, vec2(r.width(), r.height() * 0.15)),
                CornerRadius {
                    nw: 8,
                    ne: 8,
                    sw: 0,
                    se: 0,
                },
                &[
                    (0.0, rgb(61, 149, 255)),
                    (0.3, rgb(0, 84, 227)),
                    (1.0, rgb(0, 63, 196)),
                ],
            );
            clip.rect_filled(
                Rect::from_center_size(
                    pos2(r.right() - 8.0, r.top() + r.height() * 0.075),
                    vec2(7.0, 7.0),
                ),
                1,
                rgb(222, 80, 48),
            );
            bar(0.0, 12.5, 24.0, 36.0, rgb(112, 140, 224));
            bar(3.0, 15.0, 18.0, 5.0, rgb(214, 223, 247));
            bar(3.0, 22.0, 18.0, 5.0, rgb(214, 223, 247));
            bar(24.0, 12.5, 76.0, 36.0, Color32::WHITE);
            bar(29.0, 17.0, 30.0, 3.5, rgb(22, 64, 168));
            bar(29.0, 25.0, 62.0, 7.0, rgb(50, 172, 50));
            bar(29.0, 36.0, 40.0, 3.0, rgb(150, 148, 138));
            // The taskbar and its start button.
            let task = Rect::from_min_max(pos2(r.left(), r.bottom() - r.height() * 0.13), r.max);
            clip.rect_filled(
                task,
                CornerRadius {
                    nw: 0,
                    ne: 0,
                    sw: 8,
                    se: 8,
                },
                rgb(36, 94, 219),
            );
            clip.rect_filled(
                Rect::from_min_size(task.min, vec2(r.width() * 0.2, task.height())),
                CornerRadius {
                    nw: 0,
                    sw: 8,
                    ne: 6,
                    se: 6,
                },
                rgb(61, 160, 55),
            );
            clip.text(
                task.left_center() + vec2(5.0, 0.0),
                Align2::LEFT_CENTER,
                "start",
                font(theme::START, (task.height() * 0.8).max(6.0)),
                Color32::WHITE,
            );
        }
        Skin::Julia => {
            let pal = Palette::JULIA;
            clip.rect_filled(r, 8, pal.canvas);
            for (x, y) in [
                (0.3, 0.2),
                (0.62, 0.12),
                (0.88, 0.3),
                (0.45, 0.62),
                (0.8, 0.72),
            ] {
                julia::heart(
                    &clip,
                    r.min + vec2(r.width() * x, r.height() * y),
                    6.0,
                    Color32::from_white_alpha(170),
                );
            }
            clip.rect_filled(
                Rect::from_min_size(r.min, vec2(r.width() * 0.12, r.height())),
                CornerRadius {
                    nw: 8,
                    sw: 8,
                    ne: 0,
                    se: 0,
                },
                pal.rail,
            );
            clip.text(
                r.min + vec2(r.width() * 0.18, r.height() * 0.08),
                Align2::LEFT_TOP,
                "Julia",
                font(theme::SCRIPT, (r.height() * 0.26).max(10.0)),
                pal.signal_text,
            );
            let ribbon = Rect::from_min_size(
                r.min + vec2(r.width() * 0.18, r.height() * 0.58),
                vec2(r.width() * 0.74, r.height() * 0.14),
            );
            clip.rect_filled(ribbon, 6, pal.well);
            let proven =
                Rect::from_min_size(ribbon.min, vec2(ribbon.width() * 0.66, ribbon.height()));
            clip.rect_filled(proven, 6, pal.signal);
            julia::candy(&clip, proven);
            julia::bow(
                &clip,
                pos2(proven.right(), ribbon.top() - 1.0),
                ribbon.height() * 1.7,
                pal.signal,
                pal.signal_text,
            );
            julia::sparkle(
                &clip,
                r.min + vec2(r.width() * 0.9, r.height() * 0.14),
                5.0,
                Color32::WHITE,
            );
        }
    }
    clip.rect_stroke(
        r,
        8,
        Stroke::new(1.0, Color32::from_black_alpha(30)),
        StrokeKind::Inside,
    );
}

// ---------------------------------------------------------------------
// The game
// ---------------------------------------------------------------------

fn play_view(ui: &mut Ui, pal: &Palette, game: &mut Game, prefs: &mut Prefs) {
    // The game's keys, taken before any button can act on them.
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
            RichText::new("Shitcoin Defense")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if matches!(game.state, State::Playing | State::Countdown(_)) {
                if widgets::button(ui, "Pause", Button::Quiet).clicked() {
                    game.pause();
                }
            } else if game.state == State::Paused
                && widgets::button(ui, "Resume", Button::Primary).clicked()
            {
                game.state = State::Playing;
            }
        });
    });
    ui.add_space(12.0);
    arena(ui, pal, game, prefs, space);
    ui.add_space(10.0);
    ui.label(
        RichText::new(
            "Point with the mouse, or turn with ← → (or A D). Knock the shitcoins away; let the sats into the bitcoin. Space pauses; Esc goes back to the toybox.",
        )
        .size(12.5)
        .color(pal.faint),
    );
    if leave {
        game.leave();
    }
}

fn arena(ui: &mut Ui, pal: &Palette, game: &mut Game, prefs: &mut Prefs, space: bool) {
    let (rect, resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), ARENA_HEIGHT), Sense::click());
    let center = rect.center();
    // A round field inside the frame: everything comes the same distance,
    // out of the haze at its edge.
    let field = (rect.height().min(rect.width()) / 2.0 - 12.0).max(RING + 60.0);
    let far = field + 16.0;

    let steer = ui.input(|i| {
        let left = i.key_down(Key::ArrowLeft) || i.key_down(Key::A);
        let right = i.key_down(Key::ArrowRight) || i.key_down(Key::D);
        f32::from(u8::from(right)) - f32::from(u8::from(left))
    });
    if resp.hovered() && ui.input(|i| i.pointer.delta() != Vec2::ZERO) {
        game.steered = Some(Instant::now());
    }
    let aim = if game.autopilot {
        game.coins
            .iter()
            .filter(|c| c.kind.bad())
            .min_by(|a, b| a.dist.total_cmp(&b.dist))
            .map(|c| c.angle)
    } else {
        resp.hover_pos()
            .filter(|_| steer == 0.0)
            .filter(|_| {
                game.steered
                    .is_some_and(|t| t.elapsed().as_secs_f32() < 1.5)
            })
            .map(|pos| (pos - center).angle())
    };

    let now = Instant::now();
    let dt = game
        .last
        .map_or(0.0, |l| now.duration_since(l).as_secs_f32());
    game.last = Some(now);
    // Away from the page mid-game: pause rather than lose while gone.
    if dt > 0.5 {
        game.pause();
    }
    match game.state {
        State::Playing | State::Countdown(_) if space => game.pause(),
        State::Paused if space || resp.clicked() => game.state = State::Playing,
        State::Over if space => game.play(),
        _ => {}
    }
    if let Some(score) = game.step(dt.min(0.05), steer, aim, far)
        && score > prefs.game_best
    {
        prefs.game_best = score;
        game.new_best = true;
    }
    draw(ui, rect, pal, game, prefs.game_best, field, far);
    if game.state == State::Over {
        over_card(ui, rect, pal, game, prefs.game_best);
    }
}

fn draw(ui: &Ui, rect: Rect, pal: &Palette, game: &mut Game, best: u32, field: f32, far: f32) {
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 16, pal.well);
    let jolt = if game.shake > 0.0 {
        let k = 7.0 * game.shake / SHAKE;
        vec2(game.rand() - 0.5, game.rand() - 0.5) * 2.0 * k
    } else {
        Vec2::ZERO
    };
    let c = rect.center() + jolt;
    p.circle_filled(c, field, pal.canvas.gamma_multiply(0.6));
    if game.slow > 0.0 {
        p.circle_stroke(
            c,
            field - 3.0,
            Stroke::new(4.0, pal.signal.gamma_multiply(0.3)),
        );
    }
    p.circle_stroke(c, RING, Stroke::new(1.0, pal.hairline));

    for k in &game.coins {
        let seen = ((far - k.dist) / 28.0).clamp(0.0, 1.0);
        coin(
            &p,
            c + dir(k.angle) * k.dist,
            k.kind,
            k.kind == Kind::Hype && k.hits < 2,
            seen,
            pal,
            dir(k.angle),
        );
    }
    bitcoin(&p, c, CORE, pal, game.glow / GLOW);
    shield(&p, c, game.angle, RING, pal, 1.0 + game.flash / FLASH);
    for s in &game.sparks {
        let f = 1.0 - s.age / s.life;
        p.circle_filled(c + s.at, s.size * f, s.tone.color(pal).gamma_multiply(f));
    }
    for fl in &game.floats {
        let f = fl.age / FLOAT_SECS;
        p.text(
            c + fl.at - vec2(0.0, 18.0 + 30.0 * f),
            Align2::CENTER_CENTER,
            &fl.text,
            font(theme::MEDIUM, 14.0),
            fl.tone.color(pal).gamma_multiply(1.0 - f * f),
        );
    }

    // The scoreboard in the corners.
    let inset = rect.shrink(16.0);
    let score = p.text(
        inset.left_top(),
        Align2::LEFT_TOP,
        thousands(game.score.into()),
        font(MONO_MEDIUM, 20.0),
        pal.text,
    );
    if game.mult() > 1 {
        p.text(
            pos2(score.right() + 10.0, score.center().y),
            Align2::LEFT_CENTER,
            format!("×{}", game.mult()),
            font(MONO_MEDIUM, 15.0),
            pal.signal_text,
        );
    }
    p.text(
        inset.left_top() + vec2(0.0, 26.0),
        Align2::LEFT_TOP,
        format!("{} blocked · {} sats", game.blocked, game.stacked),
        theme::body(12.0),
        pal.muted,
    );
    p.text(
        inset.right_top(),
        Align2::RIGHT_TOP,
        format!("Wave {}", game.wave),
        font(theme::MEDIUM, 15.0),
        pal.text,
    );
    p.text(
        inset.right_top() + vec2(0.0, 22.0),
        Align2::RIGHT_TOP,
        wave_name(game.wave),
        theme::body(12.0),
        pal.muted,
    );
    // Lives: three confirmations, as a little chain.
    let base = inset.left_bottom() - vec2(0.0, 22.0);
    for i in 0..LIVES {
        let b = Rect::from_min_size(base + vec2(f32::from(i) * 22.0, 0.0), vec2(14.0, 14.0));
        if i + 1 < LIVES {
            p.hline(
                (b.right())..=(b.right() + 8.0),
                b.center().y,
                Stroke::new(1.5, pal.faint),
            );
        }
        if i < game.lives {
            p.rect_filled(b, 3, pal.text);
        } else {
            p.rect_stroke(b, 3, Stroke::new(1.3, pal.alert), StrokeKind::Inside);
            p.line_segment(
                [b.left_top(), b.right_bottom()],
                Stroke::new(1.3, pal.alert),
            );
        }
    }
    p.text(
        base + vec2(0.0, 18.0),
        Align2::LEFT_TOP,
        "confirmations left",
        theme::body(11.0),
        pal.faint,
    );
    p.text(
        inset.right_bottom(),
        Align2::RIGHT_BOTTOM,
        format!("Best {}", thousands(best.into())),
        mono(12.5),
        pal.muted,
    );
    if game.slow > 0.0 {
        p.text(
            pos2(rect.center().x, inset.top()),
            Align2::CENTER_TOP,
            format!("Halving · {:.0}s", game.slow.ceil()),
            font(theme::MEDIUM, 14.0),
            pal.signal_text,
        );
    }

    // What the moment calls for, in the middle.
    match game.state {
        State::Countdown(t) => {
            let n = (t / (COUNTDOWN / 3.0)).ceil().clamp(1.0, 3.0) as u32;
            let beat = (t / (COUNTDOWN / 3.0)).fract();
            dim(&p, rect, pal);
            p.text(
                rect.center() - vec2(0.0, 40.0),
                Align2::CENTER_CENTER,
                n.to_string(),
                font(theme::TITLE, 56.0 + 18.0 * beat),
                pal.text,
            );
            legend(&p, rect.center() + vec2(0.0, 40.0), pal);
        }
        State::Playing if game.banner > 0.0 => {
            let f = (game.banner / BANNER).min(1.0);
            let alpha = (f * 3.0).min(1.0);
            p.text(
                rect.center() - vec2(0.0, 150.0),
                Align2::CENTER_CENTER,
                format!("Wave {}", game.wave),
                font(theme::TITLE, 30.0),
                pal.text.gamma_multiply(alpha),
            );
            p.text(
                rect.center() - vec2(0.0, 120.0),
                Align2::CENTER_CENTER,
                wave_name(game.wave),
                font(theme::MEDIUM, 15.0),
                pal.muted.gamma_multiply(alpha),
            );
        }
        State::Paused => {
            dim(&p, rect, pal);
            p.text(
                rect.center() - vec2(0.0, 16.0),
                Align2::CENTER_CENTER,
                "Paused",
                font(theme::TITLE, 30.0),
                pal.text,
            );
            p.text(
                rect.center() + vec2(0.0, 18.0),
                Align2::CENTER_CENTER,
                "Space or a click to go on · Esc for the toybox",
                theme::body(13.5),
                pal.muted,
            );
        }
        _ => {}
    }
}

fn dim(p: &Painter, rect: Rect, pal: &Palette) {
    p.rect_filled(rect, 16, pal.well.gamma_multiply(0.72));
}

/// The one rule, under the countdown: which to stop, which to let in.
fn legend(p: &Painter, at: Pos2, pal: &Palette) {
    let row = |x: f32, kinds: &[Kind], text: &str| {
        let mut cx = x;
        for kind in kinds {
            coin(p, pos2(cx, at.y), *kind, false, 1.0, pal, vec2(1.0, 0.0));
            cx += 30.0;
        }
        p.text(
            pos2(cx - 6.0, at.y),
            Align2::LEFT_CENTER,
            text,
            font(theme::MEDIUM, 14.0),
            pal.text,
        );
    };
    row(at.x - 250.0, &[Kind::Scam, Kind::Pump], "Knock these away");
    row(at.x + 40.0, &[Kind::Sats], "Let these in");
}

/// The game-over card, with its buttons.
fn over_card(ui: &mut Ui, rect: Rect, pal: &Palette, game: &mut Game, best: u32) {
    let card_rect = Rect::from_center_size(rect.center(), vec2(360.0, 232.0));
    let p = ui.painter_at(rect);
    dim(&p, rect, pal);
    p.rect_filled(
        card_rect.translate(vec2(0.0, 3.0)),
        16,
        Color32::from_black_alpha(30),
    );
    p.rect_filled(card_rect, 16, pal.raised);
    p.rect_stroke(
        card_rect,
        16,
        Stroke::new(1.0, pal.hairline),
        StrokeKind::Inside,
    );
    p.text(
        card_rect.center_top() + vec2(0.0, 34.0),
        Align2::CENTER_CENTER,
        "Rekt!",
        font(theme::TITLE, 32.0),
        pal.alert,
    );
    p.text(
        card_rect.center_top() + vec2(0.0, 62.0),
        Align2::CENTER_CENTER,
        "Three shitcoins got into the bitcoin.",
        theme::body(13.0),
        pal.muted,
    );
    let score_line = if game.new_best {
        format!("{} · a new best!", thousands(game.score.into()))
    } else {
        format!(
            "{} · best {}",
            thousands(game.score.into()),
            thousands(best.into())
        )
    };
    p.text(
        card_rect.center_top() + vec2(0.0, 98.0),
        Align2::CENTER_CENTER,
        score_line,
        font(MONO_MEDIUM, 17.0),
        if game.new_best {
            pal.signal_text
        } else {
            pal.text
        },
    );
    p.text(
        card_rect.center_top() + vec2(0.0, 126.0),
        Align2::CENTER_CENTER,
        format!(
            "Wave {} · {} blocked · {} sats stacked",
            game.wave, game.blocked, game.stacked
        ),
        theme::body(12.5),
        pal.muted,
    );
    let buttons = Rect::from_min_max(
        card_rect.left_bottom() + vec2(24.0, -58.0),
        card_rect.right_bottom() - vec2(24.0, 18.0),
    );
    let mut row = ui.new_child(
        UiBuilder::new()
            .max_rect(buttons)
            .layout(Layout::left_to_right(Align::Center)),
    );
    if widgets::button(&mut row, "Play again", Button::Primary).clicked() {
        game.play();
    }
    row.add_space(8.0);
    if widgets::button(&mut row, "Back to the toybox", Button::Quiet).clicked() {
        game.shelve();
    }
}

/// A coin in flight. Shitcoins wear their ticker; sats wear ₿.
fn coin(
    p: &Painter,
    at: Pos2,
    kind: Kind,
    cracked: bool,
    alpha: f32,
    pal: &Palette,
    outward: Vec2,
) {
    let r = kind.radius();
    let (fill, rim) = kind.colors(pal);
    let a = |color: Color32| color.gamma_multiply(alpha);
    if kind == Kind::Pump {
        // Its rocket exhaust, trailing behind.
        for (k, s, heat) in [(1.0, 0.72, 0.5), (1.85, 0.52, 0.35), (2.6, 0.34, 0.2)] {
            p.circle_filled(
                at + outward * r * k,
                r * s,
                a(Color32::from_rgb(255, 128, 40)).gamma_multiply(heat),
            );
        }
    }
    if !kind.bad() {
        p.circle_filled(at, r + 5.0, a(fill.gamma_multiply(0.22)));
    }
    p.circle_filled(at + vec2(1.5, 2.0), r, a(Color32::from_black_alpha(36)));
    p.circle_filled(at, r, a(fill));
    p.circle_stroke(at, r - 1.0, Stroke::new(2.2, a(rim)));
    p.circle_stroke(at, r - 4.2, Stroke::new(0.8, a(rim.gamma_multiply(0.55))));
    let (size, ink) = match kind {
        Kind::Sats => (
            13.0,
            if Skin::current() == Skin::Standard {
                theme::INK
            } else {
                Color32::WHITE
            },
        ),
        Kind::Halving => (14.0, pal.signal_text),
        _ => (8.6, Color32::from_rgb(255, 241, 224)),
    };
    p.text(
        at,
        Align2::CENTER_CENTER,
        kind.label(),
        font(MONO_MEDIUM, size),
        a(ink),
    );
    if cracked {
        let crack = Stroke::new(1.4, a(Color32::from_rgb(40, 24, 12)));
        p.line_segment(
            [at + vec2(-r * 0.7, -r * 0.5), at + vec2(-r * 0.1, 0.0)],
            crack,
        );
        p.line_segment(
            [at + vec2(-r * 0.1, 0.0), at + vec2(r * 0.2, -r * 0.6)],
            crack,
        );
        p.line_segment(
            [at + vec2(-r * 0.1, 0.0), at + vec2(r * 0.4, r * 0.65)],
            crack,
        );
    }
}

/// The bitcoin in the middle, glowing after it stacks something.
fn bitcoin(p: &Painter, c: Pos2, r: f32, pal: &Palette, glow: f32) {
    p.circle_filled(
        c,
        r + 6.0 + 10.0 * glow,
        pal.signal_alpha(0.18 + 0.25 * glow),
    );
    p.circle_filled(c, r, pal.signal);
    p.circle_stroke(c, r - 3.0, Stroke::new(1.2, Color32::from_white_alpha(90)));
    let ink = if Skin::current() == Skin::Standard {
        theme::INK
    } else {
        Color32::WHITE
    };
    p.text(c, Align2::CENTER_CENTER, "₿", mono(r * 1.15), ink);
}

/// The shield on its ring, and the guardian behind it with laser eyes.
/// `power` above 1 flashes it after a knock.
fn shield(p: &Painter, c: Pos2, angle: f32, ring: f32, pal: &Palette, power: f32) {
    let arc: Vec<Pos2> = (0..=18)
        .map(|i| c + dir(angle - SHIELD + 2.0 * SHIELD * i as f32 / 18.0) * ring)
        .collect();
    let hot = (power - 1.0).clamp(0.0, 1.0);
    p.add(Shape::line(
        arc,
        Stroke::new(5.0 + 3.0 * hot, pal.text.lerp_to_gamma(pal.signal, hot)),
    ));
    let out = dir(angle);
    let g = c + out * (ring - 14.0);
    p.circle_filled(g, 8.0, pal.text);
    let side = vec2(-out.y, out.x);
    let laser = Color32::from_rgb(255, 48, 48);
    for sgn in [-1.0, 1.0] {
        let eye = g + out * 3.0 + side * 3.2 * sgn;
        p.circle_filled(eye, 1.7, laser);
        p.line_segment(
            [eye, eye + out * 8.0],
            Stroke::new(1.2, laser.gamma_multiply(0.55)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A game in play with nothing arriving on its own.
    fn quiet() -> Game {
        let mut g = Game::default();
        g.play();
        g.state = State::Playing;
        g.next_spawn = 1e9;
        g.angle = 0.0;
        g
    }

    fn incoming(kind: Kind, angle: f32, speed: f32) -> Coin {
        Coin {
            kind,
            angle,
            dist: RING + 40.0,
            speed,
            phase: 0.0,
            hits: if kind == Kind::Hype { 2 } else { 1 },
            knock: 0.0,
        }
    }

    fn run(g: &mut Game, frames: usize) -> Option<u32> {
        let mut end = None;
        for _ in 0..frames {
            end = end.or(g.step(0.02, 0.0, None, 500.0));
        }
        end
    }

    #[test]
    fn the_shield_knocks_a_shitcoin_away() {
        let mut g = quiet();
        g.coins.push(incoming(Kind::Scam, 0.05, 60.0));
        assert_eq!(run(&mut g, 60), None);
        assert_eq!((g.score, g.blocked, g.lives), (10, 1, LIVES));
        assert!(g.coins.is_empty());
    }

    #[test]
    fn three_shitcoins_in_and_it_is_over() {
        let mut g = quiet();
        for _ in 0..2 {
            g.coins.push(incoming(Kind::Scam, PI, 120.0));
            assert_eq!(run(&mut g, 100), None);
        }
        assert_eq!(g.lives, 1);
        g.coins.push(incoming(Kind::Scam, PI, 120.0));
        assert_eq!(run(&mut g, 100), Some(0));
        assert_eq!(g.state, State::Over);
    }

    #[test]
    fn sats_are_let_in_not_blocked() {
        let mut g = quiet();
        g.coins.push(incoming(Kind::Sats, PI, 90.0));
        run(&mut g, 100);
        assert_eq!((g.stacked, g.lives), (1, LIVES));
        assert!(g.score > 0);
        // Blocked instead, they're lost, and so is the streak.
        g.combo = 7;
        g.coins.push(incoming(Kind::Sats, 0.0, 90.0));
        run(&mut g, 100);
        assert_eq!((g.stacked, g.combo), (1, 0));
    }

    #[test]
    fn hype_takes_two_knocks() {
        let mut g = quiet();
        g.coins.push(incoming(Kind::Hype, 0.0, 80.0));
        run(&mut g, 400);
        assert_eq!(g.blocked, 1);
        assert!(g.coins.is_empty());
        assert!(g.floats.iter().any(|f| f.text == "crack") || g.blocked == 1);
    }

    #[test]
    fn a_halving_slows_the_shitcoins() {
        let mut g = quiet();
        g.coins.push(incoming(Kind::Halving, PI, 90.0));
        run(&mut g, 100);
        assert!(g.slow > 0.0);
    }

    #[test]
    fn waves_get_faster_and_busier() {
        let mut g = quiet();
        g.spawn(500.0);
        let early_speed = g.coins[0].speed / g.coins[0].kind.pace();
        let early_gap = g.interval();
        g.coins.clear();
        g.wave = 8;
        g.spawn(500.0);
        let late_speed = g.coins[0].speed / g.coins[0].kind.pace();
        let late_gap = g.interval();
        assert!(
            late_speed > early_speed * 1.6,
            "{early_speed} → {late_speed}"
        );
        assert!(late_gap < early_gap, "{early_gap} → {late_gap}");
    }

    #[test]
    fn the_countdown_comes_first() {
        let mut g = Game::default();
        g.play();
        assert!(matches!(g.state, State::Countdown(_)));
        for _ in 0..130 {
            g.step(0.02, 0.0, None, 500.0);
        }
        assert_eq!(g.state, State::Playing);
    }
}
