//! `AVILA_GUI_CAPTURE=<dir>`: walks every page in both appearances,
//! saves a PNG of each, then quits — so the interface can be reviewed
//! (by a person or an agent) without clicking through it. Pair it with
//! `--demo` for reproducible content.

use crate::rail::Page;
use crate::ribbon::Scale;
use crate::theme::Skin;
use eframe::egui::{
    self, ColorImage, Context, Event, PointerButton, RawInput, Theme, UserData, ViewportCommand,
};
use std::path::PathBuf;

/// Frames to let layout, fonts and textures settle before each shot.
const SETTLE: u32 = 14;
/// Frames of a game playing itself before its shot.
const PLAY_SETTLE: u32 = 300;
/// A pose's pointer steps start this many frames in, one every `STEP`.
const STEP_START: u32 = 4;
const STEP: u32 = 3;

/// A pointer step, in points: move there, and click if asked.
pub type Step = (f32, f32, bool);

/// What's open on the XP skin's desktop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Desk {
    #[default]
    Window,
    StartMenu,
    /// The window restored, over the wallpaper.
    Restored,
    TurnOff,
    About,
}

/// How the app should be posed for one shot.
#[derive(Clone, Copy, Debug)]
pub struct Pose {
    pub page: Page,
    pub scale: Scale,
    /// Open the first peer's panel.
    pub select_peer: bool,
    /// Scroll the page down this far.
    pub scroll: f32,
    pub hide: bool,
    pub clock: bool,
    /// Zoom the Chain page's ribbon to this slice of it.
    pub zoom: Option<(f64, f64)>,
    /// Pretend the node raised an eclipse indicator.
    pub eclipse: bool,
    /// Open the Settings page's advanced section.
    pub advanced: bool,
    /// Wear this toybox skin.
    pub skin: Skin,
    /// Let the game play itself for a while.
    pub play: bool,
    /// Open a finished game.
    pub over: bool,
    pub desk: Desk,
    /// Pointer steps to play once posed: open a menu, hover an item.
    pub pointer: &'static [Step],
}

#[derive(Clone, Copy)]
struct Shot {
    theme: Theme,
    pose: Pose,
    size: [f32; 2],
    name: &'static str,
}

pub struct Capture {
    dir: PathBuf,
    shots: Vec<Shot>,
    next: usize,
    wait: u32,
    requested: bool,
    /// Whether the current shot has been posed yet.
    posed: bool,
    /// Frames since it was.
    posed_frames: u32,
}

fn file_name(shot: &Shot) -> String {
    format!(
        "{}-{}{}.png",
        if shot.theme == Theme::Dark {
            "dark"
        } else {
            "light"
        },
        shot.pose.page.label().to_lowercase(),
        shot.name,
    )
}

impl Capture {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let dir = PathBuf::from(std::env::var_os("AVILA_GUI_CAPTURE")?);
        std::fs::create_dir_all(&dir).ok()?;
        const FULL: [f32; 2] = [1120.0, 760.0];
        // The smallest window the app allows.
        const SMALL: [f32; 2] = [760.0, 480.0];
        let pose = |page| Pose {
            page,
            scale: Scale::Blocks,
            select_peer: false,
            scroll: 0.0,
            hide: false,
            clock: false,
            zoom: None,
            eclipse: false,
            advanced: false,
            skin: Skin::Standard,
            play: false,
            over: false,
            desk: Desk::Window,
            pointer: &[],
        };
        let mut shots = Vec::new();
        for theme in [Theme::Light, Theme::Dark] {
            for page in Page::ALL {
                shots.push(Shot {
                    theme,
                    pose: pose(page),
                    size: FULL,
                    name: "",
                });
            }
        }
        let by_work = |page| Pose {
            scale: Scale::Work,
            ..pose(page)
        };
        let picked = Pose {
            select_peer: true,
            ..pose(Page::Peers)
        };
        let xp = |page| Pose {
            skin: Skin::Xp,
            ..pose(page)
        };
        let julia = |page| Pose {
            skin: Skin::Julia,
            ..pose(page)
        };
        for (theme, pose, size, name) in [
            (Theme::Light, by_work(Page::Overview), FULL, "-work"),
            (Theme::Dark, by_work(Page::Chain), FULL, "-work"),
            (Theme::Light, picked, FULL, "-selected"),
            (Theme::Dark, picked, FULL, "-selected"),
            (
                Theme::Light,
                Pose {
                    scroll: 620.0,
                    ..pose(Page::Chain)
                },
                FULL,
                "-lower",
            ),
            (
                Theme::Dark,
                Pose {
                    scroll: 420.0,
                    ..picked
                },
                FULL,
                "-selected-lower",
            ),
            (
                Theme::Light,
                Pose {
                    hide: true,
                    eclipse: true,
                    ..picked
                },
                FULL,
                "-hidden",
            ),
            (
                Theme::Light,
                Pose {
                    scroll: 620.0,
                    clock: true,
                    ..pose(Page::Chain)
                },
                FULL,
                "-clock",
            ),
            (
                Theme::Dark,
                Pose {
                    scroll: 620.0,
                    clock: true,
                    ..pose(Page::Chain)
                },
                FULL,
                "-clock",
            ),
            (
                Theme::Light,
                Pose {
                    zoom: Some((0.99995, 1.0)),
                    ..pose(Page::Chain)
                },
                FULL,
                "-zoomed",
            ),
            (
                Theme::Light,
                Pose {
                    zoom: Some((0.999_985, 1.0)),
                    ..pose(Page::Chain)
                },
                FULL,
                "-zoomed-close",
            ),
            (
                Theme::Dark,
                Pose {
                    advanced: true,
                    scroll: 560.0,
                    ..pose(Page::Settings)
                },
                FULL,
                "-advanced",
            ),
            (
                Theme::Light,
                Pose {
                    play: true,
                    ..pose(Page::Toybox)
                },
                FULL,
                "-play",
            ),
            (
                Theme::Light,
                Pose {
                    skin: Skin::Xp,
                    ..pose(Page::Overview)
                },
                FULL,
                "-xp",
            ),
            (
                Theme::Light,
                Pose {
                    skin: Skin::Xp,
                    ..pose(Page::Toybox)
                },
                FULL,
                "-xp",
            ),
            (
                Theme::Light,
                Pose {
                    skin: Skin::Julia,
                    ..pose(Page::Overview)
                },
                FULL,
                "-julia",
            ),
            (
                Theme::Light,
                Pose {
                    skin: Skin::Julia,
                    select_peer: true,
                    ..pose(Page::Peers)
                },
                FULL,
                "-julia",
            ),
            (
                Theme::Light,
                Pose {
                    scroll: 600.0,
                    ..pose(Page::Settings)
                },
                FULL,
                "-appearance",
            ),
            (Theme::Light, pose(Page::Toybox), FULL, ""),
            (Theme::Dark, pose(Page::Toybox), FULL, ""),
            (
                Theme::Light,
                Pose {
                    over: true,
                    ..pose(Page::Toybox)
                },
                FULL,
                "-over",
            ),
            (Theme::Light, julia(Page::Chain), FULL, "-julia"),
            (
                Theme::Light,
                Pose {
                    advanced: true,
                    ..julia(Page::Settings)
                },
                FULL,
                "-julia",
            ),
            (Theme::Light, julia(Page::Toybox), FULL, "-julia"),
            (
                Theme::Light,
                Pose {
                    play: true,
                    ..julia(Page::Toybox)
                },
                FULL,
                "-julia-play",
            ),
            (Theme::Dark, pose(Page::Overview), SMALL, "-small"),
            (Theme::Light, pose(Page::Peers), SMALL, "-small"),
            (Theme::Light, xp(Page::Chain), FULL, "-xp"),
            (
                Theme::Light,
                Pose {
                    select_peer: true,
                    ..xp(Page::Peers)
                },
                FULL,
                "-xp",
            ),
            (Theme::Light, xp(Page::Activity), FULL, "-xp"),
            (
                Theme::Light,
                Pose {
                    scroll: 600.0,
                    ..xp(Page::Peers)
                },
                FULL,
                "-xp-table",
            ),
            (
                Theme::Light,
                Pose {
                    advanced: true,
                    ..xp(Page::Settings)
                },
                FULL,
                "-xp",
            ),
            (
                Theme::Light,
                Pose {
                    desk: Desk::StartMenu,
                    ..xp(Page::Overview)
                },
                FULL,
                "-xp-start",
            ),
            (
                Theme::Light,
                Pose {
                    desk: Desk::Restored,
                    ..xp(Page::Chain)
                },
                FULL,
                "-xp-desktop",
            ),
            (
                Theme::Light,
                Pose {
                    eclipse: true,
                    ..xp(Page::Overview)
                },
                FULL,
                "-xp-eclipse",
            ),
            (
                Theme::Light,
                Pose {
                    desk: Desk::TurnOff,
                    ..xp(Page::Overview)
                },
                FULL,
                "-xp-turnoff",
            ),
            (
                Theme::Light,
                Pose {
                    desk: Desk::About,
                    ..xp(Page::Peers)
                },
                FULL,
                "-xp-about",
            ),
            (Theme::Light, xp(Page::Overview), SMALL, "-xp-small"),
            (
                Theme::Light,
                Pose {
                    // Open View, then point at its second item.
                    pointer: &[(66.0, 41.0, true), (110.0, 88.0, false)],
                    ..xp(Page::Chain)
                },
                FULL,
                "-xp-menu",
            ),
        ] {
            shots.push(Shot {
                theme,
                pose,
                size,
                name,
            });
        }
        // `AVILA_GUI_CAPTURE_ONLY=xp` takes just the shots so named.
        if let Ok(only) = std::env::var("AVILA_GUI_CAPTURE_ONLY") {
            shots.retain(|shot| file_name(shot).contains(&only));
        }
        Some(Self {
            dir,
            shots,
            next: 0,
            wait: SETTLE,
            requested: false,
            posed: false,
            posed_frames: 0,
        })
    }

    /// Plays the current shot's pointer steps into egui's input, before
    /// the frame runs.
    pub fn feed(&mut self, raw: &mut RawInput) {
        let frame = self.posed_frames;
        self.posed_frames = self.posed_frames.saturating_add(1);
        let Some(shot) = self.shots.get(self.next) else {
            return;
        };
        let Some(k) = frame.checked_sub(STEP_START) else {
            return;
        };
        let Some(&(x, y, click)) = shot.pose.pointer.get((k / STEP) as usize) else {
            return;
        };
        let pos = egui::pos2(x, y);
        let button = |pressed| Event::PointerButton {
            pos,
            button: PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        match k % STEP {
            0 => {
                raw.events.push(Event::PointerMoved(pos));
                if click {
                    raw.events.push(button(true));
                }
            }
            1 if click => raw.events.push(button(false)),
            _ => {}
        }
    }

    /// Runs at the top of every frame: saves a shot that arrived, says how
    /// to pose the app for the next one, and asks for it once things
    /// settle. `None` once every shot is taken (the window then closes).
    pub fn drive(&mut self, ctx: &Context) -> Option<Pose> {
        let arrived = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let (Some(image), Some(shot)) = (arrived, self.shots.get(self.next).copied())
            && self.requested
        {
            let name = file_name(&shot);
            if let Err(e) = std::fs::write(self.dir.join(&name), png(&image)) {
                eprintln!("capture: couldn't write {name}: {e}");
            }
            self.next += 1;
            self.requested = false;
            self.posed = false;
        }
        let Some(shot) = self.shots.get(self.next).copied() else {
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return None;
        };
        if !self.posed {
            self.posed = true;
            self.posed_frames = 0;
            let steps = STEP_START + STEP * shot.pose.pointer.len() as u32 + 30;
            self.wait = if shot.pose.play {
                PLAY_SETTLE
            } else {
                SETTLE.max(steps)
            };
            ctx.send_viewport_cmd(ViewportCommand::InnerSize(egui::vec2(
                shot.size[0],
                shot.size[1],
            )));
        }
        ctx.set_theme(shot.theme);
        if !self.requested {
            if self.wait == 0 {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(UserData::default()));
                self.requested = true;
            } else {
                self.wait -= 1;
            }
        }
        ctx.request_repaint();
        Some(shot.pose)
    }
}

/// A minimal PNG encoder — stored (uncompressed) deflate blocks — so the
/// harness needs no image crate.
fn png(image: &ColorImage) -> Vec<u8> {
    let [w, h] = image.size;
    let mut raw = Vec::with_capacity((w * 4 + 1) * h);
    for row in image.pixels.chunks(w.max(1)) {
        raw.push(0); // filter: none
        for p in row {
            raw.extend_from_slice(&p.to_srgba_unmultiplied());
        }
    }
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &zlib_stored(&raw));
    chunk(&mut out, b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = data.chunks(65_535).collect();
    if blocks.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    }
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFF_u32;
    for &byte in data {
        c ^= u32::from(byte);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_known_values() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn png_has_the_right_frame() {
        let img = ColorImage::new([3, 2], vec![egui::Color32::from_rgb(247, 139, 19); 6]);
        let bytes = png(&img);
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(bytes.ends_with(&[0xAE, 0x42, 0x60, 0x82]));
        // IHDR: width 3, height 2.
        assert_eq!(&bytes[16..24], &[0, 0, 0, 3, 0, 0, 0, 2]);
    }
}
