//! `AVILA_GUI_CAPTURE=<dir>`: walks every page in both appearances,
//! saves a PNG of each, then quits — so the interface can be reviewed
//! (by a person or an agent) without clicking through it. Pair it with
//! `--demo` for reproducible content.

use crate::rail::Page;
use crate::ribbon::Scale;
use eframe::egui::{self, ColorImage, Context, Event, Theme, UserData, ViewportCommand};
use std::path::PathBuf;

/// Frames to let layout, fonts and textures settle before each shot.
const SETTLE: u32 = 14;

/// How the app should be posed for one shot.
#[derive(Clone, Copy, Debug)]
pub struct Pose {
    pub page: Page,
    pub scale: Scale,
    /// Open the first peer's panel.
    pub select_peer: bool,
    /// Scroll the page down this far.
    pub scroll: f32,
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
            (Theme::Dark, pose(Page::Overview), SMALL, "-small"),
            (Theme::Light, pose(Page::Peers), SMALL, "-small"),
        ] {
            shots.push(Shot {
                theme,
                pose,
                size,
                name,
            });
        }
        Some(Self {
            dir,
            shots,
            next: 0,
            wait: SETTLE,
            requested: false,
        })
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
            let name = format!(
                "{}-{}{}.png",
                if shot.theme == Theme::Dark {
                    "dark"
                } else {
                    "light"
                },
                shot.pose.page.label().to_lowercase(),
                shot.name,
            );
            if let Err(e) = std::fs::write(self.dir.join(&name), png(&image)) {
                eprintln!("capture: couldn't write {name}: {e}");
            }
            self.next += 1;
            self.wait = SETTLE;
            self.requested = false;
        }
        let Some(shot) = self.shots.get(self.next).copied() else {
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return None;
        };
        if self.wait == SETTLE {
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
