//! `AVILA_GUI_BENCH=1` (best with `--demo`): measures what each page
//! costs, prints a table, and quits. For every page it first lets the app
//! run as it normally would and counts repaints — the idle cost of
//! leaving the window open — then forces repaints and times each frame,
//! the cost of interacting with it.

use crate::rail::Page;
use eframe::egui::{Context, ViewportCommand};
use std::time::{Duration, Instant};

const IDLE: Duration = Duration::from_secs(6);
/// Let a page's entrance animations finish before counting idle frames.
const SETTLE: Duration = Duration::from_secs(3);
const WARM: u32 = 12;
const FORCED: usize = 150;

enum Stage {
    Warm(u32),
    Settle(Instant),
    Idle { since: Instant, frames: u32 },
    Forced(Vec<f32>),
}

struct Row {
    page: Page,
    idle_fps: f32,
    frame_ms: Vec<f32>,
}

pub struct Bench {
    page: usize,
    stage: Stage,
    rows: Vec<Row>,
    idle_fps: f32,
}

impl Bench {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        std::env::var_os("AVILA_GUI_BENCH")?;
        Some(Self {
            page: 0,
            stage: Stage::Warm(WARM),
            rows: Vec::new(),
            idle_fps: 0.0,
        })
    }

    /// Whether this frame should be followed by another right away.
    #[must_use]
    pub fn forcing(&self) -> bool {
        matches!(self.stage, Stage::Warm(_) | Stage::Forced(_))
    }

    /// Runs at the top of every frame with the previous frame's CPU time.
    /// Returns the page to show, or `None` once done (the window closes).
    pub fn drive(&mut self, ctx: &Context, cpu_secs: Option<f32>) -> Option<Page> {
        let page = *Page::ALL.get(self.page)?;
        match &mut self.stage {
            Stage::Warm(0) => self.stage = Stage::Settle(Instant::now()),
            Stage::Warm(n) => *n -= 1,
            Stage::Settle(since) => {
                if since.elapsed() >= SETTLE {
                    self.stage = Stage::Idle {
                        since: Instant::now(),
                        frames: 0,
                    };
                }
            }
            Stage::Idle { since, frames } => {
                *frames += 1;
                if since.elapsed() >= IDLE {
                    self.idle_fps = *frames as f32 / since.elapsed().as_secs_f32();
                    self.stage = Stage::Forced(Vec::with_capacity(FORCED));
                }
            }
            Stage::Forced(samples) => {
                if let Some(s) = cpu_secs {
                    samples.push(s * 1000.0);
                }
                if samples.len() >= FORCED {
                    self.rows.push(Row {
                        page,
                        idle_fps: self.idle_fps,
                        frame_ms: std::mem::take(samples),
                    });
                    self.page += 1;
                    self.stage = Stage::Warm(WARM);
                    if self.page >= Page::ALL.len() {
                        self.report();
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                        return None;
                    }
                }
            }
        }
        if self.forcing() {
            ctx.request_repaint();
        }
        Page::ALL.get(self.page).copied()
    }

    fn report(&self) {
        eprintln!(
            "{:<10} {:>9} {:>10} {:>10} {:>10}",
            "page", "idle fps", "frame avg", "p95 ms", "max ms"
        );
        for row in &self.rows {
            let mut ms = row.frame_ms.clone();
            ms.sort_by(f32::total_cmp);
            let avg = ms.iter().sum::<f32>() / ms.len().max(1) as f32;
            let p95 = ms.get(ms.len() * 95 / 100).copied().unwrap_or(0.0);
            let max = ms.last().copied().unwrap_or(0.0);
            eprintln!(
                "{:<10} {:>9.1} {:>10.2} {:>10.2} {:>10.2}",
                row.page.label(),
                row.idle_fps,
                avg,
                p95,
                max
            );
        }
    }
}
