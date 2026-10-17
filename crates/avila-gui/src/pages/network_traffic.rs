//! Bounded history of node-wide traffic counters, including disconnected peers.

use super::{Action, Scene};
use crate::session::Sample;
use crate::theme::{self, font, mono};
use crate::widgets;
use eframe::egui::{Align2, Sense, Stroke, Ui, pos2, vec2};

const WINDOW: usize = 120;
const MAX_INTERVAL_SECS: f64 = 2.5;
const CHART_HEIGHT: f32 = 220.0;

#[derive(Clone, Copy)]
struct Rate {
    recv: f64,
    sent: f64,
}

pub fn show(ui: &mut Ui, s: &Scene) -> Option<Action> {
    widgets::section(
        ui,
        "Network traffic",
        Some("Node-wide totals, including peers that disconnected"),
    );
    if s.session.demo {
        ui.label(
            eframe::egui::RichText::new(
                "Demo mode is simulated; these counters are not live network traffic.",
            )
            .size(13.0)
            .color(s.pal.muted),
        );
    }
    let run_label = if s.session.running() {
        format!("Live · {}", s.session.phase().label())
    } else {
        format!("Last run · {}", s.session.phase().label())
    };
    ui.label(
        eframe::egui::RichText::new(run_label)
            .size(12.5)
            .color(s.pal.muted),
    );
    ui.add_space(8.0);
    let Some(view) = s.session.view.as_ref() else {
        widgets::empty(
            ui,
            "Waiting for the node",
            "Traffic totals appear after the first sync update. No peer addresses are shown here.",
        );
        return None;
    };

    ui.horizontal_wrapped(|ui| {
        metric(ui, "Received", view.network_bytes_recv);
        ui.add_space(26.0);
        metric(ui, "Sent", view.network_bytes_sent);
        ui.add_space(26.0);
        ui.label(
            eframe::egui::RichText::new(format!(
                "{} {}",
                view.established().count(),
                if s.session.running() {
                    "connected"
                } else {
                    "peers in last sample"
                }
            ))
            .size(13.0)
            .color(s.pal.muted),
        );
    });
    ui.add_space(14.0);
    let rates = rates(&s.session.history);
    if rates.is_empty() {
        widgets::empty(
            ui,
            "Collecting traffic samples",
            "Rates need two one-second samples from the same node run.",
        );
        return None;
    }
    chart(ui, s, &rates);
    ui.add_space(8.0);
    ui.label(
        eframe::egui::RichText::new(
            "Rates are sampled from cumulative node totals. Gaps and counter resets are omitted.",
        )
        .size(12.0)
        .color(s.pal.muted),
    );
    None
}

fn rates(history: &std::collections::VecDeque<Sample>) -> Vec<Rate> {
    let samples: Vec<Sample> = history.iter().copied().collect();
    samples
        .windows(2)
        .filter_map(|pair| {
            let (a, b) = (pair[0], pair[1]);
            if a.run_id != b.run_id || !b.t.is_finite() || !a.t.is_finite() || b.t <= a.t {
                return None;
            }
            let elapsed = b.t - a.t;
            if elapsed > MAX_INTERVAL_SECS {
                return None;
            }
            let recv = b.network_bytes_recv.checked_sub(a.network_bytes_recv)?;
            let sent = b.network_bytes_sent.checked_sub(a.network_bytes_sent)?;
            Some(Rate {
                recv: recv as f64 / elapsed,
                sent: sent as f64 / elapsed,
            })
        })
        .rev()
        .take(WINDOW)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn metric(ui: &mut Ui, label: &str, bytes: u64) {
    ui.vertical(|ui| {
        ui.label(
            eframe::egui::RichText::new(label)
                .size(12.0)
                .color(ui.visuals().weak_text_color()),
        );
        ui.label(eframe::egui::RichText::new(format_bytes(bytes)).font(mono(18.0)));
    });
}

fn chart(ui: &mut Ui, s: &Scene, rates: &[Rate]) {
    let (rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width().max(240.0), CHART_HEIGHT),
        Sense::hover(),
    );
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8, s.pal.well);
    let max = rates
        .iter()
        .map(|r| r.recv.max(r.sent))
        .fold(1.0_f64, f64::max);
    let plot = rect.shrink2(vec2(44.0, 30.0));
    for i in 0..=4 {
        let y = plot.bottom() - plot.height() * i as f32 / 4.0;
        p.line_segment(
            [pos2(plot.left(), y), pos2(plot.right(), y)],
            Stroke::new(1.0, s.pal.hairline),
        );
        let value = max * i as f64 / 4.0;
        p.text(
            pos2(plot.left() - 6.0, y),
            Align2::RIGHT_CENTER,
            format_rate(value),
            mono(9.5),
            s.pal.muted,
        );
    }
    let point = |i: usize, value: f64| {
        let x = if rates.len() <= 1 {
            plot.right()
        } else {
            plot.left() + plot.width() * i as f32 / (rates.len() - 1) as f32
        };
        let y = plot.bottom() - (value / max).clamp(0.0, 1.0) as f32 * plot.height();
        pos2(x, y)
    };
    for (values, color) in [
        (
            rates.iter().map(|r| r.recv).collect::<Vec<_>>(),
            s.pal.signal_text,
        ),
        (rates.iter().map(|r| r.sent).collect::<Vec<_>>(), s.pal.text),
    ] {
        for i in 1..values.len() {
            p.line_segment(
                [point(i - 1, values[i - 1]), point(i, values[i])],
                Stroke::new(2.0, color),
            );
        }
    }
    p.text(
        pos2(rect.left() + 10.0, rect.top() + 9.0),
        Align2::LEFT_TOP,
        format!("Peak scale {}", format_rate(max)),
        font(theme::MEDIUM, 12.0),
        s.pal.muted,
    );
    let recv = rates.last().map_or(0.0, |r| r.recv);
    let sent = rates.last().map_or(0.0, |r| r.sent);
    let legend_y = rect.bottom() - 13.0;
    p.line_segment(
        [
            pos2(rect.left() + 12.0, legend_y),
            pos2(rect.left() + 23.0, legend_y),
        ],
        Stroke::new(2.0, s.pal.signal_text),
    );
    p.text(
        pos2(rect.left() + 27.0, legend_y),
        Align2::LEFT_CENTER,
        format!("Received {}", format_rate(recv)),
        mono(10.5),
        s.pal.muted,
    );
    p.line_segment(
        [
            pos2(rect.left() + 150.0, legend_y),
            pos2(rect.left() + 161.0, legend_y),
        ],
        Stroke::new(2.0, s.pal.text),
    );
    p.text(
        pos2(rect.left() + 165.0, legend_y),
        Align2::LEFT_CENTER,
        format!("Sent {}", format_rate(sent)),
        mono(10.5),
        s.pal.muted,
    );
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut amount = bytes as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < UNITS.len() {
        amount /= 1024.0;
        unit += 1;
    }
    format!("{amount:.1} {}", UNITS[unit])
}

fn format_rate(bytes_per_second: f64) -> String {
    let value = if bytes_per_second.is_finite() {
        bytes_per_second.max(0.0)
    } else {
        0.0
    };
    format!("{}/s", format_bytes(value.min(u64::MAX as f64) as u64))
}

#[cfg(test)]
mod tests {
    use super::{MAX_INTERVAL_SECS, WINDOW, rates};
    use crate::session::Sample;
    use std::collections::VecDeque;

    fn sample(t: f64, run_id: u64, recv: u64, sent: u64) -> Sample {
        Sample {
            t,
            run_id,
            connected: 0,
            headers: 0,
            headers_buffered: 0,
            replayed: 0,
            peers: 0,
            mempool: 0,
            network_bytes_recv: recv,
            network_bytes_sent: sent,
        }
    }

    #[test]
    fn rates_omit_restart_reset_zero_time_and_long_gap_pairs() {
        let history = VecDeque::from([
            sample(0.0, 4, 0, 0),
            sample(1.0, 4, 100, 50),
            sample(1.0, 4, 110, 60),
            sample(2.0, 4, 5, 5),
            sample(3.0, 4, 15, 25),
            sample(3.0 + MAX_INTERVAL_SECS + 1.0, 4, 20, 30),
            sample(8.0, 5, 300, 300),
            sample(9.0, 5, 500, 700),
        ]);

        let result = rates(&history);
        assert_eq!(result.len(), 3);
        assert_eq!((result[0].recv, result[0].sent), (100.0, 50.0));
        assert_eq!((result[1].recv, result[1].sent), (10.0, 20.0));
        assert_eq!((result[2].recv, result[2].sent), (200.0, 400.0));
    }

    #[test]
    fn zero_traffic_is_a_valid_zero_rate() {
        let history = VecDeque::from([sample(1.0, 0, 0, 0), sample(2.0, 0, 0, 0)]);
        let result = rates(&history);
        assert_eq!(result.len(), 1);
        assert_eq!((result[0].recv, result[0].sent), (0.0, 0.0));
    }

    #[test]
    fn rate_series_is_bounded_to_chart_window() {
        let history: VecDeque<_> = (0_u32..=200)
            .map(|i| sample(f64::from(i), 1, u64::from(i) * 10, u64::from(i) * 20))
            .collect();
        assert_eq!(rates(&history).len(), WINDOW);
    }
}
