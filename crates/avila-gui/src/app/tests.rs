#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use avila_core::NodeConfig;
use eframe::egui::Color32;

struct Desktop {
    ctx: egui::Context,
    app: AvilaApp,
}

impl Desktop {
    fn new() -> Self {
        let ctx = egui::Context::default();
        let node = Node::new(NodeConfig::default().validate().unwrap()).unwrap();
        let logo = egui::ColorImage::new([1, 1], vec![Color32::BLACK]);
        let app = AvilaApp::new(&ctx, node, logo, AppearanceConfig::default());
        let mut desktop = Self { ctx, app };
        desktop.frame(vec![]);
        desktop
    }

    fn frame(&mut self, events: Vec<egui::Event>) -> String {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(760.0, 480.0) / self.ctx.zoom_factor(),
            )),
            events,
            ..Default::default()
        };
        let mut first = self.ctx.run_ui(input.clone(), |ui| self.app.render(ui));
        // This input/paint test has no GPU renderer to consume texture uploads.
        first.textures_delta.clear();
        // Allow first-frame table/window sizing to settle before inspecting paint output.
        let mut output = self.ctx.run_ui(
            egui::RawInput {
                events: vec![],
                ..input
            },
            |ui| self.app.render(ui),
        );
        output.textures_delta.clear();
        let mut text = String::new();
        for shape in output.shapes {
            collect_text(&shape.shape, &mut text);
        }
        text
    }
}

fn collect_text(shape: &egui::Shape, text: &mut String) {
    match shape {
        egui::Shape::Text(shape) => {
            text.push_str(shape.galley.text());
            text.push('\n');
        }
        egui::Shape::Vec(shapes) => {
            for shape in shapes {
                collect_text(shape, text);
            }
        }
        _ => {}
    }
}

fn shortcut(key: egui::Key) -> Vec<egui::Event> {
    [true, false]
        .into_iter()
        .map(|pressed| egui::Event::Key {
            key,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::COMMAND,
        })
        .collect()
}

#[test]
fn search_shortcut_accepts_typing_and_explains_empty_results() {
    let mut desktop = Desktop::new();
    assert!(
        desktop
            .frame(shortcut(egui::Key::F))
            .contains("Configuration loaded")
    );
    let text = desktop.frame(vec![egui::Event::Text("unmatched query".into())]);
    assert!(text.contains("No events match this search."));
    assert_eq!(desktop.app.node.events().entries().count(), 1);
    assert_eq!(desktop.app.node.snapshot().validated_tip_height, None);
}

#[test]
fn keyboard_pages_render_at_minimum_size_and_double_scale() {
    let mut desktop = Desktop::new();
    for zoom in [1.0, 2.0] {
        desktop.ctx.set_zoom_factor(zoom);
        for (key, expected) in [
            (egui::Key::Num1, "no validated chain yet"),
            (egui::Key::Num2, "Start sync"),
            (egui::Key::Num3, "Configuration loaded"),
            (egui::Key::Num4, "Implementation status"),
            (egui::Key::Num5, "Loaded settings for this process."),
        ] {
            let mut text = desktop.frame(shortcut(key));
            if !text.contains(expected) {
                for direction in [-400.0, 400.0, 400.0] {
                    desktop.frame(vec![
                        egui::Event::PointerMoved(egui::pos2(200.0, 180.0)),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            delta: egui::vec2(0.0, direction),
                            phase: egui::TouchPhase::Move,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ]);
                    for _ in 0..3 {
                        text = desktop.frame(vec![]);
                        if text.contains(expected) {
                            break;
                        }
                    }
                    if text.contains(expected) {
                        break;
                    }
                }
            }
            if !text.contains(expected) {
                eprintln!("==== DUMP {expected} zoom {zoom} ====\n{text}\n====");
            }
            assert!(
                text.contains(expected),
                "Missing {expected:?} at scale {zoom}"
            );
            assert!(text.contains("no chain data"));
        }
    }
}
