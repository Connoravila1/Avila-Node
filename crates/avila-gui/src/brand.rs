//! The node's mark: the logo's calligraphic swirl, lifted off its orange
//! field so it can be inked onto any surface.

use eframe::egui::{self, ColorImage, TextureHandle, TextureOptions};

pub const LOGO_PNG: &[u8] = include_bytes!("../../../assets/avila-node-logo.png");

/// The swirl as a white mask (tint it when painting). Each pixel's alpha
/// is how far it sits below the orange field's luminance, so the logo's
/// anti-aliased stroke edges survive the lift. Downsampled with a box
/// filter to `side` px — the 1254 px source aliases badly if the GPU is
/// left to shrink it.
pub fn swirl_mask(side: usize) -> Result<ColorImage, String> {
    let icon = eframe::icon_data::from_png_bytes(LOGO_PNG).map_err(|e| e.to_string())?;
    let (w, h) = (icon.width as usize, icon.height as usize);
    if w == 0 || h == 0 || icon.rgba.len() != w * h * 4 {
        return Err("logo decoded to an unexpected shape".into());
    }
    let field = 153.0_f32; // luminance of (247, 139, 19)
    let alpha_at = |x: usize, y: usize| -> f32 {
        let i = (y * w + x) * 4;
        let [r, g, b] = [icon.rgba[i], icon.rgba[i + 1], icon.rgba[i + 2]].map(f32::from);
        let lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        ((field - lum) / field).clamp(0.0, 1.0)
    };
    let mut pixels = Vec::with_capacity(side * side);
    for ty in 0..side {
        let (y0, y1) = (ty * h / side, ((ty + 1) * h / side).max(ty * h / side + 1));
        for tx in 0..side {
            let (x0, x1) = (tx * w / side, ((tx + 1) * w / side).max(tx * w / side + 1));
            let mut sum = 0.0;
            for y in y0..y1.min(h) {
                for x in x0..x1.min(w) {
                    sum += alpha_at(x, y);
                }
            }
            let n = ((y1.min(h) - y0) * (x1.min(w) - x0)).max(1) as f32;
            let a = (sum / n * 255.0).round() as u8;
            pixels.push(egui::Color32::from_white_alpha(a));
        }
    }
    Ok(ColorImage::new([side, side], pixels))
}

pub fn swirl_texture(ctx: &egui::Context) -> Option<TextureHandle> {
    swirl_mask(160)
        .ok()
        .map(|img| ctx.load_texture("avila-swirl", img, TextureOptions::LINEAR))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn swirl_mask_lifts_ink_off_the_field() {
        let img = swirl_mask(64).expect("logo decodes");
        assert_eq!(img.size, [64, 64]);
        // The corners are pure orange field: fully transparent.
        assert_eq!(img.pixels[0].a(), 0);
        // The centre crosses the ₿'s strokes: some ink must survive.
        let inked = img.pixels.iter().filter(|p| p.a() > 128).count();
        assert!(inked > 64 * 64 / 20, "only {inked} inked pixels");
    }
}
