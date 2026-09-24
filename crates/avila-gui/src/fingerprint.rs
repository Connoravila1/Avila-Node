//! A BIP324 session id drawn as a picture, so two people can compare it
//! at a glance: OpenSSH's "drunken bishop" walk, the same algorithm behind
//! `ssh-keygen -lv` randomart. Both ends of a v2 connection derive the
//! same session id; if the pictures (or the hex) match, nobody is sitting
//! in the middle.

pub const WIDTH: usize = 17;
pub const HEIGHT: usize = 9;

/// How often the bishop visited each cell, plus where it started and
/// stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Art {
    pub visits: [[u8; WIDTH]; HEIGHT],
    pub start: (usize, usize),
    pub end: (usize, usize),
}

/// Walks the bishop: each byte gives four moves, two bits each, low bits
/// first — bit 0 picks left/right, bit 1 up/down — sliding along walls.
#[must_use]
pub fn randomart(bytes: &[u8]) -> Art {
    let start = (WIDTH / 2, HEIGHT / 2);
    let (mut x, mut y) = start;
    let mut visits = [[0_u8; WIDTH]; HEIGHT];
    for byte in bytes {
        let mut b = *byte;
        for _ in 0..4 {
            x = if b & 1 == 1 {
                (x + 1).min(WIDTH - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if b & 2 == 2 {
                (y + 1).min(HEIGHT - 1)
            } else {
                y.saturating_sub(1)
            };
            visits[y][x] = visits[y][x].saturating_add(1);
            b >>= 2;
        }
    }
    Art {
        visits,
        start,
        end: (x, y),
    }
}

/// The id as `getpeerinfo` prints it, in groups of eight for reading
/// aloud.
#[must_use]
pub fn hex_groups(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(4)
        .map(|c| c.iter().map(|b| format!("{b:02x}")).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_walk_matches_openssh() {
        // One byte 0b11_10_01_00: moves (−1,−1) (+1,−1) (−1,+1) (+1,+1).
        let art = randomart(&[0b1110_0100]);
        let (cx, cy) = (WIDTH / 2, HEIGHT / 2);
        assert_eq!(art.start, (cx, cy));
        // The third move lands back on the first cell.
        assert_eq!(art.visits[cy - 1][cx - 1], 2);
        assert_eq!(art.visits[cy - 2][cx], 1);
        assert_eq!(art.end, (cx, cy));
        assert_eq!(art.visits[cy][cx], 1);
    }

    #[test]
    fn walls_stop_the_bishop() {
        // All-zero bytes: always up-left, into the corner.
        let art = randomart(&[0; 8]);
        assert_eq!(art.end, (0, 0));
        assert!(art.visits[0][0] > 20);
    }

    #[test]
    fn different_ids_draw_differently() {
        let a: Vec<u8> = (0..32).collect();
        let b: Vec<u8> = (0..32).map(|i| i ^ 0x5a).collect();
        assert_ne!(randomart(&a), randomart(&b));
        assert_eq!(hex_groups(&a[..8]), vec!["00010203", "04050607"]);
    }
}
