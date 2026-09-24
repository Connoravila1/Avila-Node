//! Pure-Rust minisketch — the set-reconciliation primitive BIP-330
//! (Erlay) tx relay needs, with no FFI chain: GF(2^32) arithmetic,
//! odd-power syndromes, Frobenius expansion, Berlekamp-Massey, and
//! trace-split root finding.
//!
//! A sketch of capacity `c` is `c` field elements (4c bytes wire): the
//! syndromes `s_j = Σ x^(2j-1)` for `j = 1..=c`. XOR two sketches to
//! cancel shared elements — the remainder decodes iff the symmetric
//! difference has at most `c` elements.

/// Field modulus: x^32 + x^22 + x^2 + x + 1.
const MOD: u64 = 0x1_0040_0007;

#[inline]
fn gf_mul(a: u32, b: u32) -> u32 {
    let mut r = 0u64;
    let mut aa = u64::from(a);
    let mut bb = b;
    while bb != 0 {
        if bb & 1 != 0 {
            r ^= aa;
        }
        aa <<= 1;
        bb >>= 1;
    }
    // Reduce mod the field polynomial.
    for i in (32..63).rev() {
        if r >> i & 1 != 0 {
            r ^= MOD << (i - 32);
        }
    }
    r as u32
}

#[inline]
fn gf_pow(mut a: u32, mut e: u64) -> u32 {
    let mut r = 1u32;
    while e != 0 {
        if e & 1 != 0 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

#[inline]
fn gf_inv(a: u32) -> u32 {
    gf_pow(a, 0xffff_fffe) // a^(2^32 - 2) = a^-1
}

#[inline]
fn gf_sq(a: u32) -> u32 {
    gf_mul(a, a)
}

// -- dense polys over GF(2^32): coeff[i] = x^i term -------------------

fn pdeg(p: &[u32]) -> usize {
    let mut d = p.len();
    while d > 0 && p[d - 1] == 0 {
        d -= 1;
    }
    d // degree+1 as a length; 0 = zero poly
}

fn ptrim(p: &[u32]) -> Vec<u32> {
    p[..pdeg(p)].to_vec()
}

fn pmul(a: &[u32], b: &[u32]) -> Vec<u32> {
    let (da, db) = (pdeg(a), pdeg(b));
    if da == 0 || db == 0 {
        return Vec::new();
    }
    let mut r = vec![0u32; da + db - 1];
    for (i, &x) in a[..da].iter().enumerate() {
        if x == 0 {
            continue;
        }
        for (j, &y) in b[..db].iter().enumerate() {
            if y != 0 {
                r[i + j] ^= gf_mul(x, y);
            }
        }
    }
    r
}

fn pmod(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut a = a.to_vec();
    let db = pdeg(b);
    assert!(db > 0, "poly mod by zero");
    let inv_lc = gf_inv(b[db - 1]);
    while pdeg(&a) >= db {
        let d = pdeg(&a) - db;
        let c = gf_mul(a[d + db - 1], inv_lc);
        for i in 0..db {
            a[d + i] ^= gf_mul(c, b[i]);
        }
        a.truncate(d + db - 1);
    }
    ptrim(&a)
}

fn pgcd(mut a: Vec<u32>, mut b: Vec<u32>) -> Vec<u32> {
    while pdeg(&b) > 0 {
        let r = pmod(&a, &b);
        a = b;
        b = r;
    }
    a
}

/// Quotient a/b — exact division when b | a (used after gcd splits).
fn pdiv(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut a = a.to_vec();
    let db = pdeg(b);
    let mut q = vec![0u32; pdeg(&a).saturating_sub(db - 1)];
    let inv_lc = gf_inv(b[db - 1]);
    while pdeg(&a) >= db {
        let d = pdeg(&a) - db;
        let c = gf_mul(a[d + db - 1], inv_lc);
        q[d] = c;
        for i in 0..db {
            a[d + i] ^= gf_mul(c, b[i]);
        }
        a.truncate(d + db - 1);
    }
    q
}

// -- the sketch --------------------------------------------------------

/// A capacity-`c` sketch: `c` odd-power syndromes.
#[derive(Clone, Debug)]
pub struct Sketch {
    synd: Vec<u32>,
}

impl Sketch {
    /// Capacity-`c` sketch — reconciles up to `c` differing elements.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            synd: vec![0; capacity],
        }
    }

    /// Serialized capacity in field elements.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.synd.len()
    }

    /// Adds a 32-bit element (XOR into each odd-power syndrome).
    pub fn add(&mut self, x: u32) {
        let x2 = gf_sq(x);
        let mut p = x; // x^1
        for s in &mut self.synd {
            *s ^= p;
            p = gf_mul(p, x2); // next odd power: x^(2j+1) -> x^(2j+3)
        }
    }

    /// XOR — cancels every element present in both sets.
    pub fn merge(&mut self, other: &Sketch) {
        for (a, b) in self.synd.iter_mut().zip(other.synd.iter()) {
            *a ^= b;
        }
    }

    /// Wire form: `4 * capacity` bytes, little-endian syndromes.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * self.synd.len());
        for s in &self.synd {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// The largest sketch we'll accept on the wire — 4× the biggest
    /// sketch we ever send (`capacity` clamps to 512). A peer's frame
    /// is 4 MB, which is ~1M syndromes: without this cap Berlekamp-
    /// Massey decodes an adversary-sized input before any budget trips.
    pub const MAX_WIRE_FIELDS: usize = 2048;

    /// Reads a sketch from its serialized form.
    #[must_use]
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty()
            || !bytes.len().is_multiple_of(4)
            || bytes.len() / 4 > Self::MAX_WIRE_FIELDS
        {
            return None;
        }
        Some(Self {
            synd: bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect(),
        })
    }

    /// Decodes the symmetric difference — `Some` iff it fits capacity.
    /// Elements come back unsorted; the caller maps them to txids.
    #[must_use]
    pub fn decode(&self) -> Option<Vec<u32>> {
        let c = self.synd.len();
        if c == 0 {
            return Some(Vec::new());
        }
        // Expand to full syndromes S_1..S_{2c}: odd powers are stored;
        // even powers follow by Frobenius — S_{2k} = S_k^2.
        let mut s = vec![0u32; 2 * c + 1]; // 1-indexed
        for (j, &v) in self.synd.iter().enumerate() {
            s[2 * j + 1] = v;
        }
        for k in 1..=(2 * c) {
            if k % 2 == 0 {
                s[k] = gf_sq(s[k / 2]);
            }
        }
        if s[1..].iter().all(|&v| v == 0) {
            return Some(Vec::new());
        }
        // Berlekamp-Massey -> locator Λ(z) = ∏ (1 - x_i z).
        let locator = berlekamp_massey(&s[1..]);
        if locator.is_empty() || pdeg(&locator) - 1 > c {
            return None; // difference exceeds capacity
        }
        let d = pdeg(&locator) - 1;
        if d == 0 {
            return Some(Vec::new());
        }
        // Roots r of Λ give elements x = r^-1. Λ = ∏(1 - x_i z) ⇒
        // roots are 1/x_i.
        let roots = find_roots(&locator);
        if roots.len() != d {
            return None; // couldn't factor — over capacity
        }
        let mut out: Vec<u32> = roots.iter().map(|&r| gf_inv(r)).collect();
        out.sort_unstable();
        Some(out)
    }
}

/// BM over syndromes s[0..n] (s[0] = S_1): linear recurrence locator.
fn berlekamp_massey(s: &[u32]) -> Vec<u32> {
    let n = s.len();
    let mut c_poly = vec![0u32; n + 1];
    let mut b_poly = vec![0u32; n + 1];
    c_poly[0] = 1;
    b_poly[0] = 1;
    let (mut l, mut m) = (0usize, 1usize);
    let mut b = 1u32;
    for k in 0..n {
        // discrepancy at syndrome k+1
        let mut d = s[k];
        for i in 1..=l {
            if c_poly[i] != 0 {
                d ^= gf_mul(c_poly[i], s[k - i]);
            }
        }
        if d == 0 {
            m += 1;
        } else if 2 * l <= k {
            let t = c_poly.clone();
            let coef = gf_mul(d, gf_inv(b));
            for i in 0..=n - m {
                if b_poly[i] != 0 {
                    c_poly[i + m] ^= gf_mul(coef, b_poly[i]);
                }
            }
            l = k + 1 - l;
            b_poly = t;
            b = d;
            m = 1;
        } else {
            let coef = gf_mul(d, gf_inv(b));
            for i in 0..=n - m {
                if b_poly[i] != 0 {
                    c_poly[i + m] ^= gf_mul(coef, b_poly[i]);
                }
            }
            m += 1;
        }
    }
    ptrim(&c_poly)
}

/// All roots of `p` over GF(2^32) via Berlekamp trace splitting:
/// split by gcd(p, Tr(a·x)) for random `a` until linear factors.
fn find_roots(p: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![ptrim(p)];
    // Deterministic shift sequence — randomness only breaks ties; a
    // fixed sweep is reproducible and terminates as surely as random.
    let mut seed = 0x9e3779b9u32;
    while let Some(poly) = stack.pop() {
        match pdeg(&poly) {
            0 | 1 => {}
            2 => out.push(gf_mul(poly[0], gf_inv(poly[1]))), // c0 + c1 z → z = c0/c1
            _ => {
                let mut split = false;
                for _ in 0..64 {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    let a = seed | 1;
                    // T_a(x) = Σ_{i=0}^{31} (a·x)^{2^i} mod p
                    let mut r = vec![0, a]; // a·x
                    let mut t = r.clone();
                    for _ in 1..32 {
                        r = pmod(&pmul(&r, &r), &poly);
                        for (i, &v) in r.iter().enumerate() {
                            if i < t.len() {
                                t[i] ^= v;
                            } else {
                                t.push(v);
                            }
                        }
                    }
                    let g = pgcd(poly.clone(), t);
                    let gd = pdeg(&g);
                    if gd > 1 && gd < pdeg(&poly) {
                        stack.push(pdiv(&poly, &g));
                        stack.push(g);
                        split = true;
                        break;
                    }
                }
                if !split {
                    return Vec::new(); // couldn't split — fail decode
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn gf_field_laws() {
        assert_eq!(gf_mul(3, 5), 15);
        assert_eq!(gf_mul(0, 0xffff_ffff), 0);
        for &a in &[1u32, 7, 0xdead_beef, 0xffff_ffff] {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "a*a^-1 for {a:#x}");
        }
    }

    #[test]
    fn reconcile_small_difference() {
        let mut a = Sketch::new(8);
        let mut b = Sketch::new(8);
        for i in 0..1000u32 {
            a.add(i * 7 + 1);
            b.add(i * 7 + 1);
        }
        // a-only: {100, 200}, b-only: {300}
        a.add(100);
        a.add(200);
        b.add(300);
        a.merge(&b);
        let mut got = a.decode().unwrap();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200, 300]);
    }

    #[test]
    fn empty_difference_decodes_empty() {
        let mut a = Sketch::new(4);
        let mut b = Sketch::new(4);
        for i in 1..500u32 {
            a.add(i);
            b.add(i);
        }
        a.merge(&b);
        assert_eq!(a.decode(), Some(vec![]));
    }

    #[test]
    fn over_capacity_fails() {
        let mut a = Sketch::new(2);
        let mut b = Sketch::new(2);
        for i in 0..50u32 {
            a.add(i);
            b.add(i);
        }
        for i in 0..4u32 {
            a.add(1000 + i); // 4 uniques, capacity 2
        }
        a.merge(&b);
        // Must not falsely succeed — either None or a valid decode.
        if let Some(d) = a.decode() {
            assert_eq!(d.len(), 4);
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let mut a = Sketch::new(4);
        a.add(42);
        a.add(0xdead_beef);
        let bytes = a.serialize();
        assert_eq!(bytes.len(), 16);
        let b = Sketch::deserialize(&bytes).unwrap();
        let mut x = a.clone();
        let y = b;
        x.merge(&y);
        assert_eq!(x.decode(), Some(vec![]));
    }
}
