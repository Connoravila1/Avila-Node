//! MuHash-3072 — the multiplicative UTXO-set hash used by `gettxoutsetinfo`
//! (`hash_type="muhash"`) and Core's assumeutxo commitments.
//!
//! A direct port of Bitcoin Core's `crypto/muhash.cpp`: a `Num3072` is a
//! 3072-bit residue modulo the safe prime `2^3072 - 1103717`, stored as 48
//! 64-bit limbs. Each inserted element is `SHA256(data)` fed through a
//! ChaCha20 keystream to produce a group element; the set hash is the product
//! of all elements' numerators over denominators, output as `SHA256` of the
//! reduced 384-byte representation.
//!
//! The modular inverse uses the safegcd divsteps variant (the same algorithm
//! libsecp256k1 uses for field/scalar inversion), which is why the signed
//! 62-bit-limb `Num3072Signed` representation exists: it lets carries be
//! deferred across the linear-combination updates the divstep matrix applies.

/// 2^3072 - 1103717 — the modulus; the largest 3072-bit safe prime.
const MAX_PRIME_DIFF: u64 = 1103717;
/// The modular inverse of `2^3072 - MAX_PRIME_DIFF` modulo 2^62.
const MODULUS_INVERSE: u64 = 0x70a1421da087d93;

const LIMB_SIZE: usize = 64;
const LIMBS: usize = 48; // 3072 / 64
const SIGNED_LIMB_SIZE: usize = 62;
const SIGNED_LIMBS: usize = 50; // ceil(3072 / 62) + slack
const FINAL_LIMB_POSITION: usize = 3072 / SIGNED_LIMB_SIZE; // 49
const FINAL_LIMB_MODULUS_BITS: u32 = (3072 % SIGNED_LIMB_SIZE) as u32; // 34
const MAX_SIGNED_LIMB: i64 = (1 << SIGNED_LIMB_SIZE) - 1;
const BYTE_SIZE: usize = 384;

type Limb = u64;
type SignedLimb = i64;
type DoubleLimb = u128;
type SignedDoubleLimb = i128;

/// [c0, c1] = a * b
fn mul(a: Limb, b: Limb) -> (Limb, Limb) {
    let t = (a as DoubleLimb) * (b as DoubleLimb);
    (t as Limb, (t >> LIMB_SIZE) as Limb)
}

/// [c0, c1] *= n
fn muln2(c0: &mut Limb, c1: &mut Limb, n: Limb) {
    let t = (*c0 as DoubleLimb) * (n as DoubleLimb);
    *c0 = t as Limb;
    let mut t2 = t >> LIMB_SIZE;
    t2 += (*c1 as DoubleLimb) * (n as DoubleLimb);
    *c1 = t2 as Limb;
}

/// [c0, c1, c2] += a * b — c2 starts 0.
fn muladd3(c0: &mut Limb, c1: &mut Limb, c2: &mut Limb, a: Limb, b: Limb) {
    let t = (a as DoubleLimb) * (b as DoubleLimb);
    let th = (t >> LIMB_SIZE) as Limb;
    let tl = t as Limb;
    *c0 = c0.wrapping_add(tl);
    let mut th = th;
    th = th.wrapping_add(u64::from(*c0 < tl));
    *c1 = c1.wrapping_add(th);
    *c2 = c2.wrapping_add(u64::from(*c1 < th));
}

/// [c0, c1, c2] += n * [d0, d1, d2] — c2 is 0 initially.
fn mulnadd3(c0: &mut Limb, c1: &mut Limb, c2: &mut Limb, d0: Limb, d1: Limb, d2: Limb, n: Limb) {
    let mut t = (d0 as DoubleLimb) * (n as DoubleLimb) + (*c0 as DoubleLimb);
    *c0 = t as Limb;
    t >>= LIMB_SIZE;
    t += (d1 as DoubleLimb) * (n as DoubleLimb) + (*c1 as DoubleLimb);
    *c1 = t as Limb;
    t >>= LIMB_SIZE;
    *c2 = (t + (d2 as DoubleLimb) * (n as DoubleLimb)) as Limb;
}

/// n = c0; [c0, c1, c2] shifts left one limb.
fn extract3(c0: &mut Limb, c1: &mut Limb, c2: &mut Limb) -> Limb {
    let n = *c0;
    *c0 = *c1;
    *c1 = *c2;
    *c2 = 0;
    n
}

/// [c0, c1] += a, then n = c0 and shift left one limb.
fn addnextract2(c0: &mut Limb, c1: &mut Limb, a: Limb) -> Limb {
    let mut c2: Limb = 0;
    *c0 = c0.wrapping_add(a);
    if *c0 < a {
        *c1 = c1.wrapping_add(1);
        if *c1 == 0 {
            c2 = 1;
        }
    }
    let n = *c0;
    *c0 = *c1;
    *c1 = c2;
    n
}

/// A 3072-bit number modulo `2^3072 - 1103717`, little-endian limb order.
/// Values may sit unreduced in `[0, 2^3072)` between operations; `IsOverflow`
/// detects the tail above the modulus.
#[derive(Clone)]
pub struct Num3072 {
    limbs: [Limb; LIMBS],
}

impl Num3072 {
    fn zero() -> Self {
        Num3072 { limbs: [0; LIMBS] }
    }

    /// `true` when the value is ≥ the modulus (the top `MAX_PRIME_DIFF`
    /// values of the 3072-bit range).
    fn is_overflow(&self) -> bool {
        if self.limbs[0] <= u64::MAX - MAX_PRIME_DIFF {
            return false;
        }
        self.limbs[1..].iter().all(|&l| l == u64::MAX)
    }

    /// `this mod modulus`, applied when `is_overflow`.
    fn full_reduce(&mut self) {
        let mut c0: Limb = MAX_PRIME_DIFF;
        let mut c1: Limb = 0;
        for i in 0..LIMBS {
            let n = addnextract2(&mut c0, &mut c1, self.limbs[i]);
            self.limbs[i] = n;
        }
    }

    /// `this *= a`, reduced — the schoolbook multiply where the high half is
    /// folded back via `2^3072 ≡ MAX_PRIME_DIFF (mod modulus)`.
    fn multiply(&mut self, a: &Num3072) {
        let mut c0: Limb = 0;
        let mut c1: Limb = 0;
        let mut c2: Limb = 0;
        let mut tmp = Num3072::zero();

        // Limbs 0..LIMBS-1 of this*a into tmp, one reduction folded in.
        for j in 0..LIMBS - 1 {
            let (mut d0, mut d1) = mul(self.limbs[1 + j], a.limbs[LIMBS - 1]);
            let mut d2: Limb = 0;
            for i in 2 + j..LIMBS {
                muladd3(
                    &mut d0,
                    &mut d1,
                    &mut d2,
                    self.limbs[i],
                    a.limbs[LIMBS + j - i],
                );
            }
            mulnadd3(&mut c0, &mut c1, &mut c2, d0, d1, d2, MAX_PRIME_DIFF);
            for i in 0..j + 1 {
                muladd3(&mut c0, &mut c1, &mut c2, self.limbs[i], a.limbs[j - i]);
            }
            tmp.limbs[j] = extract3(&mut c0, &mut c1, &mut c2);
        }

        // Limb LIMBS-1 of the product.
        debug_assert!(c2 == 0);
        for i in 0..LIMBS {
            muladd3(
                &mut c0,
                &mut c1,
                &mut c2,
                self.limbs[i],
                a.limbs[LIMBS - 1 - i],
            );
        }
        tmp.limbs[LIMBS - 1] = extract3(&mut c0, &mut c1, &mut c2);

        // Second reduction of the folded remainder.
        muln2(&mut c0, &mut c1, MAX_PRIME_DIFF);
        for j in 0..LIMBS {
            let n = addnextract2(&mut c0, &mut c1, tmp.limbs[j]);
            self.limbs[j] = n;
        }
        debug_assert!(c1 == 0);
        debug_assert!(c0 == 0 || c0 == 1);

        if self.is_overflow() {
            self.full_reduce();
        }
        if c0 != 0 {
            self.full_reduce();
        }
    }

    fn set_to_one(&mut self) {
        self.limbs[0] = 1;
        for l in &mut self.limbs[1..] {
            *l = 0;
        }
    }

    /// `this /= a` — multiplies by `a`'s modular inverse.
    fn divide(&mut self, a: &Num3072) {
        if self.is_overflow() {
            self.full_reduce();
        }
        let inv = if a.is_overflow() {
            let mut b = a.clone();
            b.full_reduce();
            b.inverse()
        } else {
            a.inverse()
        };
        self.multiply(&inv);
        if self.is_overflow() {
            self.full_reduce();
        }
    }

    /// The modular inverse via safegcd divsteps — see `GetInverse` in
    /// Core's muhash.cpp for the algorithm sketch.
    fn inverse(&self) -> Num3072 {
        let mut d = Num3072Signed::zero();
        let mut e = Num3072Signed::zero();
        let mut f = Num3072Signed::zero();
        let mut g = Num3072Signed::zero();
        e.limbs[0] = 1;
        // f starts at the modulus: 2^3072 + (-MAX_PRIME_DIFF) in signed
        // limb form.
        f.limbs[0] = -(MAX_PRIME_DIFF as SignedLimb);
        f.limbs[FINAL_LIMB_POSITION] = (1_i64) << FINAL_LIMB_MODULUS_BITS;
        g.set_from_num3072(self);
        let mut len = SIGNED_LIMBS;
        let mut eta: SignedLimb = -1;
        loop {
            let (t, new_eta) = divstep_matrix(eta, f.limbs[0] as Limb, g.limbs[0] as Limb);
            eta = new_eta;
            update_fg(&mut f, &mut g, &t, len);
            update_de(&mut d, &mut e, &t);

            if g.limbs[0] == 0 {
                let cond: SignedLimb = g.limbs[1..len].iter().fold(0, |c, &l| c | l);
                if cond == 0 {
                    break;
                }
            }

            // Drop the top limb while both f and g's top limbs are all
            // sign bits (0 or -1).
            let fn_ = f.limbs[len - 1];
            let gn = g.limbs[len - 1];
            let mut cond = ((len as SignedLimb) - 2) >> (LIMB_SIZE - 1);
            cond |= fn_ ^ (fn_ >> (LIMB_SIZE - 1));
            cond |= gn ^ (gn >> (LIMB_SIZE - 1));
            if cond == 0 {
                f.limbs[len - 2] |= f.limbs[len - 1] << SIGNED_LIMB_SIZE;
                g.limbs[len - 2] |= g.limbs[len - 1] << SIGNED_LIMB_SIZE;
                len -= 1;
            }
        }
        d.normalize((f.limbs[len - 1] >> (LIMB_SIZE - 1)) != 0);
        d.to_num3072()
    }

    fn from_bytes(data: &[u8; BYTE_SIZE]) -> Self {
        let mut out = Num3072::zero();
        let (limb_bytes, _) = data.as_chunks::<8>();
        for (limb, bytes) in out.limbs.iter_mut().zip(limb_bytes) {
            *limb = u64::from_le_bytes(*bytes);
        }
        out
    }

    fn to_bytes(&self) -> [u8; BYTE_SIZE] {
        let mut out = [0u8; BYTE_SIZE];
        for i in 0..LIMBS {
            out[8 * i..8 * i + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }
}

/// `Num3072` in 62-bit signed limbs — deferrable-carry form for the divstep
/// linear combinations.
struct Num3072Signed {
    limbs: [SignedLimb; SIGNED_LIMBS],
}

impl Num3072Signed {
    fn zero() -> Self {
        Num3072Signed {
            limbs: [0; SIGNED_LIMBS],
        }
    }

    /// Repack 64-bit limbs into 62-bit signed limbs.
    fn set_from_num3072(&mut self, n: &Num3072) {
        let mut c: DoubleLimb = 0;
        let mut b = 0usize;
        let mut outpos = 0usize;
        for i in 0..LIMBS {
            c += (n.limbs[i] as DoubleLimb) << b;
            b += LIMB_SIZE;
            while b >= SIGNED_LIMB_SIZE {
                self.limbs[outpos] = (c as Limb & (MAX_SIGNED_LIMB as Limb)) as SignedLimb;
                outpos += 1;
                c >>= SIGNED_LIMB_SIZE;
                b -= SIGNED_LIMB_SIZE;
            }
        }
        debug_assert_eq!(outpos, SIGNED_LIMBS - 1);
        self.limbs[SIGNED_LIMBS - 1] = c as SignedLimb;
        c >>= SIGNED_LIMB_SIZE;
        debug_assert_eq!(c, 0);
    }

    /// Repack back into 64-bit limbs — input must be in `0..modulus`.
    fn to_num3072(&self) -> Num3072 {
        let mut out = Num3072::zero();
        let mut c: DoubleLimb = 0;
        let mut b = 0usize;
        let mut outpos = 0usize;
        for i in 0..SIGNED_LIMBS {
            c += (self.limbs[i] as SignedDoubleLimb as DoubleLimb) << b;
            b += SIGNED_LIMB_SIZE;
            if b >= LIMB_SIZE {
                out.limbs[outpos] = c as Limb;
                outpos += 1;
                c >>= LIMB_SIZE;
                b -= LIMB_SIZE;
            }
        }
        debug_assert_eq!(outpos, LIMBS);
        debug_assert_eq!(c, 0);
        out
    }

    /// Reduces a value in `1-2^3072..2^3072-1` into `0..2^3072-1` with all
    /// limbs normalized to `0..2^62-1`, optionally negating first.
    fn normalize(&mut self, negate: bool) {
        // Add the modulus if negative: range becomes 1-2^3072..2^3072-1.
        let mut cond_add = self.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
        self.limbs[0] += (-(MAX_PRIME_DIFF as SignedLimb)) & cond_add;
        self.limbs[FINAL_LIMB_POSITION] += ((1_i64) << FINAL_LIMB_MODULUS_BITS) & cond_add;
        // Optionally negate every limb.
        let cond_negate = -SignedLimb::from(negate);
        for l in self.limbs.iter_mut() {
            *l = (*l ^ cond_negate).wrapping_sub(cond_negate);
        }
        // Carry: all limbs but the top into 0..2^62-1.
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] = self.limbs[i + 1].wrapping_add(self.limbs[i] >> SIGNED_LIMB_SIZE);
            self.limbs[i] &= MAX_SIGNED_LIMB;
        }
        // Add the modulus again if still negative → 0..2^3072-1.
        cond_add = self.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
        self.limbs[0] += (-(MAX_PRIME_DIFF as SignedLimb)) & cond_add;
        self.limbs[FINAL_LIMB_POSITION] += ((1_i64) << FINAL_LIMB_MODULUS_BITS) & cond_add;
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] = self.limbs[i + 1].wrapping_add(self.limbs[i] >> SIGNED_LIMB_SIZE);
            self.limbs[i] &= MAX_SIGNED_LIMB;
        }
    }
}

/// 2x2 divstep transformation matrix, scaled by 2^62.
struct SignedMatrix {
    u: SignedLimb,
    v: SignedLimb,
    q: SignedLimb,
    r: SignedLimb,
}

/// -1/(2i+1) mod 256 for i in 0..128 — the bottom-bit cancellation table.
const NEGINV256: [u8; 128] = [
    0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59, 0xD7, 0xED, 0xCB, 0x21,
    0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31, 0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41,
    0x3F, 0x95, 0x73, 0x89, 0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
    0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9, 0x37, 0x4D, 0x2B, 0x81,
    0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91, 0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1,
    0x9F, 0xF5, 0xD3, 0xE9, 0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
    0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19, 0x97, 0xAD, 0x8B, 0xE1,
    0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1, 0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01,
];

/// SIGNED_LIMB_SIZE divsteps at once, computed from eta and the bottom limbs
/// of f and g. Returns the matrix and the new eta.
fn divstep_matrix(mut eta: SignedLimb, mut f: Limb, mut g: Limb) -> (SignedMatrix, SignedLimb) {
    let mut u: Limb = 1;
    let mut v: Limb = 0;
    let mut q: Limb = 0;
    let mut r: Limb = 1;
    let mut i = SIGNED_LIMB_SIZE as i64;
    loop {
        // Sentinel bit: count zeros only up to i.
        let zeros = (g | (u64::MAX << (i as u32))).trailing_zeros() as i64;
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;
        if i == 0 {
            break;
        }
        if eta < 0 {
            eta = -eta;
            std::mem::swap(&mut f, &mut g);
            g = g.wrapping_neg();
            std::mem::swap(&mut u, &mut q);
            q = q.wrapping_neg();
            std::mem::swap(&mut v, &mut r);
            r = r.wrapping_neg();
        }
        let limit = std::cmp::min(eta + 1, i) as u64;
        let m = (u64::MAX >> (LIMB_SIZE as u64 - limit)) & 0xFF;
        let w = g.wrapping_mul(NEGINV256[((f >> 1) & 127) as usize] as Limb) & m;
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }
    (
        SignedMatrix {
            u: u as SignedLimb,
            v: v as SignedLimb,
            q: q as SignedLimb,
            r: r as SignedLimb,
        },
        eta,
    )
}

/// [d, e] ← t·[d, e]/2^62, kept reduced mod modulus. Inputs and outputs are
/// in `1-2*modulus..modulus-1`.
fn update_de(d: &mut Num3072Signed, e: &mut Num3072Signed, t: &SignedMatrix) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let sd = d.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    let se = e.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);

    let mut di = d.limbs[0];
    let mut ei = e.limbs[0];
    let mut cd = (u as SignedDoubleLimb) * (di as SignedDoubleLimb)
        + (v as SignedDoubleLimb) * (ei as SignedDoubleLimb);
    let mut ce = (q as SignedDoubleLimb) * (di as SignedDoubleLimb)
        + (r as SignedDoubleLimb) * (ei as SignedDoubleLimb);

    // C++: `md -= (MODULUS_INVERSE * (limb_t)cd + md) & MAX_SIGNED_LIMB` —
    // the product/sum wraps in 64 bits, then masks to 62.
    md = md.wrapping_sub(
        (MODULUS_INVERSE
            .wrapping_mul(cd as Limb)
            .wrapping_add(md as Limb)
            & (MAX_SIGNED_LIMB as Limb)) as SignedLimb,
    );
    me = me.wrapping_sub(
        (MODULUS_INVERSE
            .wrapping_mul(ce as Limb)
            .wrapping_add(me as Limb)
            & (MAX_SIGNED_LIMB as Limb)) as SignedLimb,
    );

    cd -= (1103717 as SignedDoubleLimb) * (md as SignedDoubleLimb);
    ce -= (1103717 as SignedDoubleLimb) * (me as SignedDoubleLimb);
    debug_assert_eq!(cd & (MAX_SIGNED_LIMB as SignedDoubleLimb), 0);
    debug_assert_eq!(ce & (MAX_SIGNED_LIMB as SignedDoubleLimb), 0);
    cd >>= SIGNED_LIMB_SIZE;
    ce >>= SIGNED_LIMB_SIZE;

    for i in 1..SIGNED_LIMBS - 1 {
        di = d.limbs[i];
        ei = e.limbs[i];
        cd += (u as SignedDoubleLimb) * (di as SignedDoubleLimb)
            + (v as SignedDoubleLimb) * (ei as SignedDoubleLimb);
        ce += (q as SignedDoubleLimb) * (di as SignedDoubleLimb)
            + (r as SignedDoubleLimb) * (ei as SignedDoubleLimb);
        d.limbs[i - 1] = (cd as SignedLimb) & MAX_SIGNED_LIMB;
        cd >>= SIGNED_LIMB_SIZE;
        e.limbs[i - 1] = (ce as SignedLimb) & MAX_SIGNED_LIMB;
        ce >>= SIGNED_LIMB_SIZE;
    }

    di = d.limbs[SIGNED_LIMBS - 1];
    ei = e.limbs[SIGNED_LIMBS - 1];
    cd += (u as SignedDoubleLimb) * (di as SignedDoubleLimb)
        + (v as SignedDoubleLimb) * (ei as SignedDoubleLimb);
    ce += (q as SignedDoubleLimb) * (di as SignedDoubleLimb)
        + (r as SignedDoubleLimb) * (ei as SignedDoubleLimb);
    cd += (md as SignedDoubleLimb) << FINAL_LIMB_MODULUS_BITS;
    ce += (me as SignedDoubleLimb) << FINAL_LIMB_MODULUS_BITS;
    d.limbs[SIGNED_LIMBS - 2] = (cd as SignedLimb) & MAX_SIGNED_LIMB;
    cd >>= SIGNED_LIMB_SIZE;
    e.limbs[SIGNED_LIMBS - 2] = (ce as SignedLimb) & MAX_SIGNED_LIMB;
    ce >>= SIGNED_LIMB_SIZE;
    d.limbs[SIGNED_LIMBS - 1] = cd as SignedLimb;
    e.limbs[SIGNED_LIMBS - 1] = ce as SignedLimb;
}

/// [f, g] ← t·[f, g]/2^62 on the first `len` limbs.
fn update_fg(f: &mut Num3072Signed, g: &mut Num3072Signed, t: &SignedMatrix, len: usize) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut fi = f.limbs[0];
    let mut gi = g.limbs[0];
    let mut cf = (u as SignedDoubleLimb) * (fi as SignedDoubleLimb)
        + (v as SignedDoubleLimb) * (gi as SignedDoubleLimb);
    let mut cg = (q as SignedDoubleLimb) * (fi as SignedDoubleLimb)
        + (r as SignedDoubleLimb) * (gi as SignedDoubleLimb);
    debug_assert_eq!(cf & (MAX_SIGNED_LIMB as SignedDoubleLimb), 0);
    debug_assert_eq!(cg & (MAX_SIGNED_LIMB as SignedDoubleLimb), 0);
    cf >>= SIGNED_LIMB_SIZE;
    cg >>= SIGNED_LIMB_SIZE;
    for i in 1..len {
        fi = f.limbs[i];
        gi = g.limbs[i];
        cf += (u as SignedDoubleLimb) * (fi as SignedDoubleLimb)
            + (v as SignedDoubleLimb) * (gi as SignedDoubleLimb);
        cg += (q as SignedDoubleLimb) * (fi as SignedDoubleLimb)
            + (r as SignedDoubleLimb) * (gi as SignedDoubleLimb);
        f.limbs[i - 1] = (cf as SignedLimb) & MAX_SIGNED_LIMB;
        cf >>= SIGNED_LIMB_SIZE;
        g.limbs[i - 1] = (cg as SignedLimb) & MAX_SIGNED_LIMB;
        cg >>= SIGNED_LIMB_SIZE;
    }
    f.limbs[len - 1] = cf as SignedLimb;
    g.limbs[len - 1] = cg as SignedLimb;
}

/// ChaCha20 keystream — Core's `ChaCha20Aligned`: the 20-round cipher with
/// an all-zero nonce and block counter starting at zero, producing raw
/// keystream bytes (no XOR against plaintext).
struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    fn new(key: &[u8; 32]) -> Self {
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        let (key_words, _) = key.as_chunks::<4>();
        for (word, bytes) in state[4..12].iter_mut().zip(key_words) {
            *word = u32::from_le_bytes(*bytes);
        }
        // state[12..16]: block counter + nonce, all zero for the aligned
        // keystream form Core uses.
        ChaCha20 { state }
    }

    fn block(&mut self, out: &mut [u8; 64]) {
        let mut x = self.state;
        for _ in 0..10 {
            // Column rounds.
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            // Diagonal rounds.
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        for i in 0..16 {
            x[i] = x[i].wrapping_add(self.state[i]);
            out[4 * i..4 * i + 4].copy_from_slice(&x[i].to_le_bytes());
        }
        self.state[12] = self.state[12].wrapping_add(1);
    }

    fn keystream(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(64) {
            let mut block = [0u8; 64];
            self.block(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

/// The multiplicative set hash — numerator/denominator pair of `Num3072`s.
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    pub fn new() -> Self {
        let mut numerator = Num3072::zero();
        numerator.set_to_one();
        let mut denominator = Num3072::zero();
        denominator.set_to_one();
        MuHash3072 {
            numerator,
            denominator,
        }
    }

    /// `SHA256(data)` keyed ChaCha20 keystream → a group element.
    fn to_num3072(data: &[u8]) -> Num3072 {
        let hashed = crate::hash::sha256(data);
        let mut tmp = [0u8; BYTE_SIZE];
        ChaCha20::new(&hashed).keystream(&mut tmp);
        Num3072::from_bytes(&tmp)
    }

    /// Inserts a serialized element into the set.
    pub fn insert(&mut self, data: &[u8]) -> &mut Self {
        let el = Self::to_num3072(data);
        self.numerator.multiply(&el);
        self
    }

    /// Removes a serialized element (the element hashes into the
    /// denominator).
    #[allow(dead_code)]
    pub fn remove(&mut self, data: &[u8]) -> &mut Self {
        let el = Self::to_num3072(data);
        self.denominator.multiply(&el);
        self
    }

    /// The 256-bit set commitment: `SHA256(numerator/denominator)`.
    pub fn finalize(&mut self) -> [u8; 32] {
        let denominator = self.denominator.clone();
        self.numerator.divide(&denominator);
        self.denominator.set_to_one();
        let data = self.numerator.to_bytes();
        crate::hash::sha256(&data)
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// Core's `FromInt(i)` — a MuHash3072 constructed from the 32-byte
    /// array `{i, 0, ...}`: numerator = element, denominator = 1.
    fn from_int(i: u8) -> ([u8; 32], [u8; 32]) {
        let mut elem = [0u8; 32];
        elem[0] = i;
        let mut one = [0u8; 32];
        one[0] = 1; // denominator stays the multiplicative identity
        (elem, one)
    }

    /// `uint256{"..."}` display hex → the internal byte order Core
    /// stores.
    fn display_hex(raw: &[u8; 32]) -> String {
        let mut b = *raw;
        b.reverse();
        hex::encode(&b)
    }

    /// crypto_tests.cpp `muhash_tests`: FromInt(0)*FromInt(1)/FromInt(2)
    /// finalizes to a fixed uint256 — exercises multiply, divide (the
    /// divstep inverse), and ToBytes end to end.
    #[test]
    fn core_vector_insert_remove_finalize() {
        let (e0, _) = from_int(0);
        let (e1, _) = from_int(1);
        let (e2, _) = from_int(2);
        let mut h = MuHash3072::new();
        h.insert(&e0).insert(&e1).remove(&e2);
        assert_eq!(
            display_hex(&h.finalize()),
            "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
        );
    }

    /// The serialization vector: FromInt(1)*FromInt(2) serializes as
    /// numerator‖denominator bytes — pinning ToNum3072 (SHA256 + ChaCha20
    /// keystream) and Multiply at the limb level.
    #[test]
    fn core_vector_serialization() {
        let (e1, _) = from_int(1);
        let (e2, _) = from_int(2);
        let mut h = MuHash3072::new();
        h.insert(&e1).insert(&e2);
        let mut ser = Vec::with_capacity(2 * BYTE_SIZE);
        ser.extend_from_slice(&h.numerator.to_bytes());
        ser.extend_from_slice(&h.denominator.to_bytes());
        // ser_exp's numerator = the first 384 bytes (768 hex chars); its
        // denominator is Num3072(1) = `01` then zeros.
        let expected = concat!(
            "1fa093295ea30a6a3acdc7b3f770fa538eff537528e990e2910e40bbcfd7f6696b1256901929094694b56316de342f593303",
            "dd12ac43e06dce1be1ff8301c845beb15468fff0ef002dbf80c29f26e6452bccc91b5cb9437ad410d2a67ea847887fa3c6",
            "a6553309946880fe20db2c73fe0641adbd4e86edfee0d9f8cd0ee1230898873dc13ed8ddcaf045c80faa082774279007a2",
            "253f8922ee3ef361d378a6af3ddaf180b190ac97e556888c36b3d1fb1c85aab9ccd46e3deaeb7b7cf5db067a7e9ff86b65",
            "8cf3acd6662bbcce37232daa753c48b794356c020090c831a8304416e2aa7ad633c0ddb2f11be1be316a81be7f7e472071",
            "c042cb68faef549c221ebff209273638b741aba5a81675c45a5fa92fea4ca821d7a324cb1e1a2ccd3b76c4228ec8066dad",
            "2a5df6e1bd0de45c7dd5de8070bdb46db6c554cf9aefc9b7b2bbf9f75b1864d9f95005314593905c0109b71f703d49944a",
            "e94477b51dac10a816bb6d1c700bafabc8bd86fac8df24be519a2f2836b16392e18036cb13e48c5c",
        );
        // The denominator of a pure insert chain is 1 — the expected
        // bytes are numerator ‖ one ‖ zeros.
        let mut den = vec![0u8; BYTE_SIZE];
        den[0] = 1;
        let mut full = expected.to_string();
        full.push_str(&hex::encode(&den));
        assert_eq!(hex::encode(&ser), full);
    }

    /// Core's overflow vector: a numerator of all-0xFF (≥ modulus)
    /// reduces through Finalize without corrupting the result.
    #[test]
    fn core_vector_overflow() {
        let mut h = MuHash3072::new();
        h.numerator.limbs = [u64::MAX; LIMBS];
        // Core checks `HexStr(out4)` — raw byte order, not the
        // uint256 display reversal.
        assert_eq!(
            hex::encode(&h.finalize()),
            "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271"
        );
    }
}
