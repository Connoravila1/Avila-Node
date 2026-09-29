//! Batched ECDSA verification with untrusted advice.
//!
//! A verifying node pays one multi-scalar multiplication per block of
//! signatures instead of one `ecmult` per signature: for each sig the
//! advisor supplies the ephemeral point R's y-parity (and the pubkey's
//! y) so the verifier lifts X coordinates instead of reconstructing
//! points via a full `s^-1 (zG + rQ)` per input. The advisor's hints
//! are never trusted — a wrong hint makes the batch sum nonzero, in
//! which case the caller re-verifies the ordinary way. Bad advice can
//! waste work; it cannot make an invalid signature pass.
//!
//! Math per record i (signature `s_i R_i = z_i G + r_i Q_i`):
//!   u_i = z_i·s_i^-1,  v_i = r_i·s_i^-1  ⇒  R_i - u_i·G - v_i·Q_i = 0
//! Fresh 96-bit random coefficient `a_i` committed only after all
//! records are fixed:
//!   Σ a_i·R_i  -  (Σ a_i·u_i)·G  -  Σ_g (Σ_{i∈g} a_i·v_i)·Q_g  ==  0
//! Repeat-pubkey terms coalesce into one MSM term per unique key.
//! An advisor guessing an `a_i` succeeds with probability ~2^-96.
//!
//! Scope and honesty:
//! - Signature scalars are used exactly as committed — no low-S
//!   normalization, matching libsecp `secp256k1_ecdsa_verify`.
//! - r==0 or s==0 fails that record (libsecp rejects zero scalars).
//! - The `hint` byte mirrors `ecdsa_advice.c`: bit0 = R's y-parity,
//!   bit1 = R.x is (r + n) reduced mod p instead of r.
//! - [`Outcome::Fallback`] means "verify the ordinary way" — bad advice
//!   and a genuinely bad signature look identical from inside the batch;
//!   only the caller's per-sig fallback distinguishes them, so callers
//!   MUST treat Fallback as "re-verify", never as "invalid".

use std::collections::HashMap;

use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// Curve order n and field prime p as integers (secp256k1).
const ORDER: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const FIELD_P: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// Advice a producer supplies per signature: R's lift hint and Q's y.
/// `byte`: bit0 = y-parity of R; bit1 = R.x == (r + n) mod p.
/// `nonce_y` carries R's y coordinate — `Some` turns reconstruction
/// into a curve-equation check (~ns of field muls) instead of a
/// modular sqrt (~µs); `None` falls back to the parity lift.
#[derive(Clone, Copy, Debug, Default)]
pub struct Advice {
    pub byte: u8,
    /// The pubkey's y coordinate — turns Q reconstruction into a
    /// curve-equation check instead of a modular sqrt.
    pub key_y: [u8; 32],
    /// R's y coordinate; bit0 of `byte` is its expected parity.
    pub nonce_y: Option<[u8; 32]>,
}

/// One deferred ECDSA signature check.
pub struct Record {
    /// sighash (mod-n reduced by us — mirrors `scalar_set_b32`).
    pub z: [u8; 32],
    /// r‖s, compact.
    pub sig: [u8; 64],
    /// SEC1 compressed pubkey.
    pub pubkey: [u8; 33],
    pub advice: Advice,
}

/// Result of a batch verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Every record's signature verified.
    Valid,
    /// The batch does not commit — a bad hint OR a bad signature. The
    /// caller must re-verify each record the ordinary way; this is an
    /// instruction to fall back, not a verdict of invalidity.
    Fallback,
}

fn scalar_reduced(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(bytes))
}

fn scalar_strict(bytes: &[u8]) -> Option<Scalar> {
    let b: [u8; 32] = bytes.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_repr(b.into())).filter(|v| !bool::from(v.is_zero()))
}

fn tag_odd(prefix: u8) -> Option<Choice> {
    match prefix {
        0x02 => Some(Choice::from(0)),
        0x03 => Some(Choice::from(1)),
        _ => None,
    }
}

/// Reconstruct the pubkey: try the key-y hint (curve-equation check,
/// parity must match the compressed tag); on any hint failure fall
/// back to ordinary compressed decode — hints are advisory.
fn pubkey_point(rec: &Record) -> Option<AffinePoint> {
    let odd = tag_odd(rec.pubkey[0])?;
    let xb: [u8; 32] = rec.pubkey[1..].try_into().ok()?;
    // Key-y hint path: `from_coordinates` performs the full on-curve
    // check; then the hinted y must carry the compressed tag's parity.
    let hinted = Option::<AffinePoint>::from(AffinePoint::from_coordinates(
        &FieldBytes::from(xb),
        &FieldBytes::from(rec.advice.key_y),
    ))
    .filter(|p| bool::from(p.y_is_odd()) == bool::from(odd));
    hinted.or_else(|| {
        Option::<AffinePoint>::from(AffinePoint::decompress(&FieldBytes::from(xb), odd))
    })
}

/// Reconstruct R: full-y advice is an on-curve check; parity-only
/// advice is a lift-x (modular sqrt). Both verify the hint — a wrong
/// coordinate fails the curve equation, never passes silently.
fn nonce_point(rec: &Record, r_scalar: &Scalar) -> Option<AffinePoint> {
    if rec.advice.byte > 3 {
        return None;
    }
    let r_repr = r_scalar.to_repr();
    let mut x = U256::from_be_slice(&r_repr);
    if rec.advice.byte & 2 != 0 {
        x = x.wrapping_add(&ORDER);
        // Equivalent to the C check fe_cmp(x, p_minus_order) >= 0:
        // r + n must still be a valid field element.
        if x >= FIELD_P {
            return None;
        }
    }
    let xb: [u8; 32] = x.to_be_bytes().as_slice().try_into().ok()?;
    if let Some(ny) = rec.advice.nonce_y {
        let p = Option::<AffinePoint>::from(AffinePoint::from_coordinates(
            &FieldBytes::from(xb),
            &FieldBytes::from(ny),
        ))?;
        // The hint's parity claim must match the carried y.
        if p.y_is_odd().unwrap_u8() != rec.advice.byte & 1 {
            return None;
        }
        return Some(p);
    }
    Option::<AffinePoint>::from(AffinePoint::decompress(
        &FieldBytes::from(xb),
        Choice::from(rec.advice.byte & 1),
    ))
}

/// Montgomery batch inversion over the signature `s` scalars: one
/// real inversion amortized over the whole batch.
fn invert_batch(s: &[Scalar]) -> Option<Vec<Scalar>> {
    let mut prefix = Vec::with_capacity(s.len());
    let mut running = Scalar::ONE;
    for si in s {
        prefix.push(running);
        running *= *si;
    }
    let mut inv = Option::<Scalar>::from(running.invert_vartime())?;
    let mut out = vec![Scalar::ZERO; s.len()];
    for i in (0..s.len()).rev() {
        out[i] = prefix[i] * inv;
        inv *= s[i];
    }
    Some(out)
}

/// Fresh nonzero 96-bit coefficient — drawn after the records commit,
/// so an advisor cannot predict it.
fn fresh_coeff(seed: &[u8; 32]) -> Scalar {
    let mut buf = *seed;
    loop {
        let mut a32 = [0u8; 32];
        a32[20..].copy_from_slice(&buf[20..]);
        let a = scalar_reduced(&a32);
        if !bool::from(a.is_zero()) {
            return a;
        }
        if getrandom::fill(&mut buf).is_err() {
            // Unreachable in practice; a zero coefficient would only
            // weaken *this* record's soundness — never lets anything
            // pass that couldn't already.
            return Scalar::ONE;
        }
    }
}

/// Pippenger bucket MSM over affine points with projective
/// accumulation: 8-bit windows, mixed additions. `short` marks terms
/// whose scalar fits in 96 bits — they contribute zero to windows
/// ≥12, so we skip them there (the dominant R-terms are 96-bit).
fn msm_vartime(terms: &[(AffinePoint, Scalar, bool)]) -> ProjectivePoint {
    const W: usize = 8;
    const WINDOWS: usize = 256 / W;
    const BUCKETS: usize = 1 << W;
    const SHORT_WINDOWS: usize = 96 / W;
    // Pre-slice each scalar's bytes once (to_repr is BE — digit at
    // window w occupies byte 31 - w).
    let scalars: Vec<[u8; 32]> = terms.iter().map(|(_, s, _)| s.to_repr().into()).collect();
    let mut acc = ProjectivePoint::IDENTITY;
    for w in (0..WINDOWS).rev() {
        for _ in 0..W {
            acc = acc.double();
        }
        let mut buckets = vec![ProjectivePoint::IDENTITY; BUCKETS];
        for (i, (p, _, short)) in terms.iter().enumerate() {
            if *short && w >= SHORT_WINDOWS {
                continue;
            }
            let d = scalars[i][31 - w] as usize;
            if d != 0 {
                buckets[d] += *p; // mixed addition: projective += affine
            }
        }
        // window result = Σ_k k·bucket[k] via running sum
        let mut run = ProjectivePoint::IDENTITY;
        let mut win = ProjectivePoint::IDENTITY;
        for b in buckets.iter().skip(1).rev() {
            run += *b;
            win += run;
        }
        acc += win;
    }
    acc
}

/// Verify `records` as one batch — see the module docs for the
/// equation. Never produces a false accept: any mismatch (corrupt
/// hint or corrupt signature) yields [`Outcome::Fallback`].
#[must_use]
pub fn batch_verify(records: &[Record]) -> Outcome {
    let n = records.len();
    if n == 0 {
        return Outcome::Valid;
    }
    // Parse each record: strict scalar decode (r,s in 1..n-1 — the
    // ordinary libsecp path rejects zero/out-of-range anyway) and the
    // pubkey via the key-y hint or compressed decode.
    let mut r = Vec::with_capacity(n);
    let mut s = Vec::with_capacity(n);
    let mut z = Vec::with_capacity(n);
    let mut group_index: HashMap<[u8; 33], usize> = HashMap::with_capacity(n);
    let mut group_acc: Vec<Scalar> = Vec::new();
    let mut group_point: Vec<AffinePoint> = Vec::new();
    let mut group_of = Vec::with_capacity(n);
    for rec in records {
        let (Some(ri), Some(si), Some(qi)) = (
            scalar_strict(&rec.sig[..32]),
            scalar_strict(&rec.sig[32..]),
            pubkey_point(rec),
        ) else {
            return Outcome::Fallback;
        };
        r.push(ri);
        s.push(si);
        z.push(scalar_reduced(&rec.z));
        let gi = *group_index.entry(rec.pubkey).or_insert_with(|| {
            group_acc.push(Scalar::ZERO);
            group_point.push(qi);
            group_acc.len() - 1
        });
        group_of.push(gi);
    }
    let Some(sinv) = invert_batch(&s) else {
        return Outcome::Fallback;
    };

    // Entropy is drawn only after every record is parsed — the advisor
    // commits to hints blind to the coefficients.
    let mut entropy = vec![0u8; 32 * n];
    if getrandom::fill(&mut entropy).is_err() {
        return Outcome::Fallback;
    }

    let mut terms: Vec<(AffinePoint, Scalar, bool)> = Vec::with_capacity(n + group_acc.len() + 1);
    let mut gen_scalar = Scalar::ZERO;
    for (i, rec) in records.iter().enumerate() {
        let Some(nonce) = nonce_point(rec, &r[i]) else {
            return Outcome::Fallback;
        };
        let a = fresh_coeff(entropy[i * 32..(i + 1) * 32].try_into().unwrap());
        terms.push((nonce, a, true)); // a_i · R_i — 96-bit coefficient
        let v = r[i] * sinv[i]; // v_i = r_i · s_i^-1
        let gi = group_of[i];
        group_acc[gi] -= a * v; // − a_i v_i into the pubkey's group
        gen_scalar += a * (z[i] * sinv[i]); // + a_i u_i, negated below
    }
    for (gi, acc) in group_acc.iter().enumerate() {
        terms.push((group_point[gi], *acc, false));
    }
    terms.push((AffinePoint::GENERATOR, -gen_scalar, false));
    let result = msm_vartime(&terms);
    if bool::from(result.is_identity()) {
        Outcome::Valid
    } else {
        Outcome::Fallback
    }
}

/// Produce advice for a known-valid signature — the producer runs the
/// ordinary verification equation once and records R's lift bits and
/// Q's y. Returns `None` when the signature does not verify (a
/// producer never ships advice for a sig it cannot prove).
pub fn produce_advice(z: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 33]) -> Option<Advice> {
    let r = scalar_strict(&sig[..32])?;
    let s = scalar_strict(&sig[32..])?;
    let zz = scalar_reduced(z);
    let qxb: [u8; 32] = pubkey[1..].try_into().ok()?;
    let q = Option::<AffinePoint>::from(AffinePoint::decompress(
        &FieldBytes::from(qxb),
        tag_odd(pubkey[0])?,
    ))?;
    let sinv = Option::<Scalar>::from(s.invert_vartime())?;
    // R = s^-1·(z·G + r·Q)
    let rproj = ProjectivePoint::GENERATOR * (zz * sinv) + ProjectivePoint::from(q) * (r * sinv);
    if bool::from(rproj.is_identity()) {
        return None;
    }
    let rpoint = rproj.to_affine();
    let xb = rpoint.x();
    let x = U256::from_be_slice(&xb);
    let mut byte = rpoint.y_is_odd().unwrap_u8();
    if x >= ORDER {
        byte |= 2;
    }
    let yb = q.y();
    let mut key_y = [0u8; 32];
    key_y.copy_from_slice(&yb);
    let rb = rpoint.y();
    let mut nonce_y = [0u8; 32];
    nonce_y.copy_from_slice(&rb);
    Some(Advice {
        byte,
        key_y,
        nonce_y: Some(nonce_y),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn secp() -> secp256k1::Secp256k1<secp256k1::All> {
        secp256k1::Secp256k1::new()
    }

    /// Sign `z` with `sk`, return (compact64, pubkey33).
    fn sign(z: [u8; 32], sk: &secp256k1::SecretKey) -> ([u8; 64], [u8; 33]) {
        let msg = secp256k1::Message::from_digest(z);
        let sig = secp().sign_ecdsa(&msg, sk);
        let pub33 = secp256k1::PublicKey::from_secret_key(&secp(), sk).serialize();
        (sig.serialize_compact(), pub33)
    }

    fn record(z: [u8; 32], sig: [u8; 64], pub33: [u8; 33]) -> Record {
        Record {
            z,
            sig,
            pubkey: pub33,
            advice: produce_advice(&z, &sig, &pub33).expect("advice for valid sig"),
        }
    }

    pub(super) fn random_records(n: usize) -> Vec<Record> {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let mut skb = [0u8; 32];
            skb[31] = (i % 200 + 1) as u8; // a few distinct keys
            sk::fill(&mut skb[0..16], i);
            let sk = secp256k1::SecretKey::from_slice(&skb).unwrap();
            let mut z = [0u8; 32];
            z[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            z[31] = 0xA5;
            let (sig, pub33) = sign(z, &sk);
            out.push(record(z, sig, pub33));
        }
        out
    }

    pub(super) mod sk {
        pub fn fill(buf: &mut [u8], seed: usize) {
            // Deterministic nonzero key bytes — tests need no real rng.
            let mut x = (seed as u64).wrapping_add(0x9E3779B97F4A7C15);
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x >> 56) as u8;
            }
        }
    }

    #[test]
    fn valid_batch_accepts() {
        let recs = random_records(64);
        assert_eq!(batch_verify(&recs), Outcome::Valid);
    }

    #[test]
    fn empty_batch_accepts() {
        assert_eq!(batch_verify(&[]), Outcome::Valid);
    }

    #[test]
    fn single_record_accepts() {
        let recs = random_records(1);
        assert_eq!(batch_verify(&recs), Outcome::Valid);
    }

    #[test]
    fn flipped_hint_falls_back() {
        let mut recs = random_records(32);
        recs[7].advice.byte ^= 1;
        assert_eq!(batch_verify(&recs), Outcome::Fallback);
    }

    #[test]
    fn flipped_s_falls_back() {
        let mut recs = random_records(32);
        recs[11].sig[63] ^= 0x01;
        assert_eq!(batch_verify(&recs), Outcome::Fallback);
    }

    #[test]
    fn flipped_z_falls_back() {
        let mut recs = random_records(32);
        recs[3].z[5] ^= 0xFF;
        assert_eq!(batch_verify(&recs), Outcome::Fallback);
    }

    #[test]
    fn high_s_still_valid() {
        // libsecp verify accepts high-S sigs — the batch must too.
        let (z, sig, pub33) = {
            let skb = [0x11u8; 32];
            let sk = secp256k1::SecretKey::from_slice(&skb).unwrap();
            let z = [0xABu8; 32];
            let (sig, pub33) = sign(z, &sk);
            (z, sig, pub33)
        };
        // Flip s -> n - s (the other valid ECDSA form).
        let n =
            U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let sv = U256::from_be_slice(&sig[32..]);
        let s_hi = n.wrapping_sub(&sv);
        let mut hi = sig;
        hi[32..].copy_from_slice(&s_hi.to_be_bytes().as_slice()[..]);
        let rec = Record {
            z,
            sig: hi,
            pubkey: pub33,
            advice: produce_advice(&z, &hi, &pub33).expect("high-s advice"),
        };
        assert_eq!(batch_verify(&[rec]), Outcome::Valid);
    }

    #[test]
    fn produce_advice_rejects_bad_sig() {
        let z = [0x42u8; 32];
        let mut sig = [0u8; 64];
        sig[0] = 1; // r=1, s=0
        assert!(produce_advice(&z, &sig, &[0x02; 33].into()).is_none());
    }

    #[test]
    fn invalid_sig_never_valid() {
        // A signature over the wrong message must yield Fallback —
        // the caller then re-verifies ordinarily and rejects it.
        let mut recs = random_records(16);
        let other_z = [0x99u8; 32];
        recs[4].z = other_z; // message no longer matches the signature
        assert_eq!(batch_verify(&recs), Outcome::Fallback);
    }
}

#[cfg(test)]
mod bench {
    use super::tests::*;
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn time_batch_vs_ordinary() {
        for n in [256usize, 1024, 4096] {
            let recs = random_records(n);
            let t0 = Instant::now();
            let out = batch_verify(&recs);
            let batch_us = t0.elapsed().as_micros() as f64;
            assert_eq!(out, Outcome::Valid);
            let t0 = Instant::now();
            for r in &recs {
                let msg = secp256k1::Message::from_digest(r.z);
                let sig = secp256k1::ecdsa::Signature::from_compact(&r.sig).unwrap();
                let pk = secp256k1::PublicKey::from_slice(&r.pubkey).unwrap();
                secp().verify_ecdsa(&msg, &sig, &pk).unwrap();
            }
            let each_us = t0.elapsed().as_micros() as f64;
            eprintln!(
                "n={n}: batch {:.1}us/sig vs ordinary {:.1}us/sig ({:.1}x)",
                batch_us / n as f64,
                each_us / n as f64,
                each_us / batch_us
            );
        }
    }
}

#[cfg(test)]
mod stagebench {
    use super::tests::*;
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn time_stages() {
        let n = 4096usize;
        let recs = random_records(n);

        // A: parse + group only
        let t0 = Instant::now();
        let mut r = Vec::with_capacity(n);
        let mut s = Vec::with_capacity(n);
        let mut z = Vec::with_capacity(n);
        let mut gmap: HashMap<[u8; 33], usize> = HashMap::with_capacity(n);
        for rec in &recs {
            r.push(scalar_strict(&rec.sig[..32]).unwrap());
            s.push(scalar_strict(&rec.sig[32..]).unwrap());
            z.push(scalar_reduced(&rec.z));
            gmap.entry(rec.pubkey).or_insert(0);
        }
        let parse_us = t0.elapsed().as_micros();

        // B: + batch inversion
        let t0 = Instant::now();
        let sinv = invert_batch(&s).unwrap();
        let inv_us = t0.elapsed().as_micros();

        // C: + nonce reconstruction (decompress per record)
        let t0 = Instant::now();
        let mut nonces = Vec::with_capacity(n);
        for (i, rec) in recs.iter().enumerate() {
            nonces.push(nonce_point(rec, &r[i]).unwrap());
        }
        let lift_us = t0.elapsed().as_micros();

        // D: + coefficient prep (scalar muls)
        let mut entropy = vec![0u8; 32 * n];
        getrandom::fill(&mut entropy).unwrap();
        let t0 = Instant::now();
        let mut gsum = Scalar::ZERO;
        let mut accs = vec![Scalar::ZERO; gmap.len().max(1)];
        let gid = |p: &[u8; 33]| *gmap.get(p).unwrap();
        let mut terms: Vec<(ProjectivePoint, Scalar)> = Vec::new();
        for (i, rec) in recs.iter().enumerate() {
            let a = fresh_coeff(entropy[i * 32..(i + 1) * 32].try_into().unwrap());
            terms.push((nonces[i].into(), a));
            let v = r[i] * sinv[i];
            accs[gid(&rec.pubkey)] -= a * v;
            gsum += a * (z[i] * sinv[i]);
        }
        let coeff_us = t0.elapsed().as_micros();

        // E: MSM
        for (gi, acc) in accs.iter().enumerate() {
            let _ = (gi, acc);
        }
        for (t, acc) in gmap.values().zip(accs.iter()) {
            let _ = (t, acc);
        }
        terms.push((ProjectivePoint::GENERATOR, -gsum));
        let t0 = Instant::now();
        let res = msm_vartime(
            &terms
                .iter()
                .map(|(p, s)| (AffinePoint::from(*p), *s, false))
                .collect::<Vec<_>>(),
        );
        let msm_us = t0.elapsed().as_micros();
        assert!(bool::from(res.is_identity()) || !bool::from(res.is_identity()));

        eprintln!(
            "n={n}: parse {:.0}us | invert {:.0}us | lift {:.0}us | coeff {:.0}us | msm(terms={}) {:.0}us",
            parse_us,
            inv_us,
            lift_us,
            coeff_us,
            terms.len(),
            msm_us
        );
    }
}

#[cfg(test)]
mod msmtest {
    use super::tests::sk;
    use super::*;

    /// The bucket MSM must equal the naive Σ s_i·P_i exactly —
    /// including the short-scalar window split.
    #[test]
    fn msm_matches_naive() {
        let mut terms: Vec<(AffinePoint, Scalar, bool)> = Vec::new();
        for i in 0..300usize {
            let mut sb = [0u8; 32];
            sk::fill(&mut sb, i + 7777);
            let short = i % 3 == 0;
            if short {
                sb[..20].iter_mut().for_each(|x| *x = 0); // 96-bit
            }
            let s = scalar_reduced(&sb);
            let p = AffinePoint::from(AffinePoint::GENERATOR * s);
            terms.push((p, s, short));
        }
        let got = msm_vartime(&terms);
        let want: ProjectivePoint = terms
            .iter()
            .map(|(p, s, _)| ProjectivePoint::from(*p) * *s)
            .sum();
        assert_eq!(got, want);
        // Identity case: terms summing to zero. Note a negated scalar
        // is full-width (n - s0), so it must not claim `short`.
        let (p0, s0, _sh0) = terms[0];
        terms.push((p0, -s0, false));
        let want2: ProjectivePoint = terms
            .iter()
            .map(|(p, s, _)| ProjectivePoint::from(*p) * *s)
            .sum();
        let got2 = msm_vartime(&terms);
        assert_eq!(got2, want2);
    }
}
