//! ECDSA batch-verify cost model — does an SP-style batch ever
//! beat libsecp's individual verify on secp256k1?
//!
//! Batch structure (Karati-Das / summation-polynomial):
//!   per sig: lift_x(r) + one scalar mul (randomizer a_i*P_i)
//!   shared:  one 2t-term MSM for the RHS point T
//!   shared:  SP evaluation — iterated univariate resultants mod p
//! If the optimistic sum can't beat individual verify, stop here.
//!
//! Note: k256 0.14 keeps the base field private; `Scalar` (mod n,
//! same 4x64 width) stands in for field-element ops in the
//! resultant model — identical cost class.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::ops::{LinearCombination, Reduce};
use k256::elliptic_curve::point::DecompressPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use std::time::Instant;

fn scalar(i: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i.wrapping_mul(0x9E3779B97F4A7C15)).to_le_bytes());
    b[8..16].copy_from_slice(&(i ^ 0xDEADBEEF).to_le_bytes());
    b[16..24].copy_from_slice(&(i.wrapping_add(1).wrapping_mul(0x2545F4914F6CDD1D)).to_le_bytes());
    Scalar::reduce(&U256::from_be_slice(&b))
}

fn main() {
    let n = 64usize;

    // ---- baseline: libsecp individual verify --------------------
    let secp_s = secp256k1::Secp256k1::new();
    let secp = secp256k1::Secp256k1::verification_only();
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    let mut msgs = Vec::new();
    for i in 0..n {
        let sk = secp256k1::SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp_s, &sk);
        let msg = secp256k1::Message::from_digest_slice(&[i as u8 + 7; 32]).unwrap();
        let sig = secp_s.sign_ecdsa(&msg, &sk);
        keys.push(pk);
        sigs.push(sig);
        msgs.push(msg);
    }
    let t0 = Instant::now();
    for i in 0..n {
        assert!(secp.verify_ecdsa(&msgs[i], &sigs[i], &keys[i]).is_ok());
    }
    let per_sig = t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0;
    println!("libsecp verify_ecdsa: {per_sig:.1} us/sig  ({n} sigs)");

    // ---- component 1: lift_x (field sqrt + curve check) ---------
    let xs: Vec<Scalar> = (0..n).map(|i| scalar(i as u64 * 2 + 1)).collect();
    let t0 = Instant::now();
    let mut hits = 0usize;
    for x in &xs {
        if bool::from(AffinePoint::decompress(&x.to_bytes(), 0u8.into()).is_some()) {
            hits += 1;
        }
    }
    let sqrt_us = t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0;
    println!("k256 lift_x: {sqrt_us:.1} us  ({hits}/{n} on-curve)");

    // ---- component 2: scalar mul on arbitrary point -------------
    let pts: Vec<ProjectivePoint> = (0..n)
        .map(|i| ProjectivePoint::GENERATOR * scalar(i as u64 + 100))
        .collect();
    let t0 = Instant::now();
    let mut acc = ProjectivePoint::IDENTITY;
    for (i, p) in pts.iter().enumerate() {
        acc += *p * scalar(i as u64 + 200);
    }
    let smul_us = t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0;
    let _ = acc;
    println!("k256 scalar mul (var-base): {smul_us:.1} us");

    // ---- component 3: shared MSM (2t terms via lincomb) ---------
    for t in [4usize, 8, 9] {
        let m = 2 * t;
        let sc: Vec<Scalar> = (0..m).map(|i| scalar(i as u64 + 300)).collect();
        let pt: Vec<ProjectivePoint> = (0..m)
            .map(|i| ProjectivePoint::GENERATOR * scalar(i as u64 + 400))
            .collect();
        let t0 = Instant::now();
        let reps = 20;
        for _ in 0..reps {
            let _ = ProjectivePoint::lincomb(
                pt.iter()
                    .copied()
                    .zip(sc.iter().copied())
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
        }
        let us = t0.elapsed().as_nanos() as f64 / reps as f64 / 1000.0;
        println!("k256 MSM (2t={m} terms): {us:.1} us");
    }

    // ---- component 4: SP eval — the resultant chain -------------
    // Evaluating S_{t+1} at field points iterates univariate
    // resultants; dominant degree ~2^{t-2} (deg-64 at t=8 ->
    // 128x128 Sylvester determinant, O(m^3) field ops).
    for deg in [4usize, 8, 16, 32, 64] {
        let m = 2 * deg;
        let mut a = vec![vec![Scalar::ZERO; m]; m];
        for (i, r) in a.iter_mut().enumerate() {
            for (j, c) in r.iter_mut().enumerate() {
                *c = scalar((i * m + j) as u64 + 500);
            }
        }
        let t0 = Instant::now();
        let mut det = Scalar::ONE;
        for i in 0..m {
            if bool::from(a[i][i].is_zero()) {
                det = Scalar::ZERO;
                break;
            }
            let inv = a[i][i].invert().unwrap();
            det *= a[i][i];
            let (lo, hi) = a.split_at_mut(i + 1);
            for r in hi.iter_mut() {
                let f = r[i] * inv;
                for c in i..m {
                    r[c] -= f * lo[i][c];
                }
            }
        }
        let us = t0.elapsed().as_nanos() as f64 / 1000.0;
        let _ = det;
        println!(
            "Sylvester det {m}x{m} (resultant deg {deg}): {us:.0} us = {:.1} verifies",
            us / per_sig
        );
    }

    let t0 = Instant::now();
    let mut accf = Scalar::ONE;
    for x in &xs {
        accf *= *x;
    }
    let mul_ns = t0.elapsed().as_nanos() as f64 / n as f64;
    let _ = accf;
    println!("k256 scalar mul (mod-n): {mul_ns:.0} ns");
}
