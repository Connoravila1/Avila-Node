//! Watch-only descriptor wallet — Core's `importdescriptors` model.
//!
//! The wallet tracks descriptor-owned scripts against the active
//! chain: `importdescriptors` registers a (possibly ranged) descriptor
//! and rescans from its timestamp; each block connect advances the
//! scan; a reorg rewinds it. Confirmed receipts and spends persist to
//! `watchlist.dat` in the network data dir; mempool receipts and
//! pending spends are folded in per query, like Core's
//! `AvailableCoins` over `mempool`.
//!
//! Signing keys never enter this wallet — an imported descriptor's
//! private material is expanded to scripts and then discarded; every
//! tracked coin reports `spendable: false`, `solvable: true`.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;

use avila_consensus::hex;

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::transaction::OutPoint;

/// A BIP352 silent-payments watch — (scan private key, spend public
/// key). Only detection lives here: the spend key's private half is
/// never required to watch, matching the wallet's watch-only rule.
#[derive(Debug, Clone)]
pub struct SilentWatch {
    /// `d_scan` — the 32-byte scan private key.
    pub scan_priv: [u8; 32],
    /// `B_spend` — the x-only spend public key (taproot internal key
    /// the sender tweaks per payment).
    pub spend_pub: [u8; 32],
}

/// One imported descriptor — Core's `WalletDescriptor`: the
/// checksummed string plus the import-request metadata. `scripts` is
/// the expanded `[range]` script set keyed back to its derivation
/// index so `listunspent`'s `desc` field can name the exact child.
#[derive(Debug, Clone)]
pub struct TrackedDesc {
    /// Canonical descriptor text including `#checksum`.
    pub desc: String,
    /// Creation/rescan timestamp (`importdescriptors` `timestamp`;
    /// `"now"` resolves to the chain tip's time at import).
    pub timestamp: i64,
    /// `active` — Core's active-flag bookkeeping (`next_index`
    /// tracking lands with it).
    pub active: bool,
    /// `internal` — change-side descriptor (only meaningful when
    /// `active`, like Core).
    pub internal: bool,
    /// `label` — only allowed on non-ranged external descriptors.
    pub label: String,
    /// `next_index` — Core's cursor for ranged descriptors.
    pub next_index: u32,
    /// `[begin, end]` derivation range — `(0, 0)` for un-ranged.
    pub range: (u32, u32),
    /// Expanded scriptPubKeys → derivation position.
    pub scripts: HashMap<Vec<u8>, u32>,
}

/// A confirmed chain coin paying to a tracked script. Spent coins are
/// retained (with `spent_height`) so `listreceivedbyaddress` can still
/// report the receipt, matching Core's wallet which keeps spent
/// outputs in `mapWallet`.
#[derive(Debug, Clone)]
pub struct WatchedCoin {
    /// Height of the block that created it.
    pub height: u32,
    /// The creating block — rechecked on reorg rewind.
    pub block: BlockHash,
    /// Satoshis.
    pub value: i64,
    /// The scriptPubKey bytes.
    pub script: Vec<u8>,
    /// Which descriptor produced the script.
    pub desc_idx: usize,
    /// Coinbase outputs are untrusted until they mature (BIP30-style
    /// immaturity — Core's `IsImmatureCoinBase`, 100 confs).
    pub coinbase: bool,
    /// Height of the block that spent it (`None` while unspent).
    pub spent_height: Option<u32>,
    /// The spending txid, for reporting.
    pub spent_by: Option<Txid>,
}

/// The resolved seed + its provenance — [`resolve_entropy`]'s output.
pub struct ResolvedEntropy {
    /// The 32-byte BIP32 seed.
    pub seed: Vec<u8>,
    /// "os" | "user" | "dice" | "mixed:os+user" | "mixed:os+dice".
    pub provenance: String,
    /// `sha256(raw entropy input)` — the commit-before-generate
    /// record; re-rolling the same dice recomputes it, so provenance
    /// is checkable, not just asserted.
    pub commitment: String,
    /// Non-fatal caveats (too-few rolls, skewed distribution).
    pub warnings: Vec<String>,
}

/// `createdescriptorseed`'s entropy ceremony (queue #37): caller
/// hex, Coldcard-convention dice rolls (SHA256 over the ASCII digits;
/// ≥50 rolls for 128 bits, ≥99 for 256; a face over 30% of rolls is
/// a skew warning), or the OS CSPRNG — `mix` XOR-folds OS entropy
/// into the caller's, so no single bad source decides the seed.
///
/// The commitment is `sha256(DOMAIN || input)` — domain-separated
/// from seed derivation (`seed = sha256(input)` for dice, per the
/// Coldcard convention). Publishing the commitment can never publish
/// the seed: the two are different hashes of the same preimage, and
/// the ≥50-roll floor puts the preimage space beyond brute force.
///
/// # Errors
/// Invalid hex, dice characters outside `1..=6`, or too little
/// material (<16 bytes hex / <50 rolls) is a hard error.
pub fn resolve_entropy(
    entropy_hex: Option<&str>,
    dice: Option<&str>,
    mix: bool,
) -> Result<ResolvedEntropy, String> {
    /// Domain tag so `sha256(tag || input)` ≠ `sha256(input)` — the
    /// commitment is publishable provenance, never the seed itself.
    const COMMIT_DOMAIN: &[u8] = b"AVILA-ENTROPY-COMMIT-v1\x00";
    fn commit(input: &[u8]) -> String {
        let mut preimage = COMMIT_DOMAIN.to_vec();
        preimage.extend_from_slice(input);
        hex::encode(&avila_consensus::hash::sha256(&preimage))
    }
    let mut warnings = Vec::new();
    // Audit low: two entropy inputs at once is a caller bug — picking
    // one silently risks seeding from the wrong source. Refuse.
    if dice.is_some() && entropy_hex.is_some() {
        return Err("entropy and dice are mutually exclusive — pick one source".into());
    }
    let (mut seed, source, input_commit) = if let Some(rolls) = dice {
        let rolls = rolls.trim();
        // Hard floor: 50 D6 rolls ≈ 129 bits. Fewer than that is a
        // wallet somebody can grind — a warning is not enough.
        if rolls.len() < 50 {
            return Err(format!(
                "dice entropy needs >=50 rolls for 128 bits ({} given); 99 for 256-bit",
                rolls.len()
            ));
        }
        if rolls.len() < 99 {
            warnings.push(format!(
                "{} rolls covers 128 bits; 99 rolls gives the full 256",
                rolls.len()
            ));
        }
        let mut faces = [0u32; 7];
        let mut digits = String::with_capacity(rolls.len());
        for ch in rolls.chars() {
            if !('1'..='6').contains(&ch) {
                return Err(format!("dice rolls must be digits 1-6 (got '{ch}')"));
            }
            faces[ch as usize - '0' as usize] += 1;
            digits.push(ch);
        }
        if faces
            .iter()
            .any(|&c| (c as f64) > rolls.len() as f64 * 0.30)
        {
            warnings.push("skewed roll distribution (>30% one face) — biased dice?".into());
        }
        // Coldcard: SHA256 over the ASCII digits — cross-verifiable
        // with the firmware's own derivation.
        let raw = avila_consensus::hash::sha256(digits.as_bytes());
        (raw.to_vec(), "dice", digits.as_bytes().to_vec())
    } else if let Some(h) = entropy_hex {
        let b = hex::decode(h.trim()).map_err(|e| format!("entropy must be hex: {e}"))?;
        if b.len() < 16 {
            return Err(format!("entropy must be >=16 bytes (got {})", b.len()));
        }
        let seed = if b.len() == 32 {
            b.clone()
        } else {
            avila_consensus::hash::sha256(&b).to_vec()
        };
        (seed, "user", b)
    } else {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).map_err(|e| format!("entropy source failed: {e}"))?;
        (s.to_vec(), "os", s.to_vec())
    };
    let provenance = if mix && source != "os" {
        let mut os = [0u8; 32];
        getrandom::fill(&mut os).map_err(|e| format!("entropy source failed: {e}"))?;
        for (a, b) in seed.iter_mut().zip(os.iter()) {
            *a ^= b;
        }
        format!("mixed:os+{source}")
    } else {
        source.to_string()
    };
    Ok(ResolvedEntropy {
        seed,
        provenance,
        commitment: commit(&input_commit),
        warnings,
    })
}

/// Vault format: `AVLAVLT1` || argon2 params (m,t,p as u32 LE) ||
/// salt(32) || nonce(12) || ciphertext+tag — argon2id passphrase KDF
/// feeding ChaCha20Poly1305. The plaintext is the signer's private
/// descriptors + provenance records (NOT the watch list — secrets
/// never share a file with watch state).
/// Build the signer provider from private descriptors — parse each
/// xprv root, then expand a bounded lookahead collecting derived
/// secrets + origins (descriptor.rs's `ExpandPrivate`). Shared by
/// `createdescriptorseed`, `signerload`, and the `avila signer`
/// subprocess (queue #39's boundary).
pub fn signer_provider_from_descs(
    descs_private: &[String],
    params: &avila_consensus::params::Params,
) -> Result<avila_consensus::descriptor::FlatProvider, String> {
    let mut signing = avila_consensus::descriptor::FlatProvider::default();
    let mut expanded = avila_consensus::descriptor::FlatProvider::default();
    for d in descs_private {
        let (parsed, mut p, _) = avila_consensus::descriptor::parse_descriptors(d, params, true)?;
        // FlatProvider's secret-erasing Drop forbids moving fields
        // out — take the maps.
        signing.keys.extend(std::mem::take(&mut p.keys));
        signing.xprvs.extend(std::mem::take(&mut p.xprvs));
        let mut cache = avila_consensus::descriptor::DeriveCache::new();
        for pos in 0..64u32 {
            let _ = parsed[0].expand_into(pos, &signing, &mut expanded, true, &mut cache);
        }
    }
    signing.keys.extend(std::mem::take(&mut expanded.keys));
    signing
        .pubkeys
        .extend(std::mem::take(&mut expanded.pubkeys));
    signing
        .origins
        .extend(std::mem::take(&mut expanded.origins));
    signing
        .scripts
        .extend(std::mem::take(&mut expanded.scripts));
    signing
        .tr_trees
        .extend(std::mem::take(&mut expanded.tr_trees));
    Ok(signing)
}

const VAULT_MAGIC: &[u8; 8] = b"AVLAVLT1";
/// Argon2id params — memory-hard at wallet scale (64 MiB, 3 lanes,
/// 2 passes): a stolen vault resists commodity GPU grinding far
/// better than any iterated-hash KDF.
const VAULT_ARGON_M: u32 = 65_536;
const VAULT_ARGON_T: u32 = 2;
const VAULT_ARGON_P: u32 = 3;

/// What a vault carries — enough to rebuild `SignerState` from the
/// private descriptors (derivation is deterministic; the seed is
/// never stored separately) plus the BIP352 scan keys (audit V-S1:
/// they are secrets, so they live here — never in watchlist.dat).
pub struct VaultContents {
    /// The xprv descriptors (with checksums).
    pub descs_private: Vec<String>,
    /// Neutered watch descriptors (public — safe in any file).
    pub descs_watch: Vec<String>,
    /// "os" | "user" | "dice" | "mixed:…".
    pub provenance: String,
    /// `sha256(DOMAIN || raw entropy input)` at creation time.
    pub entropy_commitment: String,
    /// BIP352 scan watches: (scan_priv, spend_pub, labels).
    pub silents: Vec<([u8; 32], [u8; 33], Vec<u32>)>,
}

/// Audit V-S3: parsed vault contents hold xprv text and scan keys —
/// erase them on drop so freed pages don't retain key material.
impl Drop for VaultContents {
    fn drop(&mut self) {
        for d in &mut self.descs_private {
            zeroize::Zeroize::zeroize(d);
        }
        for (scan, _, _) in &mut self.silents {
            zeroize::Zeroize::zeroize(scan);
        }
    }
}

/// Seal the signer's secrets under `passphrase` — argon2id KDF →
/// ChaCha20Poly1305 AEAD over the private descriptors + provenance.
///
/// # Errors
/// RNG or KDF failure — both are fatal for a vault write.
pub fn vault_seal(
    signer: &SignerState,
    silents: &[avila_consensus::silent::SilentAddress],
    passphrase: &str,
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    let mut pt = Vec::new();
    pt.push(signer.provenance.len() as u8);
    pt.extend_from_slice(signer.provenance.as_bytes());
    pt.push(signer.entropy_commitment.len() as u8);
    pt.extend_from_slice(signer.entropy_commitment.as_bytes());
    pt.extend_from_slice(&(signer.descs_private.len() as u32).to_le_bytes());
    for d in &signer.descs_private {
        pt.extend_from_slice(&(d.len() as u32).to_le_bytes());
        pt.extend_from_slice(d.as_bytes());
    }
    pt.extend_from_slice(&(signer.descs_watch.len() as u32).to_le_bytes());
    for d in &signer.descs_watch {
        pt.extend_from_slice(&(d.len() as u32).to_le_bytes());
        pt.extend_from_slice(d.as_bytes());
    }
    // BIP352 scan keys — V-S1: secrets belong in the AEAD-protected
    // vault, not in the watchlist's plaintext.
    pt.extend_from_slice(&(silents.len() as u32).to_le_bytes());
    for a in silents {
        pt.extend_from_slice(&a.scan_priv);
        pt.extend_from_slice(&a.spend_pub);
        pt.extend_from_slice(&(a.labels.len() as u32).to_le_bytes());
        for m in &a.labels {
            pt.extend_from_slice(&m.to_le_bytes());
        }
    }
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| format!("rng failed: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("rng failed: {e}"))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(VAULT_ARGON_M, VAULT_ARGON_T, VAULT_ARGON_P, Some(32))
            .map_err(|e| format!("argon2 params: {e}"))?,
    );
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("argon2: {e}"))?;
    // Header first — the whole header (magic, params, salt, nonce)
    // becomes the AEAD's associated data, so tampering with the KDF
    // parameters is detected at open, not rewarded (audit V-S2).
    let mut out = VAULT_MAGIC.to_vec();
    for v in [VAULT_ARGON_M, VAULT_ARGON_T, VAULT_ARGON_P] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            chacha20poly1305::aead::Payload {
                msg: &pt,
                aad: &out,
            },
        )
        .map_err(|_| "encrypt failed".to_string())?;
    out.extend_from_slice(&ct);
    // Audit V-S3: the KDF key and the plaintext (xprv bodies, scan
    // keys) must not linger in freed heap after seal.
    zeroize::Zeroize::zeroize(&mut key);
    zeroize::Zeroize::zeroize(&mut pt);
    Ok(out)
}

/// Open a vault blob with `passphrase` — wrong passphrase or tampered
/// ciphertext is an AEAD failure, not a wrong-password guess.
///
/// # Errors
/// Bad magic, truncated blob, KDF or AEAD failure.
pub fn vault_open(bytes: &[u8], passphrase: &str) -> Result<VaultContents, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    let hdr = 8 + 12 + 32 + 12; // magic + params + salt + nonce
    if bytes.len() < hdr || &bytes[..8] != VAULT_MAGIC {
        return Err("not an avila signer vault".into());
    }
    let param_u32 = |r: &[u8]| -> Result<u32, String> {
        r.try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| "vault header truncated".to_string())
    };
    let m = param_u32(&bytes[8..12])?;
    let t = param_u32(&bytes[12..16])?;
    let p = param_u32(&bytes[16..20])?;
    // Audit V-S2: header fields are file-controlled and feed the KDF
    // directly — bound them before argon2 sees them (an unbounded
    // m_cost is a memory DoS on open) and authenticate them as AEAD
    // AAD so tampering fails the tag check, not just the bounds check.
    const MAX_M_KIB: u32 = 1 << 20; // 1 GiB — far above our 64 MiB seal
    const MAX_T: u32 = 64;
    const MAX_P: u32 = 16;
    if m == 0 || m > MAX_M_KIB || t == 0 || t > MAX_T || p == 0 || p > MAX_P {
        return Err("vault argon2 params out of bounds".into());
    }
    let salt = &bytes[20..52];
    let nonce = &bytes[52..64];
    let ct = &bytes[64..];
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(m, t, p, Some(32))
            .map_err(|e| format!("vault argon2 params unreasonable: {e}"))?,
    );
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2: {e}"))?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
    let pt = cipher
        .decrypt(
            nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: ct,
                // Whole header is AAD — params/salt/nonce are bound.
                aad: &bytes[..hdr],
            },
        )
        .map_err(|_| "vault open failed — wrong passphrase or corrupt vault".to_string())?;
    /// Byte cursor over the decrypted plaintext — every read bounds-
    /// checked; a truncated vault is an error, not a panic.
    struct Cursor<'a> {
        buf: &'a [u8],
        at: usize,
    }
    impl Cursor<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8], String> {
            if self.at + n > self.buf.len() {
                return Err("vault plaintext truncated".into());
            }
            let r = &self.buf[self.at..self.at + n];
            self.at += n;
            Ok(r)
        }
        fn take_u32(&mut self) -> Result<usize, String> {
            self.take(4)?
                .try_into()
                .map(u32::from_le_bytes)
                .map(|v| v as usize)
                .map_err(|_| "vault plaintext truncated".to_string())
        }
        fn read_strs(&mut self) -> Result<Vec<String>, String> {
            let n = self.take_u32()?;
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let dl = self.take_u32()?;
                out.push(
                    String::from_utf8(self.take(dl)?.to_vec())
                        .map_err(|_| "bad desc".to_string())?,
                );
            }
            Ok(out)
        }
    }
    let mut pt = pt;
    let mut cur = Cursor { buf: &pt, at: 0 };
    let plen = cur.take(1)?[0] as usize;
    let provenance =
        String::from_utf8(cur.take(plen)?.to_vec()).map_err(|_| "bad provenance".to_string())?;
    let clen = cur.take(1)?[0] as usize;
    let entropy_commitment =
        String::from_utf8(cur.take(clen)?.to_vec()).map_err(|_| "bad commitment".to_string())?;
    let descs_private = cur.read_strs()?;
    let descs_watch = cur.read_strs()?;
    // V-S1 tail (optional for pre-V-S1 vaults): BIP352 scan keys —
    // count, then per watch scan(32) || spend(33) || labels.
    let mut silents = Vec::new();
    if cur.at < cur.buf.len() {
        let n = cur.take_u32()?;
        for _ in 0..n {
            let scan: [u8; 32] = cur
                .take(32)?
                .try_into()
                .map_err(|_| "bad scan key".to_string())?;
            let spend: [u8; 33] = cur
                .take(33)?
                .try_into()
                .map_err(|_| "bad spend key".to_string())?;
            let ln = cur.take_u32()?;
            let mut labels = Vec::with_capacity(ln);
            for _ in 0..ln {
                labels.push(cur.take_u32()? as u32);
            }
            silents.push((scan, spend, labels));
        }
    }
    // Audit V-S3: key material and the decrypted blob are erased
    // before the parsed contents leave — the plaintext Vec's heap
    // pages don't survive as recoverable free-list data.
    zeroize::Zeroize::zeroize(&mut key);
    zeroize::Zeroize::zeroize(&mut pt);
    Ok(VaultContents {
        descs_private,
        descs_watch,
        provenance,
        entropy_commitment,
        silents,
    })
}

/// Opt-in signing material (queue #35): populated ONLY by
/// `createdescriptorseed`/key import — the wallet stays watch-only
/// (Core's `disable_private_keys` model) until the operator asks for
/// a signer. Secrets are memory-resident ONLY: `watchlist.dat` never
/// carries key material — a restart loses them until the encrypted
/// vault lands; the operator's descriptor backup is the recovery.
pub struct SignerState {
    /// The signing provider — secrets + xprvs + expansion outputs.
    pub provider: avila_consensus::descriptor::FlatProvider,
    /// Private-material descriptor bodies — only surfaced by
    /// explicitly-private RPCs, never logged.
    pub descs_private: Vec<String>,
    /// Neutered watch descriptors (public — safe in any file).
    pub descs_watch: Vec<String>,
    /// Seed entropy provenance: "os" (system CSPRNG), "user",
    /// "dice", or "mixed:…" when OS entropy was XOR-folded in.
    pub provenance: String,
    /// `sha256(raw entropy input)` — commit-before-generate: the
    /// record exists before derivation, so the seed's origin is
    /// checkable rather than asserted (queue #37).
    pub entropy_commitment: String,
}

/// The wallet — persistent across restarts via `watchlist.dat`.
pub struct WatchWallet {
    /// `watchlist.dat` path — writes are atomic (tmp + rename).
    path: PathBuf,
    /// Imported descriptors in import order.
    pub descs: Vec<TrackedDesc>,
    /// scriptPubKey bytes → `(desc index, derivation position)` — the
    /// merged lookup the block scan uses.
    pub scripts: HashMap<Vec<u8>, (usize, u32)>,
    /// Chain-owned coins keyed by outpoint — includes spent ones.
    pub coins: BTreeMap<(Txid, u32), WatchedCoin>,
    /// The block hash scanned at each height — `chain[h]` parallels
    /// `cs.chain()[h]`; divergence means reorg.
    pub chain: Vec<BlockHash>,
    /// Heights skipped because the body was unavailable (pruned or
    /// not yet stored). An unsearched interval must never masquerade
    /// as an empty balance — `getbalances` surfaces these.
    pub gaps: Vec<(u32, u32)>,
    /// Blocks below this height are asserted empty — set by the first
    /// import's timestamp (or the tip for `"now"`). Lazy `advance`
    /// marks them scanned without searching, matching Core's "don't
    /// search before the earliest descriptor timestamp". An explicit
    /// `rescanblockchain` still searches the full requested range.
    pub scan_floor: u32,
    /// BIP352 silent-payments watches — detected alongside descriptor
    /// scripts; the coin's script is the tweaked taproot output.
    pub silents: Vec<avila_consensus::silent::SilentAddress>,
    /// Public halves of silent watches whose scan keys aren't in
    /// memory (watchlist stubs after V-S1) — (spend_pub, labels).
    /// `track_silent`/vault load reactivates a matching stub with its
    /// labels intact instead of starting label-less.
    pending_silents: Vec<([u8; 33], Vec<u32>)>,
    /// Opt-in signer (queue #35) — `None` until the operator creates
    /// or imports key material; memory-only, never persisted.
    pub signer: Option<SignerState>,
    /// Queue #39 boundary — keys live in the spawned `avila signer`
    /// subprocess; this handle is the pipe to it.
    pub boundary: Option<crate::signerproc::SignerProc>,
    /// Dirty flag — set by any mutation, cleared by [`Self::persist`].
    dirty: bool,
}

impl WatchWallet {
    /// Opens (or lazily creates) the wallet at `path`. Corrupt or
    /// incompatible files are treated like a missing one — the wallet
    /// is reconstructible metadata, never the only copy of anything.
    #[must_use]
    pub fn open(path: PathBuf) -> Self {
        let mut w = Self {
            path,
            descs: Vec::new(),
            scripts: HashMap::new(),
            coins: BTreeMap::new(),
            chain: Vec::new(),
            gaps: Vec::new(),
            scan_floor: 0,
            silents: Vec::new(),
            pending_silents: Vec::new(),
            signer: None,
            boundary: None,
            dirty: false,
        };
        if let Ok(text) = std::fs::read_to_string(&w.path) {
            let _ = w.load(&text);
        }
        w
    }

    /// Rewinds to the fork point (if any), then scans forward to the
    /// active tip. Returns `true` when the scan state changed.
    pub fn advance(&mut self, cs: &Chainstate) -> bool {
        let chain = cs.chain();
        let fork = self
            .chain
            .iter()
            .zip(chain.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| self.chain.len().min(chain.len()));
        let fork = fork as u32;
        if (fork as usize) < self.chain.len() {
            // Blocks above the fork are gone — drop coins they
            // created and un-mark coins they spent.
            self.coins.retain(|_, c| c.height < fork);
            for c in self.coins.values_mut() {
                if c.spent_height.is_some_and(|s| s >= fork) {
                    c.spent_height = None;
                    c.spent_by = None;
                }
            }
            self.gaps.retain(|(lo, _)| *lo < fork);
            self.chain.truncate(fork as usize);
            self.dirty = true;
        }
        for (h, &hash) in chain.iter().enumerate().skip(self.chain.len()) {
            if (h as u32) < self.scan_floor {
                // Below the import floor — asserted empty, not a gap.
                self.chain.push(hash);
                continue;
            }
            match cs.body(&hash) {
                Some(block) => {
                    self.scan_block(cs, &block, h as u32, hash);
                }
                None => {
                    // Body missing (pruned) — record the gap rather
                    // than silently counting it as scanned.
                    self.gaps.push((h as u32, h as u32));
                    self.merge_gaps();
                }
            }
            self.chain.push(hash);
            self.dirty = true;
        }
        self.dirty
    }

    /// Scan a single gap block that reacquisition fetched — records
    /// the txs and drops `height` from `gaps`. `hash` was captured
    /// when the gap opened; a reorg between then and the body's
    /// arrival can orphan it, and scanning an orphaned block would
    /// record its coins as confirmed while the active chain's real
    /// block at `height` never gets scanned. So `hash` must still be
    /// the active chain's block at `height` — otherwise the gap is
    /// left in place (to retry once a current hash is captured) and
    /// this returns `false` without touching wallet state. Returns
    /// `true` when the gap closed.
    pub fn scan_gap_height(
        &mut self,
        cs: &Chainstate,
        block: &avila_consensus::block::Block,
        height: u32,
        hash: BlockHash,
    ) -> bool {
        if cs.chain().get(height as usize) != Some(&hash) {
            return false;
        }
        self.scan_block(cs, block, height, hash);
        self.gaps
            .retain(|(lo, hi)| !(height >= *lo && height <= *hi));
        self.dirty = true;
        true
    }

    /// Heights still uncovered by any scan — the pending-refetch list.
    #[must_use]
    pub fn missing_heights(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (lo, hi) in &self.gaps {
            out.extend(*lo..=*hi);
        }
        out
    }

    /// `ScanForWalletTransactions` over one connected block — record
    /// outputs paying tracked scripts, then mark spends of ours.
    fn scan_block(
        &mut self,
        cs: &Chainstate,
        block: &avila_consensus::block::Block,
        height: u32,
        hash: BlockHash,
    ) {
        // Same-block prevout map — a tx later in the block can spend
        // an earlier tx's output (not yet in the UTXO set).
        let mut intra: HashMap<OutPoint, Vec<u8>> = HashMap::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if let Some(&(desc_idx, _)) = self.scripts.get(out.script_pubkey.as_bytes()) {
                    self.coins.insert(
                        (txid, vout as u32),
                        WatchedCoin {
                            height,
                            block: hash,
                            value: out.value,
                            script: out.script_pubkey.as_bytes().to_vec(),
                            desc_idx,
                            coinbase: tx.is_coinbase(),
                            spent_height: None,
                            spent_by: None,
                        },
                    );
                }
            }
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                let op = input.previous_output;
                if let Some(coin) = self.coins.get_mut(&(op.txid, op.vout)) {
                    coin.spent_height = Some(height);
                    coin.spent_by = Some(txid);
                }
            }
            // BIP352 silent payments — every watched (scan_priv,
            // spend_pub) pair tries the tx; a match records the
            // tweaked taproot output like any tracked coin.
            if !self.silents.is_empty() && !tx.is_coinbase() {
                for (vout, out) in tx.outputs.iter().enumerate() {
                    intra.insert(
                        OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        out.script_pubkey.as_bytes().to_vec(),
                    );
                }
                let resolve = |op: &OutPoint| -> Option<Vec<u8>> {
                    intra.get(op).cloned().or_else(|| {
                        cs.utxo()
                            .get(op)
                            .map(|c| c.out.script_pubkey.as_bytes().to_vec())
                    })
                };
                for si in 0..self.silents.len() {
                    for hit in avila_consensus::silent::detect_silent_payment(
                        tx,
                        &self.silents[si],
                        resolve,
                    ) {
                        let vout = hit.vout;
                        let out = &tx.outputs[vout as usize];
                        self.coins.insert(
                            (txid, vout),
                            WatchedCoin {
                                height,
                                block: hash,
                                value: out.value,
                                script: out.script_pubkey.as_bytes().to_vec(),
                                // Silent watches aren't descriptors —
                                // usize::MAX marks the provenance.
                                desc_idx: usize::MAX,
                                coinbase: false,
                                spent_height: None,
                                spent_by: None,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Registers a BIP352 silent-payments watch — detection secrets
    /// only; the spend half stays unspendable here. If the watchlist
    /// left a public stub for this spend key (V-S1), its labels carry
    /// over — the vault-restored key picks the watch back up whole.
    pub fn track_silent(&mut self, mut addr: avila_consensus::silent::SilentAddress) {
        if let Some(i) = self
            .pending_silents
            .iter()
            .position(|(b, _)| *b == addr.spend_pub)
        {
            let (_, labels) = self.pending_silents.remove(i);
            for m in labels {
                if !addr.labels.contains(&m) {
                    addr.labels.push(m);
                }
            }
        }
        self.silents.push(addr);
        self.dirty = true;
    }

    /// `importdescriptors` — register a descriptor's script set. The
    /// caller decides the rescan height from `timestamp` and calls
    /// [`Self::rescan_from`] when a historical scan is needed.
    ///
    /// # Errors
    /// `io` only on expansion exhaustion; descriptor validation is the
    /// caller's job (`parse_descriptors`).
    pub fn track(&mut self, desc: TrackedDesc, floor: u32) {
        let idx = self.descs.len();
        if self.descs.is_empty() || floor < self.scan_floor {
            self.scan_floor = floor;
        }
        // First descriptor to claim a script wins the `desc`/
        // `parent_descs` reporting slot (Core attributes a coin to
        // every matching descriptor; we report the canonical one).
        for (script, pos) in &desc.scripts {
            self.scripts.entry(script.clone()).or_insert((idx, *pos));
        }
        self.descs.push(desc);
        self.dirty = true;
    }

    /// Issue the next receive/change index for `descs[i]` and mark the
    /// wallet dirty — audit SP-F5: a bare `next_index += 1` never
    /// persisted, so a crash between issue and the next unrelated
    /// persist re-issued the same address. Returns the issued index,
    /// or `None` when the descriptor's range is exhausted.
    pub fn bump_next_index(&mut self, i: usize) -> Option<u32> {
        let d = self.descs.get_mut(i)?;
        if d.next_index > d.range.1 {
            return None;
        }
        let issued = d.next_index;
        d.next_index += 1;
        self.dirty = true;
        Some(issued)
    }

    /// Installs the opt-in signer — the wallet remains watch-only in
    /// every other respect; this just means `walletprocesspsbt` has
    /// keys to reach for.
    pub fn enable_signing(&mut self, signer: SignerState) {
        self.signer = Some(signer);
    }

    /// Drop the signer — `signerlock`; secrets leave memory with the
    /// state (the vault holds the recoverable form). The boundary
    /// child exits with it.
    pub fn disable_signing(&mut self) {
        self.signer = None;
        if let Some(mut b) = self.boundary.take() {
            b.lock();
        }
    }

    /// Install the subprocess boundary — signing routes through it.
    pub fn set_boundary(&mut self, proc: crate::signerproc::SignerProc) {
        self.boundary = Some(proc);
    }

    /// The boundary pipe, if the signer is out-of-process.
    pub fn boundary_mut(&mut self) -> Option<&mut crate::signerproc::SignerProc> {
        self.boundary.as_mut()
    }

    /// Whether the wallet holds signing keys (opt-in signer active).
    #[must_use]
    pub fn is_signer(&self) -> bool {
        self.signer.is_some()
    }

    /// The signer's provider, when installed — callers use it to sign.
    #[must_use]
    pub fn signer(&self) -> Option<&SignerState> {
        self.signer.as_ref()
    }

    /// Rewind the scan to `height` (exclusive of it — blocks at
    /// `height` are rescanned) then advance to the tip. Existing
    /// descriptor scripts survive the rewind, so coins found below
    /// are re-found identically.
    pub fn rescan_from(&mut self, cs: &Chainstate, height: u32) {
        self.scan_floor = 0;
        self.chain.truncate(height as usize);
        self.coins.retain(|_, c| c.height < height);
        for c in self.coins.values_mut() {
            if c.spent_height.is_some_and(|s| s >= height) {
                c.spent_height = None;
                c.spent_by = None;
            }
        }
        self.gaps.retain(|(lo, _)| *lo < height);
        self.advance(cs);
    }

    /// The first chain height whose block time is `>= timestamp`
    /// (Core's `FindWalletRescanHeight` — binary search over header
    /// times, scanning from genesis when `timestamp` predates it).
    #[must_use]
    pub fn rescan_height_for(cs: &Chainstate, timestamp: i64) -> u32 {
        let chain = cs.chain();
        let mut lo = 0usize;
        let mut hi = chain.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let t = cs
                .tree()
                .get(&chain[mid])
                .map(|n| i64::from(n.header.time))
                .unwrap_or(i64::MAX);
            if t >= timestamp {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo as u32
    }

    /// Merge adjacent gap records — `(a,b] ∪ (b,c]` → `(a,c]`.
    fn merge_gaps(&mut self) {
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.gaps.len());
        for &(lo, hi) in &self.gaps {
            match merged.last_mut() {
                Some((_, prev_hi)) if *prev_hi + 1 >= lo => *prev_hi = hi,
                _ => merged.push((lo, hi)),
            }
        }
        self.gaps = merged;
    }

    /// Unspent chain coins as of the last [`Self::advance`].
    pub fn unspent(&self) -> impl Iterator<Item = (OutPoint, &WatchedCoin)> {
        self.coins
            .iter()
            .filter(|(_, c)| c.spent_height.is_none())
            .map(|(&(txid, vout), c)| (OutPoint { txid, vout }, c))
    }

    /// The vault's path — sibling of `watchlist.dat`, same dir.
    #[must_use]
    pub fn vault_path(&self) -> PathBuf {
        self.path.with_file_name("signervault.dat")
    }

    /// Persists when dirty — `watchlist.dat` via tmp+rename like the
    /// other node data files.
    ///
    /// # Errors
    /// `io` on write/rename failure.
    pub fn persist(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let text = self.dump();
        let tmp = self.path.with_extension("dat.tmp");
        // Audit V-S4/V-S5: the watchlist names everything the wallet
        // watches — 0600 from creation, fsynced before the rename, and
        // the directory fsynced so the rename itself is durable.
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent()
            && let Ok(d) = std::fs::File::open(dir)
        {
            let _ = d.sync_all();
        }
        self.dirty = false;
        Ok(())
    }

    /// `backupwallet` — flush, then copy the wallet file to `dest`.
    /// A bare filename resolves against the wallet's directory like
    /// Core resolves it against `-walletdir`.
    ///
    /// # Errors
    /// `io` on persist/copy failure.
    pub fn backup_to(&mut self, dest: &std::path::Path) -> io::Result<PathBuf> {
        self.persist()?;
        // The file may not exist yet when nothing was ever written —
        // persist() only runs when dirty, so materialize it first.
        if !self.path.exists() {
            let text = self.dump();
            std::fs::write(&self.path, text)?;
        }
        let target = if dest.is_absolute() {
            dest.to_path_buf()
        } else {
            self.path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(dest)
        };
        std::fs::copy(&self.path, &target)?;
        Ok(target)
    }

    /// `restorewallet` — load a backup file into this wallet. A bare
    /// filename resolves against the wallet's directory; malformed
    /// backups are rejected without touching live state.
    ///
    /// # Errors
    /// `io` on read/write failure; `InvalidData` when the file isn't
    /// a wallet backup.
    pub fn restore_from(&mut self, src: &std::path::Path) -> io::Result<()> {
        let target = if src.is_absolute() {
            src.to_path_buf()
        } else {
            self.path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(src)
        };
        let text = std::fs::read_to_string(&target)?;
        // Validate into a scratch wallet first — a corrupt backup must
        // not tear down the live descriptor/coin state.
        let mut scratch = Self {
            path: self.path.clone(),
            descs: Vec::new(),
            scripts: HashMap::new(),
            coins: BTreeMap::new(),
            chain: Vec::new(),
            gaps: Vec::new(),
            scan_floor: 0,
            silents: Vec::new(),
            pending_silents: Vec::new(),
            signer: None,
            boundary: None,
            dirty: false,
        };
        scratch
            .load(&text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a wallet backup"))?;
        let restored = Self {
            path: self.path.clone(),
            dirty: true,
            ..scratch
        };
        *self = restored;
        self.persist()
    }

    /// JSON serialization — plain fields, hex for hashes/scripts.
    fn dump(&self) -> String {
        let descs: Vec<serde_json::Value> = self
            .descs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "desc": d.desc,
                    "timestamp": d.timestamp,
                    "active": d.active,
                    "internal": d.internal,
                    "label": d.label,
                    "next_index": d.next_index,
                    "range": [d.range.0, d.range.1],
                    "scripts": d
                        .scripts
                        .iter()
                        .map(|(s, p)| serde_json::json!([hex::encode(s), p]))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let coins: Vec<serde_json::Value> = self
            .coins
            .iter()
            .map(|((txid, vout), c)| {
                serde_json::json!({
                    "txid": txid.to_string(),
                    "vout": vout,
                    "height": c.height,
                    "block": c.block.to_string(),
                    "value": c.value,
                    "script": hex::encode(&c.script),
                    "desc": c.desc_idx,
                    "coinbase": c.coinbase,
                    "spent": c.spent_height,
                    "spent_by": c.spent_by.map(|t| t.to_string()),
                })
            })
            .collect();
        serde_json::json!({
            "version": 1,
            "descs": descs,
            "coins": coins,
            // Audit V-S1: the scan PRIVATE key is secret — it lives
            // in the vault, never in this file. Only the public parts
            // (spend_pub + labels) persist so the watch survives as a
            // stub until the vault's key reactivates it.
            "silents": self
                .silents
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "spend": hex::encode(&a.spend_pub),
                        "labels": a.labels,
                    })
                })
                .collect::<Vec<_>>(),
            "chain": self.chain.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "gaps": self.gaps,
            "scan_floor": self.scan_floor,
        })
        .to_string()
    }

    /// Loads a `dump` document. Any malformed entry aborts the load —
    /// the caller treats that as an empty wallet (the descriptors can
    /// always be re-imported).
    fn load(&mut self, text: &str) -> Result<(), ()> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
        if v["version"].as_i64() != Some(1) {
            return Err(());
        }
        let hex_bytes =
            |v: &serde_json::Value| -> Option<Vec<u8>> { hex::decode(v.as_str()?).ok() };
        // Audit R-load: a damaged or hostile file must never panic or
        // balloon memory. Every array index is bounds-checked via
        // `get`, and section counts are capped relative to the file's
        // own size (each serialized entry costs dozens of bytes, so a
        // count that big can't be legitimately present).
        let descs = v["descs"].as_array().ok_or(())?;
        if descs.len() * 16 > text.len() {
            return Err(());
        }
        for d in descs {
            let raw_scripts = d["scripts"].as_array().ok_or(())?;
            if raw_scripts.len() * 36 > text.len() {
                return Err(());
            }
            let scripts: HashMap<Vec<u8>, u32> = raw_scripts
                .iter()
                .filter_map(|pair| {
                    let arr = pair.as_array()?;
                    Some((hex_bytes(arr.first()?)?, arr.get(1)?.as_u64()? as u32))
                })
                .collect();
            let range = d["range"].as_array().ok_or(())?;
            let (r0, r1) = (
                range.first().and_then(|x| x.as_u64()).ok_or(())?,
                range.get(1).and_then(|x| x.as_u64()).ok_or(())?,
            );
            let td = TrackedDesc {
                desc: d["desc"].as_str().ok_or(())?.to_string(),
                timestamp: d["timestamp"].as_i64().ok_or(())?,
                active: d["active"].as_bool().unwrap_or(false),
                internal: d["internal"].as_bool().unwrap_or(false),
                label: d["label"].as_str().unwrap_or_default().to_string(),
                next_index: d["next_index"].as_u64().unwrap_or(0) as u32,
                range: (r0 as u32, r1 as u32),
                scripts,
            };
            let idx = self.descs.len();
            for (s, pos) in &td.scripts {
                self.scripts.entry(s.clone()).or_insert((idx, *pos));
            }
            self.descs.push(td);
        }
        // Silent-payments watches — absent on pre-BIP352 dumps. New
        // dumps carry only the public half (V-S1): such an entry goes
        // to `pending_silents` until the vault's scan key reactivates
        // it; a legacy entry still carrying `scan` is honored once —
        // the next persist strips it.
        let silents_arr = v["silents"].as_array().map_or(&[][..], Vec::as_slice);
        if silents_arr.len() * 66 > text.len() {
            return Err(());
        }
        for a in silents_arr {
            let Some(spend) = hex_bytes(&a["spend"]) else {
                continue;
            };
            if spend.len() != 33 {
                continue;
            }
            let mut bp = [0u8; 33];
            bp.copy_from_slice(&spend);
            let labels = a["labels"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(serde_json::Value::as_u64)
                        .map(|m| m as u32)
                        .collect()
                })
                .unwrap_or_default();
            match hex_bytes(&a["scan"]) {
                Some(scan) if scan.len() == 32 => {
                    let mut sp = [0u8; 32];
                    sp.copy_from_slice(&scan);
                    self.silents.push(avila_consensus::silent::SilentAddress {
                        scan_priv: sp,
                        spend_pub: bp,
                        labels,
                    });
                }
                _ => self.pending_silents.push((bp, labels)),
            }
        }
        let coins = v["coins"].as_array().ok_or(())?;
        if coins.len() * 64 > text.len() {
            return Err(());
        }
        for c in coins {
            let txid: Txid = c["txid"].as_str().ok_or(())?.parse().map_err(|_| ())?;
            let vout = c["vout"].as_u64().ok_or(())? as u32;
            let block: BlockHash = c["block"].as_str().ok_or(())?.parse().map_err(|_| ())?;
            let spent_by = c["spent_by"].as_str().and_then(|s| s.parse::<Txid>().ok());
            self.coins.insert(
                (txid, vout),
                WatchedCoin {
                    height: c["height"].as_u64().ok_or(())? as u32,
                    block,
                    value: c["value"].as_i64().ok_or(())?,
                    script: hex_bytes(&c["script"]).ok_or(())?,
                    desc_idx: c["desc"].as_u64().unwrap_or(0) as usize,
                    coinbase: c["coinbase"].as_bool().unwrap_or(false),
                    spent_height: c["spent"].as_u64().map(|h| h as u32),
                    spent_by,
                },
            );
        }
        let chain_arr = v["chain"].as_array().ok_or(())?;
        if chain_arr.len() * 64 > text.len() {
            return Err(());
        }
        for h in chain_arr {
            self.chain
                .push(h.as_str().ok_or(())?.parse().map_err(|_| ())?);
        }
        self.scan_floor = v["scan_floor"].as_u64().unwrap_or(0) as u32;
        let gaps_arr: &[serde_json::Value] = v["gaps"].as_array().map_or(&[][..], Vec::as_slice);
        if gaps_arr.len() * 8 > text.len() {
            return Err(());
        }
        for g in gaps_arr {
            let arr = g.as_array().ok_or(())?;
            self.gaps.push((
                arr.first().and_then(|x| x.as_u64()).ok_or(())? as u32,
                arr.get(1).and_then(|x| x.as_u64()).ok_or(())? as u32,
            ));
        }
        Ok(())
    }
}

/// `SharedWallet` — the wallet lives behind the RPC layer's lock;
/// every wallet method runs inside a `chain_query` closure so the
/// scan and the chainstate advance atomically.
pub type SharedWallet = std::sync::Arc<std::sync::Mutex<WatchWallet>>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::block::Block;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::Network;
    use avila_consensus::pow;
    use avila_consensus::script;
    use avila_consensus::transaction::{Script, Transaction, TxIn, TxOut, Witness};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: u32 = 1_800_000_000;
    /// The watched script — `OP_1` bare, matching the coinbases below.
    const WATCHED: &[u8] = &[script::OP_1];

    fn coinbase_tx(height: u32, subsidy: i64) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: subsidy,
                script_pubkey: Script::new(WATCHED.to_vec()),
            }],
            lock_time: 0,
        }
    }

    fn block_on(
        parent: &BlockHeader,
        txs: Vec<Transaction>,
        params: &avila_consensus::params::Params,
    ) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: avila_consensus::arith::CompactTarget(REGTEST_BITS),
                nonce: 0,
            },
            transactions: txs,
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    fn tracked(script: &[u8]) -> TrackedDesc {
        TrackedDesc {
            desc: "raw(51)#x".into(),
            timestamp: 0,
            active: false,
            internal: false,
            label: String::new(),
            next_index: 0,
            range: (0, 0),
            scripts: HashMap::from([(script.to_vec(), 0)]),
        }
    }

    fn chain_of(n: u32) -> Chainstate {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        let mut parent = params.genesis_header;
        for height in 1..=n {
            let block = block_on(
                &parent,
                vec![coinbase_tx(height, 50 * 100_000_000)],
                &params,
            );
            parent = block.header;
            assert!(cs.accept_block(&block, NOW).is_ok());
        }
        cs
    }

    #[test]
    fn advance_records_and_spends() {
        // 105 blocks so the h3 coinbase is mature when h106 spends it.
        let mut cs = chain_of(105);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 105);
        // Spend the height-3 coinbase in a new block — watched output
        // must drop out of `unspent`.
        let coin3_txid = cs.body(&cs.chain()[3]).unwrap().transactions[0].txid();
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: coin3_txid,
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_fffe,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![0x52]),
            }],
            lock_time: 0,
        };
        let params = Network::Regtest.params();
        let parent = cs.tip_hash();
        let tip_hdr = cs.tree().get(&parent).unwrap().header;
        let b6 = block_on(
            &tip_hdr,
            vec![coinbase_tx(106, 50 * 100_000_000), spend],
            &params,
        );
        cs.accept_block(&b6, NOW).unwrap();
        w.advance(&cs);
        let unspent: Vec<_> = w.unspent().collect();
        assert_eq!(unspent.len(), 105); // all coinbases except h3's
        assert!(unspent.iter().all(|(op, _)| op.txid != coin3_txid));
        // Spent coin is retained with a spent_height for
        // `listreceivedbyaddress`.
        let spent = &w.coins[&(coin3_txid, 0)];
        assert_eq!(spent.spent_height, Some(106));
    }

    #[test]
    fn scan_floor_suppresses_pre_import_history() {
        let cs = chain_of(5);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        // "now" at tip — floor = 5: blocks 1..4 are asserted empty.
        w.track(tracked(WATCHED), 5);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 1); // only height-5's coinbase
        // Explicit rescan bypasses the floor, like Core.
        w.rescan_from(&cs, 0);
        assert_eq!(w.unspent().count(), 5);
    }

    #[test]
    fn reorg_drops_orphans_and_unspends() {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        let mut parent = params.genesis_header;
        for height in 1..=4u32 {
            let b = block_on(
                &parent,
                vec![coinbase_tx(height, 50 * 100_000_000)],
                &params,
            );
            parent = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);

        // Fork at height 2: two side blocks with different coinbases
        // (tagged scriptSig → different txids/hashes).
        let fork_hdr = cs.tree().get(&cs.chain()[1]).unwrap().header;
        let mut side_parent = fork_hdr;
        for height in 2..=5u32 {
            let mut cb = coinbase_tx(height, 50 * 100_000_000);
            let mut sig = cb.inputs[0].script_sig.as_bytes().to_vec();
            sig.push(0xaa);
            cb.inputs[0].script_sig = Script::new(sig);
            let b = block_on(&side_parent, vec![cb], &params);
            side_parent = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        assert_eq!(cs.chain().len(), 6); // reorged to the longer fork
        w.advance(&cs);
        // The main-chain coinbases at h2-4 are gone; the side chain's
        // replacements at h2-5 (still paying WATCHED) stand.
        assert_eq!(w.unspent().count(), 5); // h1 main + h2..5 side
    }

    #[test]
    fn reorg_unspends_orphaned_spends() {
        let params = Network::Regtest.params();
        // 104 blocks so h2's coinbase is mature when block 105 spends
        // it — the fork then orphans the spend.
        let mut cs = chain_of(104);
        let h2_txid = cs.body(&cs.chain()[2]).unwrap().transactions[0].txid();
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: h2_txid,
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_fffe,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![0x52]),
            }],
            lock_time: 0,
        };
        let tip_hdr = cs.tree().get(&cs.tip_hash()).unwrap().header;
        let b4 = block_on(
            &tip_hdr,
            vec![coinbase_tx(105, 50 * 100_000_000), spend],
            &params,
        );
        cs.accept_block(&b4, NOW).unwrap();
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.coins[&(h2_txid, 0)].spent_height, Some(105));

        // Reorg away block 105 — the spend unwinds.
        let fork_hdr = cs.tree().get(&cs.chain()[103]).unwrap().header;
        let mut side = fork_hdr;
        for height in 104..=107u32 {
            let mut cb = coinbase_tx(height, 50 * 100_000_000);
            let mut sig = cb.inputs[0].script_sig.as_bytes().to_vec();
            sig.push(0xbb);
            cb.inputs[0].script_sig = Script::new(sig);
            let b = block_on(&side, vec![cb], &params);
            side = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        w.advance(&cs);
        assert_eq!(w.coins[&(h2_txid, 0)].spent_height, None);
        assert!(w.unspent().any(|(op, _)| op.txid == h2_txid));
    }

    #[test]
    fn persistence_round_trip() {
        let dir = std::env::temp_dir().join(format!("avila-watch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("watchlist.dat");
        let cs = chain_of(4);
        {
            let mut w = WatchWallet::open(path.clone());
            w.track(tracked(WATCHED), 0);
            w.advance(&cs);
            w.persist().unwrap();
        }
        let mut w = WatchWallet::open(path);
        assert_eq!(w.descs.len(), 1);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn gap_reacquisition_rescans_arrived_bodies() {
        // A wallet scanned over pruned blocks records gaps; when the
        // bodies reacquire (getdata → accept_block), `scan_gap_height`
        // fills them and `missing_heights` shrinks to empty.
        let cs = chain_of(4);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);

        // Simulate a rescan that skipped blocks 1..=3 — wipe the coins
        // they made and mark the gap like `advance` does on missing
        // bodies.
        w.coins.retain(|_, c| c.height == 0 || c.height >= 4);
        w.gaps.push((1, 3));
        assert_eq!(w.missing_heights(), vec![1, 2, 3]);

        // The fetched blocks arrive — scan each gap height.
        for h in [1u32, 2, 3] {
            let hash = cs.chain()[h as usize];
            let body = cs.body(&hash).unwrap();
            w.scan_gap_height(&cs, &body, h, hash);
        }
        assert!(w.missing_heights().is_empty());
        // The refound coins match the original scan exactly.
        assert_eq!(w.unspent().count(), 4);
        assert!(w.coins.values().all(|c| c.spent_height.is_none()));
    }

    #[test]
    fn scan_gap_height_rejects_orphaned_capture() {
        // A gap's (height, hash) is captured when the body first goes
        // missing; if a reorg replaces that height before the body
        // reacquires, scanning the late-arriving (now orphaned) block
        // must neither record its coins as confirmed nor close the
        // gap — it has to be retried with the current hash.
        let params = Network::Regtest.params();
        let mut cs = chain_of(4);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);

        // Simulate the gap exactly like `gap_reacquisition_rescans_arrived_bodies`,
        // but capture the (about to be orphaned) hash and body first —
        // this is what a reacquisition request keys its getdata on.
        let orphan_hash = cs.chain()[2];
        let orphan_block = cs.body(&orphan_hash).unwrap();
        let orphan_txid = orphan_block.transactions[0].txid();
        w.coins.remove(&(orphan_txid, 0));
        w.gaps.push((2, 2));
        assert_eq!(w.missing_heights(), vec![2]);

        // Reorg away height 2 onward via a longer side chain from
        // height 1 — mirrors `reorg_drops_orphans_and_unspends`.
        let fork_hdr = cs.tree().get(&cs.chain()[1]).unwrap().header;
        let mut side = fork_hdr;
        for height in 2..=5u32 {
            let mut cb = coinbase_tx(height, 50 * 100_000_000);
            let mut sig = cb.inputs[0].script_sig.as_bytes().to_vec();
            sig.push(0xcc);
            cb.inputs[0].script_sig = Script::new(sig);
            let b = block_on(&side, vec![cb], &params);
            side = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        assert_ne!(cs.chain()[2], orphan_hash, "height 2 must have reorged");

        // The stale (height, hash) capture's body arrives late —
        // scan_gap_height must refuse it, not fold it in.
        let closed = w.scan_gap_height(&cs, &orphan_block, 2, orphan_hash);
        assert!(!closed, "an orphaned capture must not close the gap");
        assert_eq!(w.missing_heights(), vec![2], "the gap must be retried");
        assert!(
            !w.coins.contains_key(&(orphan_txid, 0)),
            "the orphaned block's coin must not be recorded as confirmed"
        );
    }

    /// Queue #37 — the entropy ceremony's provable surface: Coldcard-
    /// convention dice derivation (SHA256 over ASCII digits), the
    /// commit-before-generate record, and XOR mixing.
    #[test]
    fn resolve_entropy_dice_is_coldcard_compatible() {
        // 50 ones — the 128-bit floor. Seed = SHA256("111…1").
        let rolls = "1".repeat(50);
        let r = resolve_entropy(None, Some(&rolls), false).unwrap();
        assert_eq!(r.provenance, "dice");
        let expect_seed = avila_consensus::hash::sha256(rolls.as_bytes()).to_vec();
        assert_eq!(r.seed, expect_seed, "seed must be SHA256(rolls)");
        // Audit SEED-1: the commitment must be domain-separated —
        // sha256(tag || input), never sha256(input) = the seed itself.
        let naive = hex::encode(&avila_consensus::hash::sha256(rolls.as_bytes()));
        assert_ne!(
            r.commitment, naive,
            "commitment must not equal sha256(input) — that IS the seed"
        );
        let mut tagged = b"AVILA-ENTROPY-COMMIT-v1\x00".to_vec();
        tagged.extend_from_slice(rolls.as_bytes());
        assert_eq!(
            r.commitment,
            hex::encode(&avila_consensus::hash::sha256(&tagged))
        );
        assert!(r.warnings.iter().any(|w| w.contains("99")));
        // Skewed distribution warns — all-one faces is maximal skew.
        assert!(r.warnings.iter().any(|w| w.contains("skewed")));
    }

    #[test]
    fn resolve_entropy_rejects_and_mixes() {
        assert!(resolve_entropy(None, Some("111"), false).is_err()); // way under floor
        // Audit SEED-2: 10-49 rolls used to warn — now a hard reject.
        let forty_nine = "1".repeat(49);
        assert!(resolve_entropy(None, Some(&forty_nine), false).is_err());
        let fifty = "1".repeat(50);
        assert!(resolve_entropy(None, Some(&fifty), false).is_ok());
        assert!(resolve_entropy(None, Some("0000000000"), false).is_err()); // bad digits
        assert!(resolve_entropy(Some("abcd"), None, false).is_err()); // <16 bytes
        // Exactly-32 hex passes through raw; shorter folds via SHA256.
        let raw32 = "ab".repeat(32);
        let r = resolve_entropy(Some(&raw32), None, false).unwrap();
        assert_eq!(r.seed, hex::decode(&raw32).unwrap());
        assert_eq!(r.provenance, "user");
        let short = "ab".repeat(16);
        let r2 = resolve_entropy(Some(&short), None, false).unwrap();
        assert_eq!(
            r2.seed,
            avila_consensus::hash::sha256(&hex::decode(&short).unwrap()).to_vec()
        );
        // Mixing XOR-folds OS entropy — provenance says so, and the
        // seed differs from the unmixed derivation.
        let rolls = "123456".repeat(17); // 102 rolls
        let mixed = resolve_entropy(None, Some(&rolls), true).unwrap();
        assert_eq!(mixed.provenance, "mixed:os+dice");
        let plain = resolve_entropy(None, Some(&rolls), false).unwrap();
        assert_ne!(mixed.seed, plain.seed);
        // Commitment still binds to the user's input, not the OS half.
        assert_eq!(mixed.commitment, plain.commitment);
    }

    /// Queue #35 — the vault roundtrips its contents, rejects the
    /// wrong passphrase at the AEAD layer (no oracle), and rejects
    /// tampered ciphertext.
    #[test]
    fn vault_seal_open_roundtrips_and_rejects() {
        let signer = SignerState {
            provider: avila_consensus::descriptor::FlatProvider::default(),
            descs_private: vec!["wpkh(tprv8x/0/*)#testp".to_string()],
            descs_watch: vec!["wpkh(tpub8x/0/*)#testw".to_string()],
            provenance: "dice".to_string(),
            entropy_commitment: "abc123".to_string(),
        };
        let silents = vec![avila_consensus::silent::SilentAddress {
            scan_priv: [0x42; 32],
            spend_pub: [0x02; 33],
            labels: vec![0, 7],
        }];
        let blob = vault_seal(&signer, &silents, "correct horse").unwrap();
        assert!(blob.starts_with(b"AVLAVLT1"));
        let v = vault_open(&blob, "correct horse").unwrap();
        assert_eq!(v.descs_private, signer.descs_private);
        assert_eq!(v.descs_watch, signer.descs_watch);
        assert_eq!(v.provenance, "dice");
        assert_eq!(v.entropy_commitment, "abc123");
        // V-S1: scan keys ride inside the vault.
        assert_eq!(v.silents.len(), 1);
        assert_eq!(v.silents[0].0, [0x42; 32]);
        assert_eq!(v.silents[0].2, vec![0, 7]);
        // Wrong passphrase → AEAD failure, not a hint.
        assert!(vault_open(&blob, "wrong horse").is_err());
        // Tampered ciphertext → AEAD failure.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(vault_open(&bad, "correct horse").is_err());
        // V-S2: tampered header params are AAD-bound — a flipped byte
        // in m/t/p fails the tag, and absurd params are bounds-rejected
        // before argon2 ever runs.
        let mut badp = blob.clone();
        badp[8] ^= 0xff; // m_cost byte
        assert!(vault_open(&badp, "correct horse").is_err());
        let mut huge = blob.clone();
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(vault_open(&huge, "correct horse").is_err());
        // Truncated blob → error, not panic.
        assert!(vault_open(&blob[..40], "correct horse").is_err());
    }

    /// BIP39: the 24 words encode the entropy; parse+to_seed is
    /// deterministic — the mnemonic IS the backup.
    #[test]
    fn bip39_mnemonic_roundtrips_entropy() {
        let entropy = [7u8; 32];
        let m = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), 24);
        let words = m.to_string();
        let m2 = bip39::Mnemonic::parse_normalized(&words).unwrap();
        assert_eq!(m.to_seed(""), m2.to_seed(""));
        assert_eq!(m2.to_entropy(), entropy.to_vec());
    }
}
