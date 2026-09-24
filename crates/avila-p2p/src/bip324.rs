//! BIP324 v2 transport — Core's `bip324.cpp`/`crypto/chacha20*` port.
//!
//! The encrypted transport wraps the v1 message layer: instead of
//! `magic || command || length || checksum || payload` frames on the
//! wire, each message is one AEAD packet —
//! `enc_L(len) || enc_P(header || msgtype || payload)` — over an
//! ElligatorSwift ECDH handshake whose public keys are
//! indistinguishable from random bytes.
//!
//! Two ciphers do the work: [`FsChaCha20`] (a continuous keystream
//! for the 3-byte packet lengths, rekeyed from its own stream every
//! 224 chunks) and [`FsChaCha20Poly1305`] (per-packet AEAD, rekeyed
//! every 224 packets from a one-block keystream at nonce
//! `{0xFFFFFFFF, rekey_counter}`). Key material comes from
//! `CHKDF_HMAC_SHA256_L32` over `bitcoin_v2_shared_secret || magic`.

use avila_consensus::hash::sha256;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use secp256k1::SecretKey;
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};

/// `FSChaCha20Poly1305::REKEY_INTERVAL` — packets per key.
const REKEY_INTERVAL: u32 = 224;
/// `BIP324Cipher::LENGTH_LEN` — bytes in the encrypted length field.
pub const LENGTH_LEN: usize = 3;
/// `BIP324Cipher::HEADER_LEN` — the per-packet ignore-flag byte.
const HEADER_LEN: usize = 1;
/// AEAD tag size (`CHACHA20POLY1305_EXPANSION`).
const TAG_LEN: usize = 16;
/// `BIP324Cipher::EXPANSION` — wire bytes added per packet.
pub const EXPANSION: usize = LENGTH_LEN + HEADER_LEN + TAG_LEN;
/// `BIP324Cipher::GARBAGE_TERMINATOR_LEN`.
pub const GARBAGE_TERMINATOR_LEN: usize = 16;
/// `V2Transport::MAX_GARBAGE_LEN` — cap on handshake garbage.
pub const MAX_GARBAGE_LEN: usize = 4095;
/// `BIP324Cipher::ELLIGATOR_SWIFT_LEN` — 64-byte encoded pubkey.
pub const ELLIGATOR_SWIFT_LEN: usize = 64;
/// `BIP324Cipher::IGNORE_BIT` — the header bit marking decoy packets.
const IGNORE_BIT: u8 = 0x80;
/// `V2Transport::MAX_CONTENTS_LEN` — `0x00 + 12-byte type + payload`
/// bounded by `MAX_PROTOCOL_MESSAGE_LENGTH` (4 MiB).
const MAX_CONTENTS_LEN: usize = 1 + 12 + 4 * 1024 * 1024;

/// `ChaCha20::Nonce96` on the wire: `LE32(first) || LE64(second)`.
fn nonce96(first: u32, second: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&first.to_le_bytes());
    n[4..].copy_from_slice(&second.to_le_bytes());
    n.into()
}

/// HMAC-SHA256 (RFC 2104) — no `hmac` dependency in the tree, and the
/// primitive is 20 lines over sha256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// `CHKDF_HMAC_SHA256_L32`: `prk = HMAC(salt, ikm)`,
/// `expand32(info) = HMAC(prk, info || 0x01)` — a single 32-byte
/// HKDF round.
struct Hkdf32 {
    prk: [u8; 32],
}

impl Hkdf32 {
    fn new(ikm: &[u8], salt: &[u8]) -> Self {
        Self {
            prk: hmac_sha256(salt, ikm),
        }
    }
    fn expand32(&self, info: &str) -> [u8; 32] {
        self.expand_bytes(info.as_bytes())
    }

    fn expand_bytes(&self, info: &[u8]) -> [u8; 32] {
        let mut data = info.to_vec();
        data.push(1);
        hmac_sha256(&self.prk, &data)
    }
}

/// Core's `FSChaCha20` — a continuous ChaCha20 keystream that rekeys
/// itself every 224 `crypt` calls by pulling 32 stream bytes as the
/// next key, then seeking to nonce `{0, ++rekey_counter}` block 0.
pub struct FsChaCha20 {
    cipher: chacha20::ChaCha20,
    chunk_counter: u32,
    rekey_counter: u64,
}

impl FsChaCha20 {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: chacha20::ChaCha20::new(key.into(), &nonce96(0, 0)),
            chunk_counter: 0,
            rekey_counter: 0,
        }
    }

    /// XOR `data` with the keystream (encrypt and decrypt are the
    /// same operation), then apply the rekey rule.
    pub fn crypt(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
        self.chunk_counter += 1;
        if self.chunk_counter == REKEY_INTERVAL {
            let mut new_key = [0u8; 32];
            self.cipher.apply_keystream(&mut new_key);
            self.rekey_counter += 1;
            self.cipher = chacha20::ChaCha20::new(&new_key.into(), &nonce96(0, self.rekey_counter));
            self.chunk_counter = 0;
        }
    }
}

/// Core's `FSChaCha20Poly1305` — RFC8439 ChaCha20-Poly1305 at nonce
/// `{packet_counter, rekey_counter}`, rekeyed every 224 packets by
/// drawing a fresh key from one keystream block at nonce
/// `{0xFFFFFFFF, rekey_counter}` (block 1 onward — block 0 belongs to
/// the poly1305 key).
pub struct FsChaCha20Poly1305 {
    key: [u8; 32],
    aead: ChaCha20Poly1305,
    packet_counter: u32,
    rekey_counter: u64,
}

impl FsChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: *key,
            aead: ChaCha20Poly1305::new(key.into()),
            packet_counter: 0,
            rekey_counter: 0,
        }
    }

    fn next_packet(&mut self) {
        self.packet_counter += 1;
        if self.packet_counter == REKEY_INTERVAL {
            let mut block = [0u8; 64];
            let mut ks = chacha20::ChaCha20::new(
                (&self.key).into(),
                &nonce96(0xFFFF_FFFF, self.rekey_counter),
            );
            ks.seek(64); // block 1 — block 0 feeds the poly key
            ks.apply_keystream(&mut block);
            self.key.copy_from_slice(&block[..32]);
            self.aead = ChaCha20Poly1305::new((&self.key).into());
            self.packet_counter = 0;
            self.rekey_counter += 1;
        }
    }

    /// AEAD-encrypt `plain` with `aad`, appending the tag.
    pub fn encrypt(&mut self, plain: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = nonce96(self.packet_counter, self.rekey_counter);
        // The AEAD only fails above ~256 GiB of plaintext — packets
        // never approach that.
        let Ok(out) = self.aead.encrypt(&nonce, Payload { msg: plain, aad }) else {
            unreachable!("packet plaintext never nears the AEAD limit")
        };
        self.next_packet();
        out
    }

    /// Verify+decrypt a `cipher || tag` buffer. A bad tag still
    /// consumes a packet (Core's `Decrypt` calls `NextPacket`
    /// unconditionally — the counters must stay in sync).
    pub fn decrypt(&mut self, cipher: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let nonce = nonce96(self.packet_counter, self.rekey_counter);
        let out = self.aead.decrypt(&nonce, Payload { msg: cipher, aad }).ok();
        self.next_packet();
        out
    }
}

/// Core's `BIP324Cipher` — the post-handshake cipher state: four
/// ciphers (send/recv × length/packet), the two garbage terminators,
/// and the session id.
pub struct Bip324Cipher {
    send_l: FsChaCha20,
    recv_l: FsChaCha20,
    send_p: FsChaCha20Poly1305,
    recv_p: FsChaCha20Poly1305,
    /// `m_send_garbage_terminator` — what we send after our garbage.
    send_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    /// `m_recv_garbage_terminator` — what marks the end of *their*
    /// garbage.
    recv_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    /// `m_session_id` — the HKDF "session_id" output.
    pub session_id: [u8; 32],
}

/// Generate the `(secret_key, ellswift_pubkey)` pair —
/// `key.EllSwiftCreate(ent32)`. `ent32` is caller entropy folded into
/// the encoding; the secret key itself comes from the OS RNG.
pub fn keypair(ent32: [u8; 32]) -> std::io::Result<(SecretKey, ElligatorSwift)> {
    let secp = secp256k1::Secp256k1::new();
    loop {
        let mut sk_bytes = [0u8; 32];
        getrandom::fill(&mut sk_bytes)
            .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
        if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
            return Ok((sk, ElligatorSwift::from_seckey(&secp, sk, Some(ent32))));
        }
    }
}

impl Bip324Cipher {
    /// `BIP324Cipher::Initialize(their_pubkey, initiator, false)`.
    pub fn initialize(
        our_key: &SecretKey,
        our_ellswift: ElligatorSwift,
        their_ellswift: ElligatorSwift,
        initiator: bool,
        magic: [u8; 4],
    ) -> Self {
        let salt = {
            let mut s = b"bitcoin_v2_shared_secret".to_vec();
            s.extend_from_slice(&magic);
            s
        };
        // BIP324 ECDH: the initiator is always party A — remap
        // our/their into the a/b slots like `ComputeBIP324ECDHSecret`.
        let ecdh = ElligatorSwift::shared_secret(
            if initiator {
                our_ellswift
            } else {
                their_ellswift
            },
            if initiator {
                their_ellswift
            } else {
                our_ellswift
            },
            *our_key,
            if initiator {
                ElligatorSwiftParty::A
            } else {
                ElligatorSwiftParty::B
            },
            None,
        );
        let hkdf = Hkdf32::new(ecdh.as_secret_bytes(), &salt);
        let keys = |label: &str| hkdf.expand32(label);
        let (init_l, init_p, resp_l, resp_p) = (
            keys("initiator_L"),
            keys("initiator_P"),
            keys("responder_L"),
            keys("responder_P"),
        );
        let garbage_term = keys("garbage_terminators");
        let session_id = keys("session_id");
        let (send_l, recv_l, send_p, recv_p) = if initiator {
            (init_l, resp_l, init_p, resp_p)
        } else {
            (resp_l, init_l, resp_p, init_p)
        };
        let mut send_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
        let mut recv_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
        send_terminator.copy_from_slice(&garbage_term[..GARBAGE_TERMINATOR_LEN]);
        recv_terminator.copy_from_slice(&garbage_term[32 - GARBAGE_TERMINATOR_LEN..]);
        if !initiator {
            std::mem::swap(&mut send_terminator, &mut recv_terminator);
        }
        Self {
            send_l: FsChaCha20::new(&send_l),
            recv_l: FsChaCha20::new(&recv_l),
            send_p: FsChaCha20Poly1305::new(&send_p),
            recv_p: FsChaCha20Poly1305::new(&recv_p),
            send_terminator,
            recv_terminator,
            session_id,
        }
    }

    /// `GetSendGarbageTerminator`.
    pub fn send_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.send_terminator
    }
    /// `GetReceiveGarbageTerminator`.
    pub fn recv_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.recv_terminator
    }

    /// `BIP324Cipher::Encrypt(contents, aad, ignore)` →
    /// `enc_L(len) || enc_P(header || contents)`.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Vec<u8> {
        let mut len = [
            (contents.len() & 0xFF) as u8,
            ((contents.len() >> 8) & 0xFF) as u8,
            ((contents.len() >> 16) & 0xFF) as u8,
        ];
        self.send_l.crypt(&mut len);
        let mut plain = Vec::with_capacity(HEADER_LEN + contents.len());
        plain.push(if ignore { IGNORE_BIT } else { 0 });
        plain.extend_from_slice(contents);
        let ct = self.send_p.encrypt(&plain, aad);
        let mut out = Vec::with_capacity(contents.len() + EXPANSION);
        out.extend_from_slice(&len);
        out.extend_from_slice(&ct);
        out
    }

    /// `BIP324Cipher::DecryptLength` — the next packet's contents
    /// length.
    pub fn decrypt_length(&mut self, enc_len: &[u8]) -> u32 {
        debug_assert_eq!(enc_len.len(), LENGTH_LEN);
        let mut buf = [0u8; LENGTH_LEN];
        buf.copy_from_slice(&enc_len[..LENGTH_LEN]);
        self.recv_l.crypt(&mut buf);
        u32::from(buf[0]) | u32::from(buf[1]) << 8 | u32::from(buf[2]) << 16
    }

    /// `BIP324Cipher::Decrypt` — `(ignore, contents)` or `None` on a
    /// bad tag (the peer desynchronized — disconnect).
    pub fn decrypt_packet(&mut self, packet: &[u8], aad: &[u8]) -> Option<(bool, Vec<u8>)> {
        let plain = self.recv_p.decrypt(packet, aad)?;
        let ignore = plain[0] & IGNORE_BIT == IGNORE_BIT;
        Some((ignore, plain[HEADER_LEN..].to_vec()))
    }
}

/// The BIP324 v1→v2 message-type translation table —
/// Core's `V2_MESSAGE_IDS` / `V2_MESSAGE_MAP`.
const SHORT_IDS: [&str; 29] = [
    "", // 0 = escape: long form follows
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
];

/// `V2_MESSAGE_MAP` encode side: command name → contents prefix.
pub fn encode_message_type(command: &str) -> Vec<u8> {
    if let Some(id) = SHORT_IDS.iter().position(|&c| c == command)
        && id > 0
    {
        return vec![id as u8];
    }
    // Long form: 0x00 || 12-byte zero-padded ascii name.
    let mut out = Vec::with_capacity(13);
    out.push(0u8);
    let mut name = [0u8; 12];
    let bytes = command.as_bytes();
    name[..bytes.len().min(12)].copy_from_slice(&bytes[..bytes.len().min(12)]);
    out.extend_from_slice(&name);
    out
}

/// `V2Transport::GetMessageType` — strip the type prefix off packet
/// contents, leaving the payload.
pub fn decode_message_type(contents: &[u8]) -> Option<(String, &[u8])> {
    let (&first, rest) = contents.split_first()?;
    if first != 0 {
        return SHORT_IDS
            .get(first as usize)
            .filter(|_| first > 0)
            .map(|s| (s.to_string(), rest));
    }
    if rest.len() < 12 {
        return None;
    }
    let name_bytes = &rest[..12];
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    if name_bytes[..end]
        .iter()
        .any(|&b| !(0x20..=0x7f).contains(&b))
        || name_bytes[end..].iter().any(|&b| b != 0)
    {
        return None;
    }
    Some((
        String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
        &rest[12..],
    ))
}

/// Outcome of the ellswift exchange — the peer either presented a v2
/// key or opened with the v1 wire format (`ShouldReconnectV1` —
/// the caller drops and redials v1).
pub enum Handshake {
    /// Cipher state ready; the version packet still to exchange. The
    /// garbage we already sent becomes its AAD.
    V2(Box<Bip324Cipher>, Vec<u8>),
    /// The peer's first bytes matched the v1 `magic||version` prefix.
    V1Fallback,
}

/// The initiator's in-flight half of the exchange — our keypair,
/// kept alive until the peer's key arrives.
pub struct PendingHandshake {
    key: SecretKey,
    ellswift: ElligatorSwift,
    /// The garbage we sent — the AAD on our version packet (Core's
    /// `m_send_garbage` survives until `SendVersion`).
    garbage: Vec<u8>,
}

/// Initiator handshake phase 1 — write `ellswift_ours || garbage`.
/// Split from [`finish_handshake`] so tests can interleave the
/// responder on in-memory pipes; production callers can just use
/// [`handshake`].
///
/// # Errors
/// `io` on write failure.
pub fn start_handshake<S: std::io::Write>(stream: &mut S) -> std::io::Result<PendingHandshake> {
    let mut ent = [0u8; 32];
    getrandom::fill(&mut ent).map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    let (key, ellswift) = keypair(ent)?;

    let mut garbage_len_bytes = [0u8; 2];
    getrandom::fill(&mut garbage_len_bytes)
        .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    let garbage_len = usize::from(u16::from_le_bytes(garbage_len_bytes)) % (MAX_GARBAGE_LEN + 1);
    let mut garbage = vec![0u8; garbage_len];
    getrandom::fill(&mut garbage)
        .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    stream.write_all(&ellswift.to_array())?;
    stream.write_all(&garbage)?;
    Ok(PendingHandshake {
        key,
        ellswift,
        garbage,
    })
}

/// Initiator handshake phase 2 — watch the peer's first 16 bytes for
/// the v1 `magic||version` prefix; once they diverge (or 64 key bytes
/// land), run ECDH and return the cipher state.
///
/// # Errors
/// `io` on socket failure or a peer that stalls the handshake.
pub fn finish_handshake<S: std::io::Read>(
    stream: &mut S,
    pending: PendingHandshake,
    magic: [u8; 4],
) -> std::io::Result<Handshake> {
    let v1_prefix: [u8; 16] = {
        let mut p = [0u8; 16];
        p[..4].copy_from_slice(&magic);
        p[4..11].copy_from_slice(b"version");
        p
    };
    // Core's `ShouldReconnectV1`: any drop while nothing has been
    // received (we've already sent a v1-header's worth of ellswift
    // bytes — enough to make a v1 peer bail on bad magic) means
    // redial cleartext. That covers the v1 peer's immediate
    // disconnect *and* a silent peer's timeout.
    let mut head = Vec::with_capacity(ELLIGATOR_SWIFT_LEN);
    while head.len() < v1_prefix.len() {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return Ok(Handshake::V1Fallback),
            Ok(_) => {
                head.push(byte[0]);
                if head.last() != v1_prefix.get(head.len() - 1) {
                    break; // diverged from the v1 prefix — it's v2
                }
            }
            // A v1 peer that got our "header" may simply RST us.
            Err(e) if head.is_empty() => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(e);
                }
                return Ok(Handshake::V1Fallback);
            }
            Err(e) => return Err(e),
        }
    }
    if head.len() == v1_prefix.len() && head == v1_prefix {
        return Ok(Handshake::V1Fallback);
    }
    // v2: complete their 64-byte key. A drop mid-key is a hard
    // failure — Core only reconnects with an empty recv buffer.
    let mut theirs = [0u8; ELLIGATOR_SWIFT_LEN];
    theirs[..head.len()].copy_from_slice(&head);
    let mut off = head.len();
    while off < ELLIGATOR_SWIFT_LEN {
        let n = stream.read(&mut theirs[off..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed during handshake",
            ));
        }
        off += n;
    }
    let cipher = Bip324Cipher::initialize(
        &pending.key,
        pending.ellswift,
        ElligatorSwift::from_array(theirs),
        true,
        magic,
    );
    Ok(Handshake::V2(Box::new(cipher), pending.garbage))
}

/// Initiator-side v2 handshake — Core's outbound `V2Transport`
/// sequence: `start` + `finish` composed for a blocking stream.
///
/// # Errors
/// `io` on socket failure or a peer that stalls the handshake.
pub fn handshake<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    magic: [u8; 4],
) -> std::io::Result<Handshake> {
    let pending = start_handshake(stream)?;
    finish_handshake(stream, pending, magic)
}

/// Responder-side v2 handshake — Core's inbound `V2Transport`: read
/// the initiator's 64-byte key, send our key + garbage + terminator +
/// version packet, then hand back the channel. (Used by tests and any
/// future inbound accept path.)
///
/// # Errors
/// `io` on socket failure or a short/oversized key read.
pub fn respond_handshake<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    magic: [u8; 4],
) -> std::io::Result<V2Channel> {
    let mut theirs = [0u8; ELLIGATOR_SWIFT_LEN];
    stream.read_exact(&mut theirs)?;

    let mut ent = [0u8; 32];
    getrandom::fill(&mut ent).map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    let (key, ellswift) = keypair(ent)?;
    let mut cipher = Box::new(Bip324Cipher::initialize(
        &key,
        ellswift,
        ElligatorSwift::from_array(theirs),
        false,
        magic,
    ));
    let mut out = ellswift.to_array().to_vec();
    // Responder garbage — same cap as the initiator's.
    let mut len_bytes = [0u8; 2];
    getrandom::fill(&mut len_bytes)
        .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    let garbage_len = usize::from(u16::from_le_bytes(len_bytes)) % (MAX_GARBAGE_LEN + 1);
    let mut garbage = vec![0u8; garbage_len];
    getrandom::fill(&mut garbage)
        .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    out.extend_from_slice(&garbage);
    out.extend_from_slice(cipher.send_garbage_terminator());
    // The version packet authenticates our garbage as its AAD.
    out.extend_from_slice(&cipher.encrypt_packet(&[], &garbage, false));
    stream.write_all(&out)?;

    // Our garbage was sent before the initiator's terminator arrives —
    // the channel's feed() skips their garbage + terminator + version
    // packet on the first poll.
    let channel = V2Channel::new(cipher, Vec::new());
    Ok(channel)
}

/// The encrypted-transport half of a session: the cipher plus the
/// incremental receive state (`recv_len` holds the decrypted packet
/// length once its 3-byte field has arrived).
pub struct V2Channel {
    cipher: Box<Bip324Cipher>,
    /// Raw ciphertext accumulated toward the current packet.
    recv_buf: Vec<u8>,
    /// Decrypted length once the `LENGTH_LEN` field is complete.
    recv_len: Option<u32>,
    /// The garbage we sent during the handshake — the AAD on our
    /// version packet (Core keeps `m_send_garbage` until
    /// `SendVersion`). Empty once the tail has been produced.
    send_garbage: Vec<u8>,
    /// The peer's garbage — the AAD expected on the *first*
    /// successfully decrypted packet (Core's `m_recv_aad`), then
    /// cleared; later packets authenticate against empty AAD.
    recv_aad: Option<Vec<u8>>,
    /// Their garbage terminator has been consumed.
    saw_terminator: bool,
    /// RecvState::VERSION — the first packet after the terminator is
    /// the version packet; its contents are dropped, not decoded.
    saw_version: bool,
}

impl V2Channel {
    /// Post-handshake state — caller must still send
    /// `handshake_tail()` (terminator + version packet) and the
    /// peer's terminator must arrive before the channel is `ready`.
    /// `send_garbage` is the garbage already on the wire — it becomes
    /// the version packet's AAD.
    pub fn new(cipher: Box<Bip324Cipher>, send_garbage: Vec<u8>) -> Self {
        Self {
            cipher,
            recv_buf: Vec::new(),
            recv_len: None,
            send_garbage,
            recv_aad: None,
            saw_terminator: false,
            saw_version: false,
        }
    }

    /// After ECDH: the bytes we owe the peer — garbage terminator,
    /// then the version packet authenticated by our garbage.
    pub fn handshake_tail(&mut self) -> Vec<u8> {
        let aad = std::mem::take(&mut self.send_garbage);
        let mut out = Vec::new();
        out.extend_from_slice(self.cipher.send_garbage_terminator());
        out.extend_from_slice(&self.cipher.encrypt_packet(&[], &aad, false));
        out
    }

    pub fn session_id(&self) -> [u8; 32] {
        self.cipher.session_id
    }

    /// Queue one message: `msgtype-prefix || payload` becomes one
    /// packet. `send_queue` bytes go straight on the wire.
    pub fn encode_message(&mut self, command: &str, payload: &[u8]) -> Vec<u8> {
        let mut contents = encode_message_type(command);
        contents.extend_from_slice(payload);
        self.cipher.encrypt_packet(&contents, &[], false)
    }

    /// Feed raw socket bytes; returns complete `(command, payload)`
    /// messages (decoy packets drop silently; the handshake tail —
    /// peer garbage + terminator + version packet — is consumed
    /// first). `Err` on a bad tag or protocol violation.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
        let mut out = Vec::new();
        self.recv_buf.extend_from_slice(bytes);
        loop {
            if !self.saw_terminator {
                // Skip peer garbage up to MAX_GARBAGE_LEN, then the
                // terminator itself, then one version packet.
                let term = *self.cipher.recv_garbage_terminator();
                let need = MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN;
                // Scan for the terminator within the garbage window.
                let limit = self.recv_buf.len().min(need);
                let mut found = None;
                for i in 0..limit {
                    if i + GARBAGE_TERMINATOR_LEN <= self.recv_buf.len()
                        && self.recv_buf[i..i + GARBAGE_TERMINATOR_LEN] == term
                    {
                        found = Some(i);
                        break;
                    }
                    if i >= MAX_GARBAGE_LEN {
                        break;
                    }
                }
                match found {
                    Some(i) => {
                        // The peer's garbage becomes the AAD on the
                        // first packet we manage to decrypt (Core's
                        // `m_recv_aad` = recv_buffer minus terminator).
                        self.recv_aad = Some(self.recv_buf[..i].to_vec());
                        self.recv_buf.drain(..i + GARBAGE_TERMINATOR_LEN);
                        self.saw_terminator = true;
                    }
                    None => {
                        // Hold the tail — the terminator may be split
                        // across reads. Anything beyond the window
                        // can't be a terminator start.
                        if self.recv_buf.len() > need {
                            return Err("peer garbage overrun");
                        }
                        if self.recv_buf.len() > MAX_GARBAGE_LEN {
                            let keep = GARBAGE_TERMINATOR_LEN - 1;
                            let drop = self.recv_buf.len() - keep;
                            self.recv_buf.drain(..drop);
                        }
                        break;
                    }
                }
            }
            if self.recv_len.is_none() {
                if self.recv_buf.len() < LENGTH_LEN {
                    break;
                }
                let enc = self.recv_buf[..LENGTH_LEN].to_vec();
                let len = self.cipher.decrypt_length(&enc);
                if len as usize > MAX_CONTENTS_LEN {
                    return Err("packet contents too large");
                }
                self.recv_buf.drain(..LENGTH_LEN);
                self.recv_len = Some(len);
            }
            let Some(len) = self.recv_len else { break };
            let len = len as usize;
            let packet_len = HEADER_LEN + len + TAG_LEN;
            if self.recv_buf.len() < packet_len {
                break;
            }
            let packet = self.recv_buf[..packet_len].to_vec();
            self.recv_buf.drain(..packet_len);
            self.recv_len = None;
            // The first decrypted packet (their version packet, or a
            // decoy before it) authenticates against their garbage;
            // afterwards the expected AAD is empty.
            let aad = self.recv_aad.take().unwrap_or_default();
            let (ignore, contents) = self
                .cipher
                .decrypt_packet(&packet, &aad)
                .ok_or("bad packet tag — transport desynchronized")?;
            // The version packet follows the terminator — drop its
            // contents without decoding (RecvState::VERSION).
            if !self.saw_version {
                self.saw_version = true;
                continue;
            }
            if ignore {
                continue;
            }
            match decode_message_type(&contents) {
                Some((cmd, payload)) => out.push((cmd, payload.to_vec())),
                // Core's `ReceiveMsgBytes`: "Message deserialization
                // failed. Drop the message but don't disconnect the
                // peer" — an unparseable message *type* means this one
                // packet is unusable, not that the transport itself
                // desynchronized (the AEAD tag already authenticated
                // it). Skip it and keep decoding the rest of `bytes`.
                None => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Core's `crypto_tests` HKDF vector — RFC5869 truncated to the
    /// single-round L32 form.
    #[test]
    fn hkdf_matches_core_vector() {
        let hkdf = Hkdf32::new(&[0x0b; 22], &unhex("000102030405060708090a0b0c"));
        assert_eq!(
            hkdf.expand_bytes(&unhex("f0f1f2f3f4f5f6f7f8f9")),
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
        );
    }

    /// Core's `AEADChaCha20Poly1305` known-answer: nonce
    /// `{0x3432b75f, 0xb3585537eb7f4024}` over a 48-byte message.
    #[test]
    fn aead_matches_core_vector() {
        let key: [u8; 32] =
            unhex("72ddc73f07101282bbbcf853b9012a9f9695fc5d36b303a97fd0845d0314e0c3")
                .try_into()
                .unwrap();
        let plain = unhex(
            "8d2d6a8befd9716fab35819eaac83b33269afb9f1a00fddf66095a6c0cd91951\
             a6b7ad3db580be0674c3f0b55f618e34",
        );
        let expected = unhex(
            "f760b8224fb2a317b1b07875092606131232a5b86ae142df5df1c846a7f6341a\
             f2564483dd77f836be45e6230808ffe402a6f0a3e8be074b3d1f4ea8a7b09451",
        );
        let aead = ChaCha20Poly1305::new((&key).into());
        let nonce = nonce96(0x3432b75f, 0xb3585537eb7f4024);
        let ct = aead
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: &[],
                },
            )
            .unwrap();
        assert_eq!(ct, expected);
        let back = aead
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload { msg: &ct, aad: &[] },
            )
            .unwrap();
        assert_eq!(back, plain);
    }

    /// Core's `FSChaCha20Poly1305` vector at `msg_idx=500` — crosses
    /// the rekey boundary at packet 224.
    #[test]
    fn fs_aead_matches_core_vector_past_rekey() {
        let key: [u8; 32] =
            unhex("5c9e1c3951a74fba66708bf9d2c217571684556b6a6a3573bff2847d38612654")
                .try_into()
                .unwrap();
        let plain = unhex(
            "d6a4cb04ef0f7c09c1866ed29dc24d820e75b0491032a51b4c3366f9ca35c19e\
             a3047ec6be9d45f9637b63e1cf9eb4c2523a5aab7b851ebeba87199db0e839cf\
             0d5c25e50168306377aedbe9089fd2463ded88b83211cf51b73b150608cc7a60\
             0d0f11b9a742948482e1b109d8faf15b450aa7322e892fa2208c6691e3fecf4c\
             711191b14d75a72147",
        );
        let aad = unhex("786cb9b6ebf44288974cf0");
        let expected = unhex(
            "9dcebbd3281ea3dd8e9a1ef7d55a97abd6743e56ebc0c190cb2c4e14160b385e\
             0bf508dddf754bd02c7c208447c131ce23e47a4a14dfaf5dd8bc601323950f75\
             4e05d46e9232f83fc5120fbbef6f5347a826ec79a93820718d4ec7a2b7cfaaa4\
             4b21e16d726448b62f803811aff4f6d827ed78e738ce8a507b81a8ae13131192\
             8039213de18a5120dc9b7370baca878f50ff254418de3da50c",
        );
        let mut enc = FsChaCha20Poly1305::new(&key);
        for _ in 0..500 {
            enc.encrypt(&[], &[0u8; 16]);
        }
        assert_eq!(enc.encrypt(&plain, &aad), expected);
        // And a fresh decryptor lands on the same plaintext.
        let mut dec = FsChaCha20Poly1305::new(&key);
        for _ in 0..500 {
            dec.decrypt(&enc_zeros(), &[0u8; 16]);
        }
        let mut enc2 = FsChaCha20Poly1305::new(&key);
        for _ in 0..500 {
            enc2.encrypt(&[], &[0u8; 16]);
        }
        let ct = enc2.encrypt(&plain, &aad);
        assert_eq!(dec.decrypt(&ct, &aad), Some(plain));
    }

    fn enc_zeros() -> Vec<u8> {
        vec![0u8; 16]
    }

    /// Core's `ReceiveMsgBytes`: "Message deserialization failed. Drop
    /// the message but don't disconnect the peer." A packet whose
    /// message-type byte doesn't decode (short id 200 is well past
    /// `SHORT_IDS`' 29 entries) must not fail `feed()`, and a message
    /// decoded earlier in the *same* `feed()` call must not be
    /// discarded alongside it.
    #[test]
    fn feed_drops_an_undecodable_message_but_keeps_the_rest() {
        use std::io::{Read, Write};

        const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest

        let (mut a, mut b) = crate::testpipe::pair();
        let pending = start_handshake(&mut a).unwrap();
        let mut ch_b = respond_handshake(&mut b, MAGIC).unwrap();
        let Handshake::V2(cipher_a, garbage_a) = finish_handshake(&mut a, pending, MAGIC).unwrap()
        else {
            panic!("v1 fallback on a v2 peer");
        };
        let mut ch_a = V2Channel::new(cipher_a, garbage_a);
        a.write_all(&ch_a.handshake_tail()).unwrap();

        // Get b past the handshake (its peer's garbage/terminator/
        // version packet) before sending anything meaningful.
        let mut buf = [0u8; 4096];
        let n = b.read(&mut buf).unwrap();
        let handshake_msgs = ch_b.feed(&buf[..n]).unwrap();
        assert!(handshake_msgs.is_empty());

        // One packet with an out-of-range short id (undecodable), then
        // one ordinary `ping`, encrypted back to back exactly as they'd
        // arrive batched in a single socket read.
        let bad = ch_a.cipher.encrypt_packet(&[200, 1, 2, 3], &[], false);
        let good = ch_a
            .cipher
            .encrypt_packet(&encode_message_type("ping"), &[], false);
        let mut combined = bad;
        combined.extend_from_slice(&good);

        let msgs = ch_b
            .feed(&combined)
            .expect("an undecodable message type must not fail the whole feed() call");
        assert_eq!(
            msgs,
            vec![("ping".to_string(), Vec::new())],
            "the bad packet is dropped; the good one decoded in the same call must survive"
        );
    }
}
