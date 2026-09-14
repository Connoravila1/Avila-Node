//! P2P message framing — Core's `CMessageHeader`/`V1Transport`.
//!
//! Wire layout: `magic[4] | command[12] | length u32 LE | checksum[4] |
//! payload`. The checksum is the first four bytes of the payload's
//! sha256d. A decoder buffers partial reads and yields complete frames only
//! after the checksum verifies, so a caller never sees an unchecked payload.

use std::collections::VecDeque;

use avila_consensus::hash::sha256d;
use thiserror::Error;

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH` (net.h) — the largest payload a peer
/// may legitimately send.
pub const MAX_MESSAGE_PAYLOAD: u32 = 4_000_000;

/// The fixed message-header size: magic + command + length + checksum.
pub const HEADER_LEN: usize = 24;

/// A frame's 12-byte command field — ASCII, NUL-padded on the right. Kept as
/// raw bytes: unknown commands pass through as [`crate::message::Message::Unknown`]
/// exactly as Core ignores unrecognized commands.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Command([u8; 12]);

impl Command {
    /// Wraps an ASCII command name (`"version"`, `"headers"`, ...). The name
    /// must be non-empty, ≤ 12 bytes, printable ASCII without interior NULs.
    /// Anything else produces `None` rather than a malformed frame.
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > 12 || !bytes.iter().all(|b| (0x20..=0x7e).contains(b))
        {
            return None;
        }
        let mut padded = [0u8; 12];
        padded[..bytes.len()].copy_from_slice(bytes);
        Some(Self(padded))
    }

    /// The command name with NUL padding stripped.
    #[must_use]
    pub fn name(&self) -> &str {
        let end = self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len());
        // Invariant: construction and decode both reject non-ASCII bytes.
        std::str::from_utf8(&self.0[..end]).unwrap_or("")
    }
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Command").field(&self.name()).finish()
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a frame stream is unusable — every variant is a protocol violation the
/// peer is responsible for (Core disconnects on the same conditions).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The declared payload length exceeds [`MAX_MESSAGE_PAYLOAD`].
    #[error("message payload {0} bytes exceeds the 4 MiB protocol maximum")]
    PayloadTooLarge(u32),
    /// The command field contains non-ASCII or non-NUL-padded bytes.
    #[error("malformed command field")]
    BadCommand,
    /// The sha256d checksum did not match the payload.
    #[error("payload checksum mismatch")]
    BadChecksum,
    /// The frame's magic does not match the expected network.
    #[error("frame magic does not match this network")]
    BadMagic,
}

/// Encodes one complete frame: `magic | command | len | checksum | payload`.
#[must_use]
pub fn encode_frame(magic: [u8; 4], command: Command, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&magic);
    frame.extend_from_slice(&command.0);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&sha256d(payload)[..4]);
    frame.extend_from_slice(payload);
    frame
}

/// Incremental frame decoder for one network. Feed bytes as they arrive;
/// `next_frame` yields `(command, payload)` for each complete, verified
/// message. Any [`FrameError`] is terminal for the connection — Core drops
/// the peer on the same violations.
pub struct FrameDecoder {
    magic: [u8; 4],
    buf: VecDeque<u8>,
    /// Set once a terminal error is reported — later calls keep returning it.
    poisoned: bool,
}

impl FrameDecoder {
    /// A decoder for the network whose `pchMessageStart` is `magic`.
    #[must_use]
    pub fn new(magic: [u8; 4]) -> Self {
        Self {
            magic,
            buf: VecDeque::new(),
            poisoned: false,
        }
    }

    /// Appends received bytes to the pending stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
    }

    /// Buffered bytes not yet consumed by a complete frame.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// The peer's declared payload length would exceed the per-message
    /// maximum plus the header — the buffer can never grow legitimately
    /// beyond one maximum frame.
    fn over_buffered(&self) -> bool {
        self.buf.len() as u64 > HEADER_LEN as u64 + u64::from(MAX_MESSAGE_PAYLOAD)
    }

    /// Pops the next complete frame, or `Ok(None)` when the buffer holds only
    /// a partial message.
    ///
    /// # Errors
    ///
    /// [`FrameError`] on any protocol violation; the decoder stays poisoned
    /// after the first error.
    pub fn next_frame(&mut self) -> Result<Option<(Command, Vec<u8>)>, FrameError> {
        if self.poisoned {
            return Err(FrameError::BadChecksum);
        }
        if self.over_buffered() {
            self.poisoned = true;
            return Err(FrameError::PayloadTooLarge(MAX_MESSAGE_PAYLOAD + 1));
        }
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let header: Vec<u8> = self.buf.iter().take(HEADER_LEN).copied().collect();
        if header[..4] != self.magic {
            self.poisoned = true;
            return Err(FrameError::BadMagic);
        }
        let command = Command(header[4..16].try_into().unwrap_or([0; 12]));
        // Core accepts any bytes in the command field of a frame whose
        // checksum verifies; we additionally require the printable/NUL-padded
        // form `Command::name` relies on.
        let raw = &header[4..16];
        let nul_pos = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if !raw[..nul_pos].iter().all(|b| (0x20..=0x7e).contains(b))
            || raw[nul_pos..].iter().any(|b| *b != 0)
        {
            self.poisoned = true;
            return Err(FrameError::BadCommand);
        }
        let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        if len > MAX_MESSAGE_PAYLOAD {
            self.poisoned = true;
            return Err(FrameError::PayloadTooLarge(len));
        }
        if self.buf.len() < HEADER_LEN + len as usize {
            return Ok(None);
        }
        self.buf.drain(..HEADER_LEN);
        let payload: Vec<u8> = self.buf.drain(..len as usize).collect();
        if sha256d(&payload)[..4] != header[20..24] {
            self.poisoned = true;
            return Err(FrameError::BadChecksum);
        }
        Ok(Some((command, payload)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest

    fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
        encode_frame(MAGIC, Command::new(command).unwrap(), payload)
    }

    #[test]
    fn command_pads_and_strips_nuls() {
        let cmd = Command::new("version").unwrap();
        assert_eq!(cmd.name(), "version");
        assert_eq!(Command::new("verack").unwrap().name(), "verack");
        assert_eq!(Command::new("abcdefghijkl").unwrap().name(), "abcdefghijkl");
    }

    #[test]
    fn command_rejects_malformed_names() {
        assert_eq!(Command::new(""), None);
        assert_eq!(Command::new("thirteenbytes!"), None);
        assert_eq!(Command::new("low\tlevel"), None); // control byte
        assert_eq!(Command::new("utf8-é"), None); // non-ASCII
    }

    #[test]
    fn frame_round_trip() {
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&frame("ping", &1234u64.to_le_bytes()));
        let (cmd, payload) = dec.next_frame().unwrap().unwrap();
        assert_eq!(cmd, Command::new("ping").unwrap());
        assert_eq!(payload, 1234u64.to_le_bytes());
        assert_eq!(dec.next_frame().unwrap(), None);
    }

    #[test]
    fn empty_payload_round_trip() {
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&frame("verack", &[]));
        let (cmd, payload) = dec.next_frame().unwrap().unwrap();
        assert_eq!(cmd.name(), "verack");
        assert!(payload.is_empty());
    }

    #[test]
    fn byte_at_a_time_feed() {
        let wire = frame("mempool", &[]);
        let mut dec = FrameDecoder::new(MAGIC);
        for (i, b) in wire.iter().enumerate() {
            dec.feed(&[*b]);
            if i < wire.len() - 1 {
                assert_eq!(
                    dec.next_frame().unwrap(),
                    None,
                    "premature frame at byte {i}"
                );
            }
        }
        assert_eq!(dec.next_frame().unwrap().unwrap().0.name(), "mempool");
    }

    #[test]
    fn coalesced_frames_decode_in_order() {
        let mut wire = frame("sendheaders", &[]);
        wire.extend_from_slice(&frame("ping", &7u64.to_le_bytes()));
        wire.extend_from_slice(&frame("pong", &9u64.to_le_bytes()));
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&wire);
        let mut names = Vec::new();
        while let Some((cmd, _)) = dec.next_frame().unwrap() {
            names.push(cmd.name().to_string());
        }
        assert_eq!(names, ["sendheaders", "ping", "pong"]);
    }

    #[test]
    fn foreign_magic_is_rejected() {
        let mut wire = frame("verack", &[]);
        wire[..4].copy_from_slice(&[0x0b, 0x11, 0x09, 0x07]); // mainnet magic
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&wire);
        assert_eq!(dec.next_frame(), Err(FrameError::BadMagic));
    }

    #[test]
    fn malformed_command_field_is_rejected() {
        for bad in [
            *b"ver\x01sion\0\0\0\0", // control byte inside the name
            *b"ping\0x\0\0\0\0\0\0", // non-NUL after padding begins
            *b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", // non-ASCII
        ] {
            let mut wire = frame("ping", &8u64.to_le_bytes());
            wire[4..16].copy_from_slice(&bad);
            // Fix the checksum so only the command field is at fault.
            let sum = sha256d(&wire[HEADER_LEN..]);
            wire[20..24].copy_from_slice(&sum[..4]);
            let mut dec = FrameDecoder::new(MAGIC);
            dec.feed(&wire);
            assert_eq!(dec.next_frame(), Err(FrameError::BadCommand), "{bad:?}");
        }
    }

    #[test]
    fn oversized_payload_is_rejected_without_buffering() {
        let mut dec = FrameDecoder::new(MAGIC);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(b"block\0\0\0\0\0\0\0");
        header.extend_from_slice(&(MAX_MESSAGE_PAYLOAD + 1).to_le_bytes());
        header.extend_from_slice(&[0u8; 4]);
        dec.feed(&header);
        assert_eq!(
            dec.next_frame(),
            Err(FrameError::PayloadTooLarge(MAX_MESSAGE_PAYLOAD + 1))
        );
        // The decoder stays poisoned after a terminal violation.
        assert!(dec.next_frame().is_err());
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let mut wire = frame("ping", &5u64.to_le_bytes());
        wire[HEADER_LEN..].copy_from_slice(&6u64.to_le_bytes()); // payload ≠ checksum
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&wire);
        assert_eq!(dec.next_frame(), Err(FrameError::BadChecksum));
    }

    #[test]
    fn truncated_payload_waits_for_more_bytes() {
        let wire = frame("block", &[0xaa; 100]);
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&wire[..wire.len() - 10]);
        assert_eq!(dec.next_frame().unwrap(), None);
        dec.feed(&wire[wire.len() - 10..]);
        assert_eq!(dec.next_frame().unwrap().unwrap().1, vec![0xaa; 100]);
    }

    #[test]
    fn garbage_prefix_is_rejected_as_bad_magic() {
        // A misaligned stream can never resynchronize — Core drops such peers
        // rather than scanning for the next magic.
        let mut dec = FrameDecoder::new(MAGIC);
        dec.feed(&[0xde, 0xad, 0xbe, 0xef]);
        dec.feed(&frame("verack", &[]));
        assert_eq!(dec.next_frame(), Err(FrameError::BadMagic));
    }
}
