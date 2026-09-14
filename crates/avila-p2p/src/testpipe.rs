//! In-memory full-duplex transport for tests — never blocks on write,
//! `WouldBlock` on empty read, EOF once the peer end drops.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::rc::Rc;

use crate::codec::{Command, encode_frame};
use crate::message::Message;

pub struct End {
    /// Bytes this end reads (written by the other end).
    inbox: Rc<RefCell<VecDeque<u8>>>,
    /// Bytes this end writes (read by the other end).
    outbox: Rc<RefCell<VecDeque<u8>>>,
    /// Whether the peer end is still alive.
    peer_open: Rc<Cell<bool>>,
    /// This end's liveness flag, observed by the peer.
    alive: Rc<Cell<bool>>,
}

impl Drop for End {
    fn drop(&mut self) {
        self.alive.set(false);
    }
}

/// Creates the two ends of a pipe.
pub fn pair() -> (End, End) {
    let a_to_b = Rc::new(RefCell::new(VecDeque::new()));
    let b_to_a = Rc::new(RefCell::new(VecDeque::new()));
    let a_open = Rc::new(Cell::new(true));
    let b_open = Rc::new(Cell::new(true));
    (
        End {
            inbox: b_to_a.clone(),
            outbox: a_to_b.clone(),
            peer_open: b_open.clone(),
            alive: a_open.clone(),
        },
        End {
            inbox: a_to_b,
            outbox: b_to_a,
            peer_open: a_open,
            alive: b_open,
        },
    )
}

impl Read for End {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut inbox = self.inbox.borrow_mut();
        if inbox.is_empty() {
            return if self.peer_open.get() {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "empty pipe"))
            } else {
                Ok(0) // peer hung up
            };
        }
        let n = buf.len().min(inbox.len());
        for slot in &mut buf[..n] {
            *slot = inbox.pop_front().unwrap_or(0);
        }
        Ok(n)
    }
}

impl Write for End {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbox.borrow_mut().extend(buf.iter().copied());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `msg` as a wire frame into `end` — the scripted peer's send.
pub fn inject(end: &mut End, magic: [u8; 4], msg: &Message) {
    let command = Command::new(msg.command_name()).expect("message has a command");
    let frame = encode_frame(magic, command, &msg.encode());
    end.write_all(&frame).expect("pipe write");
}

/// Decodes every complete frame currently pending in `end` — the scripted
/// peer's receive.
pub fn drain(end: &mut End, magic: [u8; 4]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut bytes = Vec::new();
    while let Ok(n) = end.read(&mut chunk) {
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let mut dec = crate::codec::FrameDecoder::new(magic);
    dec.feed(&bytes);
    while let Ok(Some((cmd, payload))) = dec.next_frame() {
        out.push(Message::decode(&cmd, &payload).expect("decodable message"));
    }
    out
}
