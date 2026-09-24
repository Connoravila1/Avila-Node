//! Bounded, forward-only advice transport for the isolated experiment.
//! Frames select local block/transaction positions; only the signature
//! equations establish validity. Malformed advice always permits fallback.
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAGIC: &[u8; 8] = b"AVHINT04";
pub const MAX_FRAME: usize = 1 << 20;
const MAX_CHECKS: usize = 80_000;
const MAX_BLOCK_CHECKS: usize = 500_000;
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static LIVE_HINTS: AtomicU64 = AtomicU64::new(0);
static PEAK_HINTS: AtomicU64 = AtomicU64::new(0);

pub struct Frame {
    pub hints: Vec<Vec<u8>>,
    bytes: u64,
}
impl Frame {
    fn new(hints: Vec<Vec<u8>>) -> Arc<Self> {
        let bytes = hints.iter().map(|v| v.len() as u64).sum();
        PEAK.fetch_max(LIVE.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
        PEAK_HINTS.fetch_max(
            LIVE_HINTS.fetch_add(bytes, Ordering::Relaxed) + bytes,
            Ordering::Relaxed,
        );
        Arc::new(Self { hints, bytes })
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
        LIVE_HINTS.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}
pub type Token = Option<(Arc<Frame>, usize)>;
pub fn token(frame: &Option<Arc<Frame>>, index: usize) -> Token {
    frame.as_ref().map(|f| (Arc::clone(f), index))
}
pub fn peaks() -> (u64, u64) {
    (
        PEAK.load(Ordering::Relaxed),
        PEAK_HINTS.load(Ordering::Relaxed),
    )
}

fn compact(out: &mut Vec<u8>, n: usize) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 65535 {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
}
fn count(data: &mut &[u8]) -> io::Result<usize> {
    let mut tag = [0];
    data.read_exact(&mut tag)?;
    let bytes = match tag[0] {
        253 => 2,
        254 => 4,
        255 => 8,
        n => return Ok(n as usize),
    };
    let mut value = [0; 8];
    data.read_exact(&mut value[..bytes])?;
    let value = u64::from_le_bytes(value);
    let min = match bytes {
        2 => 253,
        4 => 65536,
        _ => 1 << 32,
    };
    if value < min {
        return Err(io::Error::other("noncanonical count"));
    }
    usize::try_from(value).map_err(|_| io::Error::other("count overflow"))
}

pub fn write_frame(writer: &mut impl Write, hash: &[u8; 32], hints: &[Vec<u8>]) -> io::Result<()> {
    let mut body = Vec::new();
    compact(&mut body, hints.len());
    let mut total = 0;
    for tx in hints {
        if tx.len() > MAX_CHECKS {
            return Err(io::Error::other("transaction bound"));
        }
        total += tx.len();
        if total > MAX_BLOCK_CHECKS {
            return Err(io::Error::other("block bound"));
        }
        compact(&mut body, tx.len());
    }
    let start = body.len();
    body.resize(start + total.div_ceil(4), 0);
    let mut escapes = Vec::new();
    for (i, hint) in hints.iter().flatten().copied().enumerate() {
        let symbol = match hint {
            0 | 1 => hint,
            255 => 2,
            2 | 3 => {
                escapes.push(hint);
                3
            }
            _ => return Err(io::Error::other("unknown hint")),
        };
        body[start + i / 4] |= symbol << ((i % 4) * 2);
    }
    body.extend_from_slice(&escapes);
    if body.len() > MAX_FRAME {
        return Err(io::Error::other("frame bound"));
    }
    writer.write_all(hash)?;
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(&body)
}

fn decode(mut data: &[u8], expected_transactions: usize) -> io::Result<Arc<Frame>> {
    let n = count(&mut data)?;
    if n != expected_transactions || n > 100_000 {
        return Err(io::Error::other("transaction count"));
    }
    let mut counts = Vec::with_capacity(n);
    let mut total: usize = 0;
    for _ in 0..n {
        let checks = count(&mut data)?;
        total = total
            .checked_add(checks)
            .ok_or_else(|| io::Error::other("count overflow"))?;
        if checks > MAX_CHECKS || total > MAX_BLOCK_CHECKS {
            return Err(io::Error::other("check bound"));
        }
        counts.push(checks);
    }
    let size = total.div_ceil(4);
    if size > data.len() {
        return Err(io::Error::other("truncated packed hints"));
    }
    let (packed, rest) = data.split_at(size);
    data = rest;
    if total % 4 != 0 && packed.last().unwrap() >> ((total % 4) * 2) != 0 {
        return Err(io::Error::other("nonzero padding"));
    }
    let mut result = Vec::with_capacity(n);
    let mut ordinal = 0;
    for checks in counts {
        let mut hints = Vec::with_capacity(checks);
        for _ in 0..checks {
            let symbol = (packed[ordinal / 4] >> ((ordinal % 4) * 2)) & 3;
            ordinal += 1;
            hints.push(match symbol {
                0 | 1 => symbol,
                2 => 255,
                _ => {
                    let mut escaped = [0];
                    data.read_exact(&mut escaped)?;
                    if !matches!(escaped[0], 2 | 3) {
                        return Err(io::Error::other("bad escape"));
                    }
                    escaped[0]
                }
            });
        }
        result.push(hints);
    }
    if !data.is_empty() {
        return Err(io::Error::other("frame trailing bytes"));
    }
    Ok(Frame::new(result))
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub bytes: u64,
    pub frames: u64,
    pub missed: u64,
    pub rejected: u64,
}
pub struct Reader {
    input: Option<BufReader<File>>,
    next: Option<([u8; 32], Vec<u8>)>,
    pub stats: Stats,
}
impl Reader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut input = BufReader::new(File::open(path)?);
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::other("stream magic"));
        }
        Ok(Self {
            input: Some(input),
            next: None,
            stats: Stats {
                bytes: 8,
                ..Stats::default()
            },
        })
    }
    fn read_next(&mut self) -> io::Result<Option<([u8; 32], Vec<u8>)>> {
        let Some(reader) = self.input.as_mut() else {
            return Ok(None);
        };
        let mut hash = [0; 32];
        if reader.read(&mut hash[..1])? == 0 {
            self.input = None;
            return Ok(None);
        }
        reader.read_exact(&mut hash[1..])?;
        let mut size = [0; 4];
        reader.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as usize;
        if size > MAX_FRAME {
            return Err(io::Error::other("frame bound"));
        }
        let mut body = vec![0; size];
        reader.read_exact(&mut body)?;
        self.stats.bytes += 36 + size as u64;
        Ok(Some((hash, body)))
    }
    pub fn block(&mut self, hash: &[u8; 32], transactions: usize) -> Option<Arc<Frame>> {
        if self.next.is_none() {
            match self.read_next() {
                Ok(next) => self.next = next,
                Err(_) => {
                    self.stats.rejected += 1;
                    self.input = None;
                }
            }
        }
        if self.next.as_ref().is_none_or(|(id, _)| id != hash) {
            self.stats.missed += 1;
            return None;
        }
        let (_, data) = self.next.take().unwrap();
        match decode(&data, transactions) {
            Ok(frame) => {
                self.stats.frames += 1;
                Some(frame)
            }
            Err(_) => {
                self.stats.rejected += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_bounds() {
        let hints = vec![vec![0, 1, 2, 3, 255, 1, 0], vec![], vec![255; 260]];
        let mut packet = Vec::new();
        write_frame(&mut packet, &[7; 32], &hints).unwrap();
        let body = &packet[36..];
        assert_eq!(decode(body, 3).unwrap().hints, hints);
        assert!(decode(body, 4).is_err());
        for end in 0..body.len() {
            assert!(decode(&body[..end], 3).is_err());
        }
        let mut extra = body.to_vec();
        extra.push(0);
        assert!(decode(&extra, 3).is_err());
        assert!(decode(&[253, 0, 0], 0).is_err());
        assert!(decode(&[1, 255, 255, 255, 255, 255, 255, 255, 255, 255], 1).is_err());
        assert!(decode(&[1, 1, 0xfc], 1).is_err()); // padding
        assert!(decode(&[1, 1, 3, 4], 1).is_err()); // escape
    }
}
