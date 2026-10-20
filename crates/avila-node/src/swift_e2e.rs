//! Real-socket integration coverage for the opt-in Swift caller.
//!
//! This intentionally drives `sync::run_with_swift`, rather than testing the
//! driver and peer codec in isolation. The synthetic regtest peer is an
//! untrusted BIP455 provider; the BIP456 file is generated independently from
//! the fixture's known final live set.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use avila_consensus::arith::CompactTarget;
use avila_consensus::block::Block;
use avila_consensus::chainstate::{Acceptance, Chainstate};
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
use avila_consensus::{connect::Coin, encode::write_compact_size};
use avila_p2p::codec::{Command, FrameDecoder, encode_frame};
use avila_p2p::message::{Message, NODE_NETWORK, NetAddr, Version};
use avila_p2p::swift_spent::{
    FEATURE_DATA_V1, FEATURE_NAME, SPENT_COMMAND, SpentCoin, SpentCoins, encode_response,
};

const COIN: i64 = 100_000_000;
const NOW: u32 = 2_000_000_000;
const REGTEST_BITS: u32 = 0x207f_ffff;
const CHECKPOINT_HEIGHT: u32 = 101;
static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        loop {
            let id = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "avila-swift-tcp-{label}-{}-{id}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory: {error}"),
            }
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum ProviderMode {
    Qualified,
    NoBip455,
    BadSpentClaim,
}

fn coinbase(height: u32) -> Transaction {
    let mut script_sig = script::push_int(i64::from(height));
    script_sig.push(script::OP_1);
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::NULL,
            script_sig: Script::new(script_sig),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey: Script::new(vec![script::OP_1]),
        }],
        lock_time: 0,
    }
}

fn mine_block(previous: &BlockHeader, transactions: Vec<Transaction>, params: &Params) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: previous.hash(),
            merkle_root: previous.merkle_root,
            time: previous.time + 1,
            bits: CompactTarget(REGTEST_BITS),
            nonce: 0,
        },
        transactions,
    };
    block.header.merkle_root = block.merkle_root().0;
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn fixture_chain() -> Vec<Block> {
    let params = Network::Regtest.params();
    let mut blocks: Vec<Block> = Vec::with_capacity(CHECKPOINT_HEIGHT as usize);
    let mut previous = params.genesis_header;
    for height in 1..=CHECKPOINT_HEIGHT {
        let mut transactions = vec![coinbase(height)];
        if height == CHECKPOINT_HEIGHT {
            let first_coinbase = &blocks[0].transactions[0];
            transactions.push(Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: first_coinbase.txid(),
                        vout: 0,
                    },
                    script_sig: Script::new(Vec::new()),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: 49 * COIN,
                    script_pubkey: Script::new(vec![script::OP_1]),
                }],
                lock_time: 0,
            });
        }
        let block = mine_block(&previous, transactions, &params);
        previous = block.header;
        blocks.push(block);
    }
    blocks
}

fn write_elias_fano_record(out: &mut Vec<u8>, indices: &[u32]) {
    write_compact_size(out, indices.len() as u64);
    if indices.is_empty() {
        return;
    }
    write_compact_size(out, u64::from(*indices.last().unwrap()));
    // Fixture records are either [0] (high bit 0) or [0, 1] (bits 0 and 2).
    match indices {
        [0] => out.push(0b0000_0001),
        [0, 1] => out.push(0b0000_0101),
        _ => panic!("unexpected fixture survivor ordinals: {indices:?}"),
    }
}

fn hints_bytes() -> Vec<u8> {
    let mut out = b"UTXO".to_vec();
    out.push(0);
    out.extend_from_slice(&CHECKPOINT_HEIGHT.to_le_bytes());
    // BIP456 records are indexed from height zero; the engine starts at
    // genesis and consumes this empty record before the first fetched body.
    write_elias_fano_record(&mut out, &[]);
    for height in 1..=CHECKPOINT_HEIGHT {
        let survivors: &[u32] = match height {
            1 => &[], // spent at height 101
            101 => &[0, 1],
            _ => &[0],
        };
        write_elias_fano_record(&mut out, survivors);
    }
    out
}

fn peer_version() -> Message {
    Message::Version(Version {
        version: avila_p2p::message::PROTOCOL_VERSION,
        services: NODE_NETWORK,
        timestamp: i64::from(NOW),
        addr_recv: NetAddr::unspecified(),
        addr_from: NetAddr::unspecified(),
        nonce: 0x5357_4946_545f_5443,
        user_agent: "/avila-swift-e2e/".to_owned(),
        start_height: CHECKPOINT_HEIGHT as i32,
        relay: false,
    })
}

fn write_message(stream: &mut TcpStream, magic: [u8; 4], message: &Message) -> io::Result<()> {
    let command = message
        .command()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid p2p command"))?;
    stream.write_all(&encode_frame(magic, command, &message.encode()))
}

fn next_message(
    stream: &mut TcpStream,
    decoder: &mut FrameDecoder,
    deadline: Instant,
) -> io::Result<Option<(Command, Vec<u8>)>> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            return Ok(Some(frame));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(read) => decoder.feed(&buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

fn serve_peer(
    listener: TcpListener,
    blocks: Vec<Block>,
    mode: ProviderMode,
    shutdown: Instant,
) -> io::Result<bool> {
    listener.set_nonblocking(true)?;
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= shutdown {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let params = Network::Regtest.params();
    let magic = params.message_start;
    let mut decoder = FrameDecoder::new(magic);
    let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
    let mut sent_headers = false;
    let mut accepted_bad_claim = false;
    let mut sent_our_version = false;
    let mut saw_spent_request = false;

    while Instant::now() < shutdown {
        let read_deadline = (Instant::now() + Duration::from_millis(100)).min(shutdown);
        let Some((command, payload)) = (match next_message(&mut stream, &mut decoder, read_deadline)
        {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }) else {
            continue;
        };
        if command.name() == "version" && !sent_our_version {
            sent_our_version = true;
            write_message(&mut stream, magic, &peer_version())?;
            if !matches!(mode, ProviderMode::NoBip455) {
                write_message(
                    &mut stream,
                    magic,
                    &Message::Feature {
                        id: FEATURE_NAME.to_owned(),
                        data: FEATURE_DATA_V1.to_vec(),
                    },
                )?;
            }
            write_message(&mut stream, magic, &Message::Verack)?;
            continue;
        }
        let message = Message::decode(&command, &payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        match message {
            Message::GetHeaders(_) if !sent_headers => {
                sent_headers = true;
                write_message(&mut stream, magic, &Message::Headers(headers.clone()))?;
            }
            Message::GetData(vectors) => {
                if accepted_bad_claim {
                    continue;
                }
                for vector in vectors {
                    if let Some(block) = blocks
                        .iter()
                        .find(|block| block.block_hash() == vector.hash)
                    {
                        write_message(&mut stream, magic, &Message::Block(block.clone()))?;
                    }
                }
            }
            Message::Unknown { command, payload }
                if command == avila_p2p::swift_spent::GET_SPENT_COMMAND =>
            {
                saw_spent_request = true;
                let request = avila_p2p::swift_spent::decode_request(&payload)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let spent_out = TxOut {
                    value: 50 * COIN,
                    script_pubkey: Script::new(vec![script::OP_1]),
                };
                let response = SpentCoins {
                    block_hash: request.block_hash,
                    coins: vec![SpentCoin {
                        input_index: 0,
                        coin: Coin {
                            out: spent_out,
                            height: if matches!(mode, ProviderMode::BadSpentClaim) {
                                CHECKPOINT_HEIGHT
                            } else {
                                1
                            },
                            coinbase: true,
                        },
                    }],
                };
                let response = Message::Unknown {
                    command: SPENT_COMMAND.to_owned(),
                    payload: encode_response(&response)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
                };
                write_message(&mut stream, magic, &response)?;
                if matches!(mode, ProviderMode::BadSpentClaim) {
                    accepted_bad_claim = true;
                }
            }
            _ => {}
        }
    }
    Ok(saw_spent_request)
}

fn options_and_config(
    root: &TempTree,
    address: SocketAddr,
    checkpoint: BlockHash,
    timeout: Duration,
) -> (crate::swift_ibd::SwiftIbdOptions, crate::sync::SyncConfig) {
    let config = crate::sync::SyncConfig {
        connect: vec![address],
        target_height: CHECKPOINT_HEIGHT,
        timeout,
        v2transport: false,
        dns_seeds: false,
        data_dir: Some(root.path("promoted")),
        ..crate::sync::SyncConfig::default()
    };
    let options = crate::swift_ibd::SwiftIbdOptions {
        checkpoint_height: CHECKPOINT_HEIGHT,
        checkpoint_hash: checkpoint,
        hints_path: root.path("checkpoint.hints"),
        workspace: root.path("swift-workspace"),
    };
    (options, config)
}

fn start_server(
    blocks: &[Block],
    mode: ProviderMode,
    duration: Duration,
) -> (SocketAddr, std::thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let blocks = blocks.to_vec();
    let shutdown = Instant::now() + duration;
    let server = std::thread::spawn(move || serve_peer(listener, blocks, mode, shutdown).unwrap());
    (address, server)
}

fn assert_promoted(root: &TempTree, blocks: &[Block]) {
    let params = Network::Regtest.params();
    assert_eq!(params.assume_valid, None);
    let reopened =
        Chainstate::with_store_coinsdb(&root.path("promoted"), &params, NOW, 8 << 20).unwrap();
    assert_eq!(reopened.chain().len(), CHECKPOINT_HEIGHT as usize + 1);
    assert_eq!(reopened.tip_hash(), blocks.last().unwrap().block_hash());
    assert_eq!(reopened.snapshot_base(), None);
    assert_eq!(reopened.utxo().len(), CHECKPOINT_HEIGHT as usize);
    let first = &blocks[0].transactions[0];
    assert!(!reopened.utxo().have(&OutPoint {
        txid: first.txid(),
        vout: 0,
    }));
    let last = blocks.last().unwrap();
    assert!(reopened.utxo().have(&OutPoint {
        txid: last.transactions[1].txid(),
        vout: 0,
    }));

    // The ordinary connector is only a test oracle; the successful Swift run
    // itself has already promoted through the opaque audited snapshot token.
    let mut oracle = Chainstate::new(&params);
    for (index, block) in blocks.iter().enumerate() {
        assert_eq!(
            oracle.accept_block(block, NOW).unwrap(),
            Acceptance::Connected {
                height: index as u32 + 1,
                reorged: false,
            }
        );
    }
    let expected: HashMap<_, _> = oracle.utxo().iter().into_iter().collect();
    let actual: HashMap<_, _> = reopened.utxo().iter().into_iter().collect();
    assert_eq!(actual, expected, "promoted conventional UTXO must be exact");
}

#[test]
fn opt_in_swift_caller_crosses_tcp_audits_promotes_and_falls_back_safely() {
    let blocks = fixture_chain();
    let checkpoint = blocks.last().unwrap().block_hash();

    // Qualified provider: every body and the one matured-coinbase claim cross
    // a real v1 TCP socket; the caller audits and promotes before the ordinary
    // datadir exposes the checkpoint.
    let root = TempTree::new("qualified");
    std::fs::write(root.path("checkpoint.hints"), hints_bytes()).unwrap();
    let (address, server) = start_server(&blocks, ProviderMode::Qualified, Duration::from_secs(45));
    let (options, config) = options_and_config(&root, address, checkpoint, Duration::from_secs(40));
    let report = crate::sync::run_with_swift(&Network::Regtest.params(), &config, options, |_| {})
        .expect("qualified Swift sync");
    assert!(report.target_reached, "{report:?}");
    assert_eq!(report.connected_height, CHECKPOINT_HEIGHT);
    assert!(
        server.join().unwrap(),
        "qualified peer must receive getbspent"
    );
    assert_promoted(&root, &blocks);

    // No BIP455 advertisement must select the ordinary validator. It still
    // reaches the same tip, but it cannot use a helper-only acceptance path.
    let root = TempTree::new("fallback");
    std::fs::write(root.path("checkpoint.hints"), hints_bytes()).unwrap();
    let (address, server) = start_server(&blocks, ProviderMode::NoBip455, Duration::from_secs(45));
    let (options, config) = options_and_config(&root, address, checkpoint, Duration::from_secs(40));
    let report = crate::sync::run_with_swift(&Network::Regtest.params(), &config, options, |_| {})
        .expect("ordinary fallback sync");
    assert!(report.target_reached, "{report:?}");
    assert!(
        !server.join().unwrap(),
        "unqualified peer must not receive getbspent"
    );
    assert_promoted(&root, &blocks);

    // A provider that lies about the spent coin forces fallback. It then stops
    // serving bodies, so this bounded run must leave the ordinary tip below
    // the target and must not publish the provisional Swift checkpoint.
    let root = TempTree::new("bad-claim");
    std::fs::write(root.path("checkpoint.hints"), hints_bytes()).unwrap();
    let (address, server) =
        start_server(&blocks, ProviderMode::BadSpentClaim, Duration::from_secs(5));
    let (options, config) = options_and_config(&root, address, checkpoint, Duration::from_secs(3));
    let report = crate::sync::run_with_swift(&Network::Regtest.params(), &config, options, |_| {})
        .expect("bounded fallback report");
    assert!(
        !report.target_reached,
        "dishonest helper published target: {report:?}"
    );
    assert!(
        server.join().unwrap(),
        "dishonest peer must receive getbspent"
    );
    let promoted = root.path("promoted");
    if promoted.exists() {
        let reopened =
            Chainstate::with_store_coinsdb(&promoted, &Network::Regtest.params(), NOW, 8 << 20)
                .unwrap();
        assert_ne!(reopened.tip_hash(), checkpoint);
    }
    let target_display = checkpoint.to_string();
    assert_ne!(report.tip.as_deref(), Some(target_display.as_str()));
}
