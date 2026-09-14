//! Per-network consensus parameters: proof-of-work limits, the retarget schedule,
//! difficulty-relaxation flags, and each network's genesis header.
//!
//! Mirrors the subset of Bitcoin Core's `Consensus::Params` (`consensus/params.h`) that
//! header-chain validation needs, transcribed from `kernel/chainparams.cpp` for mainnet,
//! testnet4, signet and regtest. The genesis headers are Core's `CreateGenesisBlock` results;
//! each is cross-checked against its network's canonical hash in this module's tests (and,
//! for the three public networks, against the committed real-chain fixtures).

use std::str::FromStr;

use crate::arith::{CompactTarget, Target, U256, Work};
use crate::hash::{BlockHash, MerkleRoot};
use crate::header::BlockHeader;

/// The four Bitcoin networks this crate carries parameters for (Core's `CBaseChainParams`
/// network names: `"main"`, `"testnet4"`, `"signet"`, `"regtest"`; obsolete testnet3 is
/// deliberately omitted).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// The public test network (testnet4, `testnet4` in Core 28+).
    Testnet4,
    /// The default public signet (BIP325).
    Signet,
    /// Local regression-test network: trivial proof-of-work limit and no retargeting.
    Regtest,
}

impl Network {
    /// Returns this network's consensus parameters (Core's `CreateChainParams` /
    /// `ChainParamsFromNetwork`).
    #[must_use]
    pub fn params(self) -> Params {
        match self {
            Network::Mainnet => Params {
                network: self,
                // uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                pow_limit: pow_limit_mainnet(),
                pow_target_spacing: 10 * 60,
                pow_target_timespan: 14 * 24 * 60 * 60,
                allow_min_difficulty_blocks: false,
                enforce_bip94: false,
                no_retargeting: false,
                signet_blocks: false,
                signet_challenge: &[],
                // kernel/chainparams.cpp: uint256{...} values, in display hex.
                minimum_chain_work: Work(U256::from_be_bytes(MINIMUM_CHAIN_WORK_MAINNET)),
                assume_valid: BlockHash::from_str(
                    "00000000000000000001b658dd1120e82e66d2790811f89ede9742ada3ed6d77",
                )
                .ok(),
                // kernel/chainparams.cpp buried-deployment heights; cross-checked against
                bip34_height: 227_931,
                bip66_height: 363_725,
                bip65_height: 388_381,
                csv_height: 419_328,
                segwit_height: 481_824,
                taproot_height: 709_632,
                subsidy_halving_interval: 210_000,
                // uint256S("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8")
                bip34_hash: Some(BlockHash::from_bytes(MAINNET_BIP34_HASH)),
                script_flag_exceptions: &MAINNET_SCRIPT_FLAG_EXCEPTIONS,
                genesis_header: MAINNET_GENESIS,
            },
            Network::Testnet4 => Params {
                network: self,
                pow_limit: pow_limit_mainnet(),
                pow_target_spacing: 10 * 60,
                pow_target_timespan: 14 * 24 * 60 * 60,
                allow_min_difficulty_blocks: true,
                enforce_bip94: true,
                no_retargeting: false,
                signet_blocks: false,
                signet_challenge: &[],
                minimum_chain_work: Work(U256::from_be_bytes(MINIMUM_CHAIN_WORK_TESTNET4)),
                assume_valid: BlockHash::from_str(
                    "0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3",
                )
                .ok(),
                // Every buried deployment activates at height 1 on testnet4; segwit is
                bip34_height: 1,
                bip66_height: 1,
                bip65_height: 1,
                csv_height: 1,
                segwit_height: 1,
                taproot_height: 0,
                subsidy_halving_interval: 210_000,
                bip34_hash: None,
                script_flag_exceptions: &[],
                genesis_header: TESTNET4_GENESIS,
            },
            Network::Signet => Params {
                network: self,
                // uint256S("00000377ae000000000000000000000000000000000000000000000000000000")
                pow_limit: pow_limit_signet(),
                pow_target_spacing: 10 * 60,
                pow_target_timespan: 14 * 24 * 60 * 60,
                allow_min_difficulty_blocks: false,
                enforce_bip94: false,
                no_retargeting: false,
                signet_blocks: true,
                signet_challenge: &SIGNET_CHALLENGE,
                minimum_chain_work: Work(U256::from_be_bytes(MINIMUM_CHAIN_WORK_SIGNET)),
                assume_valid: BlockHash::from_str(
                    "000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a",
                )
                .ok(),
                bip34_height: 1,
                bip66_height: 1,
                bip65_height: 1,
                csv_height: 1,
                segwit_height: 1,
                taproot_height: 0,
                subsidy_halving_interval: 210_000,
                bip34_hash: None,
                script_flag_exceptions: &[],
                genesis_header: SIGNET_GENESIS,
            },
            Network::Regtest => Params {
                network: self,
                // uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                pow_limit: pow_limit_regtest(),
                pow_target_spacing: 10 * 60,
                // Regtest retargets daily (interval 144), not fortnightly — Core
                // `CRegTestParams` sets `nPowTargetTimespan` to one day.
                pow_target_timespan: 24 * 60 * 60,
                allow_min_difficulty_blocks: true,
                // Core's regtest takes `enforce_BIP94` from `RegTestOptions`; the default
                // (`RegTestOptions{}`) is false.
                enforce_bip94: false,
                no_retargeting: true,
                signet_blocks: false,
                signet_challenge: &[],
                // CRegTestParams leaves both zero.
                minimum_chain_work: Work::ZERO,
                assume_valid: None,
                // Core's regtest defaults bury BIP34/65/66/CSV at height 1 and activate
                bip34_height: 1,
                bip66_height: 1,
                bip65_height: 1,
                csv_height: 1,
                segwit_height: 0,
                taproot_height: 0,
                // Core's `CRegTestParams`: `nSubsidyHalvingInterval = 150`.
                subsidy_halving_interval: 150,
                bip34_hash: None,
                script_flag_exceptions: &[],
                genesis_header: REGTEST_GENESIS,
            },
        }
    }
}

/// Consensus parameters for one network (the header-relevant slice of Core's
/// `Consensus::Params`).
///
/// All fields are public so tests and tooling can construct custom networks; the four
/// built-in parameter sets are exposed through [`Network::params`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    /// The network these parameters describe.
    pub network: Network,
    /// `consensus.powLimit`: the highest target (easiest difficulty) a block may claim.
    ///
    /// This is Core's raw `uint256S(...)` value, *not* the largest compact-expressible
    /// target at or below it (what rust-bitcoin calls `max_attainable_target`). The two
    /// differ on mainnet and testnet4, where `powLimit` is `2^224 - 1` but its canonical
    /// compact encoding is `0x1d00ffff` (`0xffff << 208`). On every built-in network the
    /// distinction is unobservable — every `nBits` expansion has at most 23 significant
    /// bits and nothing in the gap has so few — but the raw value is kept for fidelity,
    /// and it *is* observable for custom [`Params`] with a laxer limit.
    pub pow_limit: Target,
    /// `consensus.nPowTargetSpacing`: the target block interval, in seconds (600 on every
    /// built-in network).
    pub pow_target_spacing: u64,
    /// `consensus.nPowTargetTimespan`: the retarget window length, in seconds (two weeks on
    /// the public networks, one day on regtest).
    pub pow_target_timespan: u64,
    /// `consensus.fPowAllowMinDifficultyBlocks`: the testnet-style rule allowing a block
    /// whose timestamp lags its parent's by more than twice the target spacing to carry
    /// the proof-of-work limit as its `nBits`.
    pub allow_min_difficulty_blocks: bool,
    /// `consensus.enforce_BIP94`: the testnet4 difficulty-period protections (BIP94):
    ///
    /// * at a retarget boundary the new `nBits` is computed from the *first* block of the
    ///   period just ended, not the last — so a minimum-difficulty block cannot drag the
    ///   next period's difficulty to the floor (the "block storm" fix); and
    /// * the first block of each period must have `nTime` no earlier than its parent's
    ///   `nTime` minus [`crate::rules::MAX_TIMEWARP`] (the timewarp-attack fix).
    ///
    /// `true` for testnet4. On regtest Core derives this from `RegTestOptions` (default
    /// `false`); these built-in parameters carry the default.
    pub enforce_bip94: bool,
    /// `consensus.fPowNoRetargeting`: difficulty adjustments are disabled entirely
    /// (regtest).
    pub no_retargeting: bool,
    /// `consensus.signet_blocks`: whether blocks carry a BIP325 signet solution that must
    /// satisfy the network's block challenge — enforced by
    /// [`crate::signet::check_signet_block_solution`] inside `check_block`.
    pub signet_blocks: bool,
    /// `consensus.signet_challenge`: the BIP325 block challenge script every
    /// post-genesis signet block's solution must satisfy. Empty on networks
    /// without signet blocks (`signet_challenge.clear()` in Core).
    pub signet_challenge: &'static [u8],
    /// `consensus.nMinimumChainWork`: the floor the best header chain's total
    /// work must reach before [`crate::chainstate`] may skip script checks
    /// under `assume_valid` (Core's `MinimumChainWork` guard in `ConnectBlock`).
    pub minimum_chain_work: Work,
    /// `consensus.defaultAssumeValid`: the externally-verified ancestor block
    /// below which script checks may be skipped — `None` where Core leaves it
    /// null (`uint256{}`), which disables the optimization entirely.
    pub assume_valid: Option<BlockHash>,
    /// `consensus.BIP34Height`: Core's `DEPLOYMENT_HEIGHTINCB` buried deployment (BIP34
    /// coinbase height enforcement). [`crate::chain::HeaderTree::insert`]'s `bad-version`
    /// check also uses this as the `nVersion < 2` floor's activation height, mirroring
    /// `DeploymentActiveAfter(pindexPrev, ..., DEPLOYMENT_HEIGHTINCB)` in Core's
    /// `ContextualCheckBlockHeader` (`validation.cpp`): a candidate block at height `h`
    /// (`pindexPrev->nHeight + 1`) is governed once `h >= bip34_height`.
    pub bip34_height: u32,
    /// `consensus.BIP66Height`: Core's `DEPLOYMENT_DERSIG` buried deployment (BIP66 strict
    /// DER signatures). Also the `bad-version` check's `nVersion < 3` floor's activation
    /// height.
    pub bip66_height: u32,
    /// `consensus.BIP65Height`: Core's `DEPLOYMENT_CLTV` buried deployment (BIP65
    /// `OP_CHECKLOCKTIMEVERIFY`). Also the `bad-version` check's `nVersion < 4` floor's
    /// activation height.
    pub bip65_height: u32,
    /// `consensus.CSVHeight`: Core's `DEPLOYMENT_CSV` buried deployment (BIP68/112/113:
    /// relative lock time, `OP_CHECKSEQUENCEVERIFY`, and the median-time-past `nLockTime`
    /// cutoff). [`crate::check::contextual_check_block`] consults it for the BIP113
    /// locktime cutoff; the relative-lock-time rules themselves are UTXO-dependent and
    /// not yet implemented.
    pub csv_height: u32,
    /// `consensus.SegwitHeight`: Core's `DEPLOYMENT_SEGWIT` buried deployment
    /// (BIP141/143/147, segregated witness). [`crate::check::contextual_check_block`]
    /// consults it for the witness-commitment rules; the witness program/script rules
    /// themselves are UTXO-dependent and not yet implemented.
    pub segwit_height: u32,
    /// Taproot's (BIP340-342) buried activation height: Core's `DEPLOYMENT_TAPROOT`
    /// versionbits deployment's `min_activation_height` (`709632` on mainnet). On
    /// testnet4, signet and regtest the deployment starts `ALWAYS_ACTIVE`, which Core
    /// records as `min_activation_height = 0` — so `0` here means "active from genesis",
    /// not "never active". Unlike the buried heights above, Core still tracks Taproot's
    /// *true* activation through versionbits signaling state (`VersionBitsCache`), not
    /// this height alone; not consulted by any rule this crate implements — carried for
    /// documentation and G2.
    pub taproot_height: u32,
    /// `consensus.nSubsidyHalvingInterval`: the number of blocks per subsidy halving
    /// (210,000 on the public networks, 150 on regtest). Consulted by
    /// [`crate::connect::block_subsidy`].
    pub subsidy_halving_interval: u32,
    /// `consensus.BIP34Hash`: the block hash expected at `bip34_height` on the real
    /// chain. `ConnectBlock` uses it to skip the BIP30 duplicate-output scan once the
    /// known chain has passed BIP34 activation; `None` reproduces Core's null
    /// `uint256` on networks where the optimization can never trigger (testnet4,
    /// signet, regtest — no real chain exists to match).
    pub bip34_hash: Option<BlockHash>,
    /// `consensus.script_flag_exceptions`: block hashes whose script-verification
    /// flags *replace* the always-on base set (P2SH | WITNESS | TAPROOT) before the
    /// deployment-gated bits are OR'd in — Core's `GetBlockScriptFlags`. Mainnet has
    /// two: the historical BIP16 violation (`SCRIPT_VERIFY_NONE`) and the taproot
    /// exception block (`P2SH | WITNESS`, dropping TAPROOT). Consulted by
    /// [`crate::script::block_script_flags`]; the stored values are raw
    /// `script/interpreter.h` flag bits.
    pub script_flag_exceptions: &'static [(BlockHash, u32)],
    /// The network's genesis block header: the anchor every [`crate::chain::HeaderTree`]
    /// is seeded with.
    pub genesis_header: BlockHeader,
}

impl Params {
    /// `consensus.DifficultyAdjustmentInterval()`: `nPowTargetTimespan / nPowTargetSpacing`
    /// (2016 on every built-in network).
    ///
    /// `0` if `pow_target_spacing` exceeds `pow_target_timespan` (or is itself `0`) — a
    /// degenerate combination no built-in network uses; [`crate::pow::required_bits`]
    /// rejects such parameters rather than panicking on the division's downstream uses.
    #[must_use]
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan
            .checked_div(self.pow_target_spacing)
            .unwrap_or(0)
    }

    /// The canonical compact (`nBits`) encoding of [`Params::pow_limit`], i.e. Core's
    /// `UintToArith256(params.powLimit).GetCompact()` — the value the minimum-difficulty
    /// rule compares against and `GetNextWorkRequired` returns for genesis/min-difficulty
    /// blocks.
    #[must_use]
    pub fn pow_limit_compact(&self) -> CompactTarget {
        self.pow_limit.to_compact()
    }
}

/// `consensus.powLimit` for mainnet and testnet4:
/// `uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")`.
fn pow_limit_mainnet() -> Target {
    let mut bytes = [0xffu8; 32];
    bytes[0] = 0;
    bytes[1] = 0;
    bytes[2] = 0;
    bytes[3] = 0;
    Target(U256::from_be_bytes(bytes))
}

/// `consensus.powLimit` for the default signet:
/// `uint256S("00000377ae000000000000000000000000000000000000000000000000000000")`.
fn pow_limit_signet() -> Target {
    let mut bytes = [0u8; 32];
    bytes[2] = 0x03;
    bytes[3] = 0x77;
    bytes[4] = 0xae;
    Target(U256::from_be_bytes(bytes))
}

/// `consensus.powLimit` for regtest:
/// `uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")`.
fn pow_limit_regtest() -> Target {
    let mut bytes = [0xffu8; 32];
    bytes[0] = 0x7f;
    Target(U256::from_be_bytes(bytes))
}

/// The merkle root shared by the mainnet, signet and regtest genesis blocks (they all embed
/// the same genesis coinbase transaction), in wire (internal) byte order: display form
/// `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`.
const SHARED_GENESIS_MERKLE_ROOT: MerkleRoot = MerkleRoot::from_bytes([
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
]);

/// The testnet4 genesis merkle root in wire byte order: display form
/// `7aa0a7ae1e22340ecb807ecde657e667b718e42aaf9306db9102fe28912b7b4e`.
const TESTNET4_GENESIS_MERKLE_ROOT: MerkleRoot = MerkleRoot::from_bytes([
    0x4e, 0x7b, 0x2b, 0x91, 0x28, 0xfe, 0x02, 0x91, 0xdb, 0x06, 0x93, 0xaf, 0x2a, 0xe4, 0x18, 0xb7,
    0x67, 0xe6, 0x57, 0xcd, 0x40, 0x7e, 0x80, 0xcb, 0x14, 0x34, 0x22, 0x1e, 0xae, 0xa7, 0xa0, 0x7a,
]);

/// `CMainParams`'s `consensus.BIP34Hash` in wire byte order: display form
/// `000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8`.
const MAINNET_BIP34_HASH: [u8; 32] = [
    0xb8, 0x08, 0x08, 0x9c, 0x75, 0x6a, 0xdd, 0x15, 0x91, 0xb1, 0xd1, 0x7b, 0xab, 0x44, 0xbb, 0xa3,
    0xfe, 0xd9, 0xe0, 0x2f, 0x94, 0x2a, 0xb4, 0x89, 0x4b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `CMainParams`'s `consensus.script_flag_exceptions`: (wire-order block hash,
/// `script/interpreter.h` flag bits). The first is the historical BIP16 violation
/// (`00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22` →
/// `SCRIPT_VERIFY_NONE`); the second is the taproot exception block
/// (`0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad` →
/// `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS` = 0x801).
const MAINNET_SCRIPT_FLAG_EXCEPTIONS: [(BlockHash, u32); 2] = [
    (
        BlockHash::from_bytes([
            0x22, 0x9c, 0x4f, 0xac, 0x88, 0xba, 0xb1, 0x94, 0xeb, 0x08, 0xf1, 0xa5, 0x28, 0xcc,
            0x30, 0x8d, 0xed, 0x23, 0x97, 0xf4, 0xf4, 0xeb, 0x6e, 0x75, 0xdc, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
        0,
    ),
    (
        BlockHash::from_bytes([
            0xad, 0x95, 0xe3, 0xa1, 0x5e, 0xe5, 0xff, 0xd5, 0x85, 0xc5, 0xe8, 0x1d, 0x44, 0xb5,
            0x6a, 0x98, 0x1e, 0x84, 0x2d, 0x5b, 0xc3, 0x14, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
        0x801,
    ),
];

/// The mainnet genesis block header (Core `CMainParams`'s `CreateGenesisBlock` result).
const MAINNET_GENESIS: BlockHeader = BlockHeader {
    version: 1,
    prev_block_hash: BlockHash::ZERO,
    merkle_root: SHARED_GENESIS_MERKLE_ROOT,
    time: 1_231_006_505,
    bits: CompactTarget(0x1d00_ffff),
    nonce: 2_083_236_893,
};

/// The testnet4 genesis block header (Core `TestNet4Params`).
const TESTNET4_GENESIS: BlockHeader = BlockHeader {
    version: 1,
    prev_block_hash: BlockHash::ZERO,
    merkle_root: TESTNET4_GENESIS_MERKLE_ROOT,
    time: 1_714_777_860,
    bits: CompactTarget(0x1d00_ffff),
    nonce: 393_743_547,
};

/// `consensus.nMinimumChainWork` for mainnet (Core `kernel/chainparams.cpp`):
/// `uint256{"0000000000000000000000000000000000000000b1f3b93b65b16d035a82be84"}`.
const MINIMUM_CHAIN_WORK_MAINNET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb1, 0xf3, 0xb9, 0x3b, 0x65, 0xb1,
    0x6d, 0x03, 0x5a, 0x82, 0xbe, 0x84,
];

/// `consensus.nMinimumChainWork` for testnet4:
/// `uint256{"0000000000000000000000000000000000000000000001d6dce8651b6094e4c1"}`.
const MINIMUM_CHAIN_WORK_TESTNET4: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xd6, 0xdc, 0xe8, 0x65,
    0x1b, 0x60, 0x94, 0xe4, 0xc1,
];

/// `consensus.nMinimumChainWork` for the default signet:
/// `uint256{"000000000000000000000000000000000000000000000000000002b517f3d1a1"}`.
const MINIMUM_CHAIN_WORK_SIGNET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x02, 0xb5,
    0x17, 0xf3, 0xd1, 0xa1,
];

/// The default signet's BIP325 block challenge (Core `kernel/chainparams.cpp`
/// `CChainParams::SigNet` — a 1-of-2 bare multisig:
/// `OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG`).
const SIGNET_CHALLENGE: [u8; 71] = [
    0x51, 0x21, 0x03, 0xad, 0x5e, 0x0e, 0xda, 0xd1, 0x8c, 0xb1, 0xf0, 0xfc, 0x0d, 0x28, 0xa3, 0xd4,
    0xf1, 0xf3, 0xe4, 0x45, 0x64, 0x03, 0x37, 0x48, 0x9a, 0xbb, 0x10, 0x40, 0x4f, 0x2d, 0x1e, 0x08,
    0x6b, 0xe4, 0x30, 0x21, 0x03, 0x59, 0xef, 0x50, 0x21, 0x96, 0x4f, 0xe2, 0x2d, 0x6f, 0x8e, 0x05,
    0xb2, 0x46, 0x3c, 0x95, 0x40, 0xce, 0x96, 0x88, 0x3f, 0xe3, 0xb2, 0x78, 0x76, 0x0f, 0x04, 0x8f,
    0x51, 0x89, 0xf2, 0xe6, 0xc4, 0x52, 0xae,
];

/// The default signet's genesis block header (Core `SigNetParams`).
const SIGNET_GENESIS: BlockHeader = BlockHeader {
    version: 1,
    prev_block_hash: BlockHash::ZERO,
    merkle_root: SHARED_GENESIS_MERKLE_ROOT,
    time: 1_598_918_400,
    bits: CompactTarget(0x1e03_77ae),
    nonce: 52_613_770,
};

/// The regtest genesis block header (Core `CRegTestParams`).
const REGTEST_GENESIS: BlockHeader = BlockHeader {
    version: 1,
    prev_block_hash: BlockHash::ZERO,
    merkle_root: SHARED_GENESIS_MERKLE_ROOT,
    time: 1_296_688_602,
    bits: CompactTarget(0x207f_ffff),
    nonce: 2,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MAINNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/mainnet-headers-000000-004031.bin");
    const TESTNET4_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/testnet4-headers-000000-004031.bin");
    const SIGNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/signet-headers-000000-002047.bin");

    #[test]
    fn params_match_core_chainparams_values() {
        for (network, interval, timespan) in [
            (Network::Mainnet, 2016u64, 14 * 24 * 60 * 60u64),
            (Network::Testnet4, 2016, 14 * 24 * 60 * 60),
            (Network::Signet, 2016, 14 * 24 * 60 * 60),
            // Regtest retargets daily: Core sets `nPowTargetTimespan` to one day.
            (Network::Regtest, 144, 24 * 60 * 60),
        ] {
            let params = network.params();
            assert_eq!(params.network, network);
            assert_eq!(params.difficulty_adjustment_interval(), interval);
            assert_eq!(params.pow_target_spacing, 10 * 60);
            assert_eq!(params.pow_target_timespan, timespan);
        }
    }

    #[test]
    fn pow_limits_match_core_chainparams_values() {
        assert_eq!(
            Network::Mainnet.params().pow_limit.0.to_hex(),
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            Network::Testnet4.params().pow_limit,
            Network::Mainnet.params().pow_limit
        );
        assert_eq!(
            Network::Signet.params().pow_limit.0.to_hex(),
            "00000377ae000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            Network::Regtest.params().pow_limit.0.to_hex(),
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn pow_limit_compact_is_the_canonical_nbits_limit() {
        assert_eq!(
            Network::Mainnet.params().pow_limit_compact(),
            CompactTarget(0x1d00_ffff)
        );
        assert_eq!(
            Network::Testnet4.params().pow_limit_compact(),
            CompactTarget(0x1d00_ffff)
        );
        assert_eq!(
            Network::Signet.params().pow_limit_compact(),
            CompactTarget(0x1e03_77ae)
        );
        assert_eq!(
            Network::Regtest.params().pow_limit_compact(),
            CompactTarget(0x207f_ffff)
        );
    }

    #[test]
    fn difficulty_relaxation_flags_match_core() {
        assert!(!Network::Mainnet.params().allow_min_difficulty_blocks);
        assert!(Network::Testnet4.params().allow_min_difficulty_blocks);
        assert!(!Network::Signet.params().allow_min_difficulty_blocks);
        assert!(Network::Regtest.params().allow_min_difficulty_blocks);
        assert!(!Network::Mainnet.params().no_retargeting);
        assert!(!Network::Testnet4.params().no_retargeting);
        assert!(!Network::Signet.params().no_retargeting);
        assert!(Network::Regtest.params().no_retargeting);
        // BIP94 is enforced on testnet4 only; regtest's option defaults off in Core.
        assert!(!Network::Mainnet.params().enforce_bip94);
        assert!(Network::Testnet4.params().enforce_bip94);
        assert!(!Network::Signet.params().enforce_bip94);
        assert!(!Network::Regtest.params().enforce_bip94);
    }

    /// `kernel/chainparams.cpp`'s buried-deployment heights (`BIP34Height`, `BIP66Height`,
    /// `BIP65Height`, `CSVHeight`, `SegwitHeight`, and Taproot's `min_activation_height`),
    /// transcribed per network.
    #[test]
    fn buried_deployment_heights_match_core_chainparams_values() {
        for (network, bip34, bip66, bip65, csv, segwit, taproot) in [
            (
                Network::Mainnet,
                227_931,
                363_725,
                388_381,
                419_328,
                481_824,
                709_632,
            ),
            (Network::Testnet4, 1, 1, 1, 1, 1, 0),
            (Network::Signet, 1, 1, 1, 1, 1, 0),
            (Network::Regtest, 1, 1, 1, 1, 0, 0),
        ] {
            let params = network.params();
            assert_eq!(params.bip34_height, bip34, "{network:?} bip34_height");
            assert_eq!(params.bip66_height, bip66, "{network:?} bip66_height");
            assert_eq!(params.bip65_height, bip65, "{network:?} bip65_height");
            assert_eq!(params.csv_height, csv, "{network:?} csv_height");
            assert_eq!(params.segwit_height, segwit, "{network:?} segwit_height");
            assert_eq!(params.taproot_height, taproot, "{network:?} taproot_height");
        }
    }

    /// The genesis constants must produce each network's canonical hash. For the public
    /// networks those hashes are additionally the first hash of each committed header
    /// fixture (see `fixtures/manifest.json`); regtest has no fixture, so its hash is
    /// asserted against the well-known literal.
    #[test]
    fn genesis_headers_hash_to_the_canonical_genesis_hashes() {
        let fixture_genesis = |bytes: &[u8]| BlockHeader::decode(&bytes[..80]).unwrap();
        for (params, expected, fixture_first) in [
            (
                Network::Mainnet.params(),
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                Some(fixture_genesis(MAINNET_HEADERS)),
            ),
            (
                Network::Testnet4.params(),
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
                Some(fixture_genesis(TESTNET4_HEADERS)),
            ),
            (
                Network::Signet.params(),
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
                Some(fixture_genesis(SIGNET_HEADERS)),
            ),
            (
                Network::Regtest.params(),
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                None,
            ),
        ] {
            let genesis = params.genesis_header;
            assert_eq!(genesis.hash().to_string(), expected);
            if let Some(from_fixture) = fixture_first {
                assert_eq!(
                    genesis, from_fixture,
                    "embedded genesis disagrees with the {} fixture",
                    expected
                );
            }
        }
    }

    /// Core's `powLimit` is a raw `uint256S` value, not necessarily compact-expressible.
    /// Pin the distinction: on mainnet `powLimit` is `2^224 - 1`, strictly above the
    /// expansion of its own canonical compact form.
    #[test]
    fn mainnet_pow_limit_is_not_compact_attainable() {
        let params = Network::Mainnet.params();
        let expanded = params.pow_limit_compact().expand();
        assert!(!expanded.negative && !expanded.overflow);
        assert!(expanded.value < params.pow_limit.0);
    }

    #[test]
    fn degenerate_spacing_yields_zero_interval() {
        let mut params = Network::Mainnet.params();
        params.pow_target_spacing = 0;
        assert_eq!(params.difficulty_adjustment_interval(), 0);
        params = Network::Mainnet.params();
        params.pow_target_spacing = params.pow_target_timespan + 1;
        assert_eq!(params.difficulty_adjustment_interval(), 0);
    }
}
