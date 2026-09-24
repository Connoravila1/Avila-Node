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
    /// Core's `ChainTypeToString` — the `chain`/`network` string every
    /// RPC reports: `"main"`, `"testnet4"`, `"signet"`, `"regtest"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "main",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// Every built-in network — `GetNetworkForMagic`'s domain for
    /// snapshot-metadata network checks.
    #[must_use]
    pub fn all() -> [Network; 4] {
        [
            Network::Mainnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ]
    }

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
                // Core v31.1: defaultAssumeValid, height 938343.
                assume_valid: BlockHash::from_str(
                    "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",
                )
                .ok(),
                message_start: [0xf9, 0xbe, 0xb4, 0xd9],
                default_port: 8333,
                base58_pubkey_prefix: 0x00,
                base58_script_prefix: 0x05,
                base58_secret_prefix: 0x80,
                base58_ext_pubkey_prefix: [0x04, 0x88, 0xb2, 0x1e],
                base58_ext_secret_prefix: [0x04, 0x88, 0xad, 0xe4],
                bech32_hrp: "bc",
                dns_seeds: &[
                    "seed.bitcoin.sipa.be",
                    "dnsseed.bluematt.me",
                    "seed.bitcoin.jonasschnelli.ch",
                    "seed.btc.petertodd.net",
                    "seed.bitcoin.sprovoost.nl",
                    "dnsseed.emzy.de",
                    "seed.bitcoin.wiz.biz",
                    "seed.mainnet.achownodes.xyz",
                ],
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
                rule_change_activation_threshold: 1815,
                bip9_deployments: [
                    Bip9Deployment {
                        name: "testdummy",
                        bit: 28,
                        start_time: BIP9_NEVER_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                    Bip9Deployment {
                        name: "taproot",
                        bit: 2,
                        start_time: 1_619_222_400,
                        timeout: 1_628_640_000,
                        min_activation_height: 709_632,
                    },
                ],
                assumeutxo_data: &[
                    AssumeutxoData {
                        height: 840_000,
                        hash_serialized: "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
                        n_chain_tx: 991_032_194,
                        blockhash: "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
                    },
                    AssumeutxoData {
                        height: 880_000,
                        hash_serialized: "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
                        n_chain_tx: 1_145_604_538,
                        blockhash: "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
                    },
                    AssumeutxoData {
                        height: 910_000,
                        hash_serialized: "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
                        n_chain_tx: 1_226_586_151,
                        blockhash: "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
                    },
                    AssumeutxoData {
                        height: 935_000,
                        hash_serialized: "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
                        n_chain_tx: 1_305_397_408,
                        blockhash: "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
                    },
                ],
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
                // Core v31.1: defaultAssumeValid, height 123613.
                assume_valid: BlockHash::from_str(
                    "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",
                )
                .ok(),
                message_start: [0x1c, 0x16, 0x3f, 0x28],
                default_port: 48333,
                base58_pubkey_prefix: 0x6f,
                base58_script_prefix: 0xc4,
                base58_secret_prefix: 0xef,
                base58_ext_pubkey_prefix: [0x04, 0x35, 0x87, 0xcf],
                base58_ext_secret_prefix: [0x04, 0x35, 0x83, 0x94],
                bech32_hrp: "tb",
                dns_seeds: &[
                    "seed.testnet4.bitcoin.sprovoost.nl",
                    "seed.testnet4.wiz.biz",
                ],
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
                rule_change_activation_threshold: 1512,
                bip9_deployments: [
                    Bip9Deployment {
                        name: "testdummy",
                        bit: 28,
                        start_time: BIP9_NEVER_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                    Bip9Deployment {
                        name: "taproot",
                        bit: 2,
                        start_time: BIP9_ALWAYS_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                ],
                // Core v31.1 `CTestNet4Params::m_assumeutxo_data`.
                assumeutxo_data: &[
                    AssumeutxoData {
                        height: 90_000,
                        hash_serialized: "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5",
                        n_chain_tx: 11_347_043,
                        blockhash: "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b",
                    },
                    AssumeutxoData {
                        height: 120_000,
                        hash_serialized: "10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0",
                        n_chain_tx: 14_141_057,
                        blockhash: "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8",
                    },
                ],
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
                // Core v31.1: defaultAssumeValid, height 293175.
                assume_valid: BlockHash::from_str(
                    "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329",
                )
                .ok(),
                message_start: [0x0a, 0x03, 0xcf, 0x40],
                default_port: 38333,
                base58_pubkey_prefix: 0x6f,
                base58_script_prefix: 0xc4,
                base58_secret_prefix: 0xef,
                base58_ext_pubkey_prefix: [0x04, 0x35, 0x87, 0xcf],
                base58_ext_secret_prefix: [0x04, 0x35, 0x83, 0x94],
                bech32_hrp: "tb",
                dns_seeds: &[
                    "seed.signet.bitcoin.sprovoost.nl",
                    "seed.signet.achownodes.xyz",
                ],
                bip34_height: 1,
                bip66_height: 1,
                bip65_height: 1,
                csv_height: 1,
                segwit_height: 1,
                taproot_height: 0,
                subsidy_halving_interval: 210_000,
                bip34_hash: None,
                script_flag_exceptions: &[],
                rule_change_activation_threshold: 1815,
                bip9_deployments: [
                    Bip9Deployment {
                        name: "testdummy",
                        bit: 28,
                        start_time: BIP9_NEVER_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                    Bip9Deployment {
                        name: "taproot",
                        bit: 2,
                        start_time: BIP9_ALWAYS_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                ],
                assumeutxo_data: &[
                    AssumeutxoData {
                        height: 160_000,
                        hash_serialized: "fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a",
                        n_chain_tx: 2_289_496,
                        blockhash: "0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c",
                    },
                    AssumeutxoData {
                        height: 290_000,
                        hash_serialized: "97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545",
                        n_chain_tx: 28_547_497,
                        blockhash: "0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0",
                    },
                ],
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
                message_start: [0xfa, 0xbf, 0xb5, 0xda],
                default_port: 18444,
                base58_pubkey_prefix: 0x6f,
                base58_script_prefix: 0xc4,
                base58_secret_prefix: 0xef,
                base58_ext_pubkey_prefix: [0x04, 0x35, 0x87, 0xcf],
                base58_ext_secret_prefix: [0x04, 0x35, 0x83, 0x94],
                bech32_hrp: "bcrt",
                dns_seeds: &[],
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
                rule_change_activation_threshold: 108,
                bip9_deployments: [
                    Bip9Deployment {
                        name: "testdummy",
                        bit: 28,
                        start_time: 0,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                    Bip9Deployment {
                        name: "taproot",
                        bit: 2,
                        start_time: BIP9_ALWAYS_ACTIVE,
                        timeout: BIP9_NO_TIMEOUT,
                        min_activation_height: 0,
                    },
                ],
                assumeutxo_data: &[
                    // For use by unit tests.
                    AssumeutxoData {
                        height: 110,
                        hash_serialized: "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1",
                        n_chain_tx: 111,
                        blockhash: "696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c",
                    },
                    // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp.
                    AssumeutxoData {
                        height: 200,
                        hash_serialized: "4f34d431c3e482f6b0d67b64609ece3964dc8d7976d02ac68dd7c9c1421738f2",
                        n_chain_tx: 201,
                        blockhash: "5e93653318f294fb5aa339d00bbf8cf1c3515488ad99412c37608b139ea63b27",
                    },
                    // For use by test/functional/feature_assumeutxo.py.
                    AssumeutxoData {
                        height: 299,
                        hash_serialized: "a4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27",
                        n_chain_tx: 334,
                        blockhash: "3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0",
                    },
                ],
                genesis_header: REGTEST_GENESIS,
            },
        }
    }
}

/// One `m_assumeutxo_data` entry — a `loadtxoutset`-acceptable snapshot
/// point: the base block, its expected `hash_serialized_3` UTXO-set
/// digest, and the `nChainTx` Core stamps on the base index entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssumeutxoData {
    /// `AssumeutxoData::height` — the snapshot base block's height.
    pub height: u32,
    /// `hash_serialized` — display-order hex of the expected
    /// `hash_serialized_3` digest over the snapshot's coins.
    pub hash_serialized: &'static str,
    /// `m_chain_tx_count` — `nChainTx` for the base block.
    pub n_chain_tx: u64,
    /// `blockhash` — display-order hex of the base block's hash.
    pub blockhash: &'static str,
}

/// One `consensus.vDeployments` entry — a BIP9 versionbits deployment
/// position. Core ships two: `testdummy` (bit 28) and `taproot` (bit 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bip9Deployment {
    /// `VersionBitsDeploymentInfo[].name` — the `deployments` key in
    /// `getdeploymentinfo`.
    pub name: &'static str,
    /// `vDeployments[].bit`.
    pub bit: i32,
    /// `vDeployments[].nStartTime`: `-1` = `ALWAYS_ACTIVE`,
    /// `-2` = `NEVER_ACTIVE`.
    pub start_time: i64,
    /// `vDeployments[].nTimeout`; `i64::MAX` = `NO_TIMEOUT`.
    pub timeout: i64,
    /// `vDeployments[].min_activation_height`.
    pub min_activation_height: u32,
}

/// `Consensus::BIP9Deployment::ALWAYS_ACTIVE` — the `nStartTime` sentinel
/// for deployments active from genesis.
pub const BIP9_ALWAYS_ACTIVE: i64 = -1;
/// `Consensus::BIP9Deployment::NEVER_ACTIVE` — the `nStartTime` sentinel
/// for deployments that can never activate.
pub const BIP9_NEVER_ACTIVE: i64 = -2;
/// `Consensus::BIP9Deployment::NO_TIMEOUT` — the `nTimeout` sentinel.
pub const BIP9_NO_TIMEOUT: i64 = i64::MAX;

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
    /// The network's `pchMessageStart` — the 4-byte magic prefixing every P2P
    /// message and every `blk*.dat` frame. [`crate::store::BlockStore`] writes
    /// and scans frames by it.
    pub message_start: [u8; 4],
    /// `nDefaultPort` — the network's standard P2P port (8333 mainnet,
    /// 48333 testnet4, 38333 signet, 18444 regtest).
    pub default_port: u16,
    /// `vSeeds` — DNS seed hostnames for peer bootstrap. Empty on regtest
    /// (Core ships a dummy seed and disables seeding entirely).
    pub dns_seeds: &'static [&'static str],
    /// `base58Prefixes[PUBKEY_ADDRESS]` — the version byte on base58check
    /// pay-to-pubkey-hash addresses (0x00 mainnet, 0x6f elsewhere).
    pub base58_pubkey_prefix: u8,
    /// `base58Prefixes[SCRIPT_ADDRESS]` — the version byte on base58check
    /// pay-to-script-hash addresses (0x05 mainnet, 0xc4 elsewhere).
    pub base58_script_prefix: u8,
    /// `base58Prefixes[SECRET_KEY]` — the version byte on WIF private
    /// keys (0x80 mainnet, 0xef elsewhere).
    pub base58_secret_prefix: u8,
    /// `base58Prefixes[EXT_PUBLIC_KEY]` — the four version bytes on
    /// BIP32 extended public keys (xpub / tpub).
    pub base58_ext_pubkey_prefix: [u8; 4],
    /// `base58Prefixes[EXT_SECRET_KEY]` — the four version bytes on
    /// BIP32 extended private keys (xprv / tprv).
    pub base58_ext_secret_prefix: [u8; 4],
    /// `bech32_hrp` — the human-readable part of segwit addresses
    /// (`bc`, `tb`, `tb`, `bcrt`).
    pub bech32_hrp: &'static str,
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
    /// `consensus.nRuleChangeActivationThreshold` — the BIP9 signalling
    /// threshold (1815 mainnet/signet, 1512 testchains, 108 regtest).
    /// The BIP9 period is [`Self::difficulty_adjustment_interval`]
    /// (`nMinerConfirmationWindow = nPowTargetTimespan/nPowTargetSpacing`
    /// on every built-in network).
    pub rule_change_activation_threshold: u32,
    /// `consensus.vDeployments` — the BIP9 positions Core ships, in
    /// `DeploymentInfo` order: `testdummy` then `taproot`.
    pub bip9_deployments: [Bip9Deployment; 2],
    /// `m_assumeutxo_data` — the snapshot points `loadtxoutset` accepts
    /// and `dumptxoutset rollback` (without an explicit target) rolls
    /// back to. Hashes are display-hex strings parsed at the call site
    /// (Core stores them as `uint256` constants).
    pub assumeutxo_data: &'static [AssumeutxoData],
    /// The network's genesis block header: the anchor every [`crate::chain::HeaderTree`]
    /// is seeded with.
    pub genesis_header: BlockHeader,
}

impl Params {
    /// The genesis block — `genesis_header` over the single coinbase
    /// transaction Core's `CreateGenesisBlock` produces: every network
    /// shares the `push(486604799) << push(4) << push(msg)` scriptSig
    /// shape, but the message and output script are per-network
    /// (`CreateGenesisBlock`'s first two arguments). Serving it from
    /// params lets RPC answer `getblock`/stats for height 0 like Core,
    /// whose blk files always contain the genesis body.
    ///
    /// `None` when the reconstructed body doesn't anchor
    /// `genesis_header`'s merkle root — i.e. a custom [`Params`] whose
    /// genesis coinbase isn't one of Core's built-in recipes.
    #[must_use]
    pub fn genesis_block(&self) -> Option<crate::block::Block> {
        use crate::script::{self, push_slice};
        use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
        const HEADLINE: &[u8] =
            b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        // `chainparams.cpp`'s `testnet4_genesis_msg`.
        const TESTNET4_MSG: &[u8] =
            b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
        // The fixed 65-byte pubkey main/testnet3/signet/regtest pay to.
        const GENESIS_PUBKEY: [u8; 65] = [
            0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71,
            0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0,
            0xea, 0x1f, 0x61, 0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3,
            0x55, 0x04, 0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d,
            0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f,
        ];
        let (message, script_pubkey) = match self.network {
            // testnet4: `<< <33 zero bytes> << OP_CHECKSIG` — Core's
            // `"0000…00"_hex` literal is 33 bytes, not 32.
            Network::Testnet4 => (
                TESTNET4_MSG,
                [&push_slice(&[0u8; 33])[..], &[script::OP_CHECKSIG]].concat(),
            ),
            _ => (
                HEADLINE,
                [&push_slice(&GENESIS_PUBKEY)[..], &[script::OP_CHECKSIG]].concat(),
            ),
        };
        // scriptSig: `<< 486604799 << CScriptNum(4) << message` — the
        // 486604799 literal is mainnet's nBits and Core hardcodes it for
        // every network, including regtest. `CScript << CScriptNum` is a
        // *data* push of the serialized number (01 04), not `OP_4`.
        let mut script_sig = push_slice(&0x1d00_ffffu32.to_le_bytes());
        script_sig.extend_from_slice(&push_slice(&[0x04]));
        script_sig.extend_from_slice(&push_slice(message));
        let block = crate::block::Block {
            header: self.genesis_header,
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::NULL,
                    script_sig: Script::new(script_sig),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: 5_000_000_000,
                    script_pubkey: Script::new(script_pubkey),
                }],
                lock_time: 0,
            }],
        };
        let (root, mutated) = block.merkle_root();
        (!mutated && root == block.header.merkle_root).then_some(block)
    }

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
/// `7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e`.
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

/// `consensus.nMinimumChainWork` for mainnet (Core v31.1 `kernel/chainparams.cpp`):
/// `uint256{"0000000000000000000000000000000000000001128750f82f4c366153a3a030"}`.
const MINIMUM_CHAIN_WORK_MAINNET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x12, 0x87, 0x50, 0xf8, 0x2f,
    0x4c, 0x36, 0x61, 0x53, 0xa3, 0xa0, 0x30,
];

/// `consensus.nMinimumChainWork` for testnet4 (Core v31.1):
/// `uint256{"0000000000000000000000000000000000000000000009a0fe15d0177d086304"}`.
const MINIMUM_CHAIN_WORK_TESTNET4: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0xa0, 0xfe, 0x15, 0xd0,
    0x17, 0x7d, 0x08, 0x63, 0x04,
];

/// `consensus.nMinimumChainWork` for the default signet (Core v31.1):
/// `uint256{"00000000000000000000000000000000000000000000000000000b463ea0a4b8"}`.
const MINIMUM_CHAIN_WORK_SIGNET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0x46, 0x3e,
    0xa0, 0xa4, 0xb8,
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

    /// `kernel/chainparams.cpp`'s `nMinimumChainWork` and
    /// `defaultAssumeValid` (Core v31.1), transcribed per network.
    /// These are pure data with nothing else to exercise the exact
    /// values, so a stale transcription after a Core version bump
    /// would otherwise go unnoticed.
    #[test]
    fn minimum_chain_work_and_assume_valid_match_core_v31_1() {
        assert_eq!(
            Network::Mainnet.params().minimum_chain_work.0.to_hex(),
            "0000000000000000000000000000000000000001128750f82f4c366153a3a030"
        );
        assert_eq!(
            Network::Mainnet.params().assume_valid.unwrap().to_string(),
            "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
        );
        assert_eq!(
            Network::Testnet4.params().minimum_chain_work.0.to_hex(),
            "0000000000000000000000000000000000000000000009a0fe15d0177d086304"
        );
        assert_eq!(
            Network::Testnet4.params().assume_valid.unwrap().to_string(),
            "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"
        );
        assert_eq!(
            Network::Signet.params().minimum_chain_work.0.to_hex(),
            "00000000000000000000000000000000000000000000000000000b463ea0a4b8"
        );
        assert_eq!(
            Network::Signet.params().assume_valid.unwrap().to_string(),
            "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"
        );
    }

    /// `m_assumeutxo_data` (Core v31.1): testnet4 ships two snapshot
    /// points — the table used to be transcribed empty — and signet's
    /// higher second point (290,000) is present alongside the first.
    #[test]
    fn assumeutxo_tables_match_core_v31_1() {
        let t4 = Network::Testnet4.params();
        let t4_heights: Vec<u32> = t4.assumeutxo_data.iter().map(|d| d.height).collect();
        assert_eq!(t4_heights, [90_000, 120_000]);

        let signet = Network::Signet.params();
        let signet_heights: Vec<u32> = signet.assumeutxo_data.iter().map(|d| d.height).collect();
        assert_eq!(signet_heights, [160_000, 290_000]);

        let mainnet = Network::Mainnet.params();
        let mainnet_heights: Vec<u32> = mainnet.assumeutxo_data.iter().map(|d| d.height).collect();
        assert_eq!(mainnet_heights, [840_000, 880_000, 910_000, 935_000]);
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

    /// The synthesized genesis body must hash to `genesis_header`'s own
    /// merkle root, making the block hash equal the genesis hash on every
    /// network. The mainnet txid/blockhash constants are the well-known
    /// values; the regtest pair is what Core's `getblock 0` serves.
    #[test]
    fn genesis_block_hashes_to_header_on_every_network() {
        for network in [
            Network::Mainnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let params = network.params();
            let block = params
                .genesis_block()
                .unwrap_or_else(|| panic!("{network:?} genesis"));
            assert_eq!(block.transactions.len(), 1);
            let (root, mutated) = block.merkle_root();
            assert!(!mutated);
            assert_eq!(
                root, block.header.merkle_root,
                "{network:?} genesis coinbase must anchor the header"
            );
            assert_eq!(block.header.hash(), params.genesis_header.hash());
        }
        let mainnet = Network::Mainnet.params().genesis_block().unwrap();
        assert_eq!(
            mainnet.transactions[0].txid().to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(
            mainnet.header.hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        let regtest = Network::Regtest.params().genesis_block().unwrap();
        assert_eq!(
            regtest.encode(),
            crate::hex::decode(concat!(
                "0100000000000000000000000000000000000000000000000000000000000000",
                "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
                "4b1e5e4adae5494dffff7f200200000001010000000100000000000000000000",
                "00000000000000000000000000000000000000000000ffffffff4d04ffff001d",
                "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c",
                "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066",
                "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554827",
                "1967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4",
                "f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
            ))
            .unwrap()
        );
    }
}
