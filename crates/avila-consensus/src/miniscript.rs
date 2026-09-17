//! Miniscript — a port of Core's `script/miniscript.{h,cpp}`: the
//! fragment grammar, the `Type` property system, the sanity
//! analysis (`IsSane`/`IsNotSatisfiable`/`FindInsaneSub`), canonical
//! serialization (`ToString`), and script emission (`ToScript`).
//!
//! Keys are `usize` indices into a key table owned by the caller —
//! Core's `Key` is exactly that for descriptors (`KeyParser::m_keys`),
//! and the `KeyCtx`/`ScriptCtx` traits here are its `KeyParser` /
//! `ScriptMaker` halves.

/// `MiniscriptContext` — P2WSH (Segwit v0) or Tapscript.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsContext {
    P2wsh,
    Tapscript,
}

fn is_tapscript(ctx: MsContext) -> bool {
    ctx == MsContext::Tapscript
}

// ---- constants (consensus/policy limits, Core names) -------------

const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const MAX_PUBKEYS_PER_MULTI_A: usize = 999;
const MAX_OPS_PER_SCRIPT: u32 = 201;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE: u32 = 3600;
const MAX_STANDARD_P2WSH_STACK_ITEMS: u32 = 100;
const MAX_STACK_SIZE: u32 = 1000;
const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;
const WITNESS_SCALE_FACTOR: u32 = 4;
const TAPROOT_CONTROL_MAX_SIZE: u32 = 128 * 32 + 33;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

fn compact_size_len(n: u32) -> u32 {
    match n {
        0..=252 => 1,
        253..=0xffff => 3,
        _ => 5,
    }
}

/// `internal::MaxScriptSize`.
fn max_script_size(ctx: MsContext) -> u32 {
    if is_tapscript(ctx) {
        // Leaf scripts under Tapscript have no explicit limit; bound
        // by the maximum standard tx size with a fully padded witness.
        let tx_overhead = 4 + 4;
        let txin_no_witness = 36 + 4 + 1;
        let p2wsh_txout = 8 + 1 + 1 + 33;
        let body_leeway = (tx_overhead
            + compact_size_len(1)
            + txin_no_witness
            + compact_size_len(1)
            + p2wsh_txout)
            * WITNESS_SCALE_FACTOR
            + 2;
        let max_elem = 65; // BIP340 sig + sighash byte
        let tap_sat = compact_size_len(MAX_STACK_SIZE)
            + (compact_size_len(max_elem) + max_elem) * MAX_STACK_SIZE
            + compact_size_len(TAPROOT_CONTROL_MAX_SIZE)
            + TAPROOT_CONTROL_MAX_SIZE;
        let max_size = MAX_STANDARD_TX_WEIGHT - body_leeway - tap_sat;
        max_size - compact_size_len(max_size)
    } else {
        MAX_STANDARD_P2WSH_SCRIPT_SIZE
    }
}

// ---- Type ---------------------------------------------------------

/// `internal::Type` — the miniscript property bitmap.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Type(u32);

/// `operator""_mst`.
fn mst(s: &str) -> Type {
    let mut flags = 0u32;
    for c in s.bytes() {
        flags |= match c {
            b'B' => 1 << 0,
            b'V' => 1 << 1,
            b'K' => 1 << 2,
            b'W' => 1 << 3,
            b'z' => 1 << 4,
            b'o' => 1 << 5,
            b'n' => 1 << 6,
            b'd' => 1 << 7,
            b'u' => 1 << 8,
            b'e' => 1 << 9,
            b'f' => 1 << 10,
            b's' => 1 << 11,
            b'm' => 1 << 12,
            b'x' => 1 << 13,
            b'g' => 1 << 14,
            b'h' => 1 << 15,
            b'i' => 1 << 16,
            b'j' => 1 << 17,
            b'k' => 1 << 18,
            _ => unreachable!("unknown character in mst literal"),
        };
    }
    Type(flags)
}

impl Type {
    /// `operator|` — union of properties.
    fn union(self, other: Type) -> Type {
        Type(self.0 | other.0)
    }
    /// `operator&` — intersection.
    fn inter(self, other: Type) -> Type {
        Type(self.0 & other.0)
    }
    /// `operator<<` — self is a subtype of (has all properties of) `other`.
    fn has_all(self, other: Type) -> bool {
        other.0 & !self.0 == 0
    }
    /// `If` — self or the empty type.
    fn if_(self, cond: bool) -> Type {
        if cond { self } else { Type(0) }
    }
    fn any(self, s: &str) -> bool {
        self.inter(mst(s)) != Type(0)
    }
}

/// `internal::SanitizeType` — enforce the type/property invariants.
fn sanitize_type(e: Type) -> Type {
    let num = [mst("K"), mst("V"), mst("B"), mst("W")]
        .iter()
        .filter(|&&t| e.has_all(t))
        .count();
    if num == 0 {
        return Type(0);
    }
    debug_assert_eq!(num, 1);
    debug_assert!(!(e.has_all(mst("z")) && e.has_all(mst("o"))));
    debug_assert!(!(e.has_all(mst("n")) && e.has_all(mst("z"))));
    debug_assert!(!(e.has_all(mst("n")) && e.has_all(mst("W"))));
    debug_assert!(!(e.has_all(mst("V")) && e.has_all(mst("d"))));
    debug_assert!(!e.has_all(mst("K")) || e.has_all(mst("u")));
    debug_assert!(!(e.has_all(mst("V")) && e.has_all(mst("u"))));
    debug_assert!(!(e.has_all(mst("e")) && e.has_all(mst("f"))));
    debug_assert!(!e.has_all(mst("e")) || e.has_all(mst("d")), "type {e:?}");
    debug_assert!(!(e.has_all(mst("V")) && e.has_all(mst("e"))));
    debug_assert!(!(e.has_all(mst("d")) && e.has_all(mst("f"))));
    debug_assert!(!e.has_all(mst("V")) || e.has_all(mst("f")));
    debug_assert!(!e.has_all(mst("K")) || e.has_all(mst("s")));
    debug_assert!(!e.has_all(mst("z")) || e.has_all(mst("m")));
    e
}

// ---- Fragment -----------------------------------------------------

/// `miniscript::Fragment` — the node kinds; `AND_N`, `WRAP_T`,
/// `WRAP_L`, `WRAP_U` are sugar built from the core set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fragment {
    Just0,
    Just1,
    PkK,
    PkH,
    Older,
    After,
    Sha256,
    Ripemd160,
    Hash256,
    Hash160,
    WrapA,
    WrapS,
    WrapC,
    WrapD,
    WrapV,
    WrapJ,
    WrapN,
    AndV,
    AndB,
    OrB,
    OrC,
    OrD,
    OrI,
    AndOr,
    Thresh,
    Multi,
    MultiA,
}

// ---- Ops / StackSize / WitnessSize ---------------------------------

/// `internal::MaxInt` — a value that can be invalid.
type MaxInt = Option<u32>;

fn max_add(a: MaxInt, b: MaxInt) -> MaxInt {
    a.and_then(|x| b.map(|y| x.saturating_add(y)))
}

fn max_or(a: MaxInt, b: MaxInt) -> MaxInt {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(x.max(y)),
    }
}

/// `internal::Ops`.
#[derive(Clone, Copy, Debug)]
struct Ops {
    count: u32,
    sat: MaxInt,
    dsat: MaxInt,
}

/// `internal::SatInfo`.
#[derive(Clone, Copy, Debug)]
struct SatInfo {
    valid: bool,
    netdiff: i32,
    exec: i32,
}

impl SatInfo {
    const EMPTY: SatInfo = SatInfo {
        valid: false,
        netdiff: 0,
        exec: 0,
    };
    const ZERO: SatInfo = SatInfo {
        valid: true,
        netdiff: 0,
        exec: 0,
    };
    const PUSH: SatInfo = SatInfo {
        valid: true,
        netdiff: -1,
        exec: 0,
    };
    const HASH: SatInfo = SatInfo {
        valid: true,
        netdiff: 0,
        exec: 0,
    };
    const NOP: SatInfo = SatInfo {
        valid: true,
        netdiff: 0,
        exec: 0,
    };
    const IF: SatInfo = SatInfo {
        valid: true,
        netdiff: 1,
        exec: 1,
    };
    const BINARY_OP: SatInfo = SatInfo {
        valid: true,
        netdiff: 1,
        exec: 1,
    };
    const OP_DUP: SatInfo = SatInfo {
        valid: true,
        netdiff: -1,
        exec: 0,
    };
    const OP_EQUALVERIFY: SatInfo = SatInfo {
        valid: true,
        netdiff: 2,
        exec: 2,
    };
    const OP_EQUAL: SatInfo = SatInfo {
        valid: true,
        netdiff: 1,
        exec: 1,
    };
    const OP_SIZE: SatInfo = SatInfo {
        valid: true,
        netdiff: -1,
        exec: 0,
    };
    const OP_CHECKSIG: SatInfo = SatInfo {
        valid: true,
        netdiff: 1,
        exec: 1,
    };
    const OP_0NOTEQUAL: SatInfo = SatInfo {
        valid: true,
        netdiff: 0,
        exec: 0,
    };
    const OP_VERIFY: SatInfo = SatInfo {
        valid: true,
        netdiff: 1,
        exec: 1,
    };

    const fn ifdup(nonzero: bool) -> SatInfo {
        SatInfo {
            valid: true,
            netdiff: if nonzero { -1 } else { 0 },
            exec: 0,
        }
    }

    /// `operator|` — set union.
    fn union(self, other: SatInfo) -> SatInfo {
        if !self.valid {
            return other;
        }
        if !other.valid {
            return self;
        }
        SatInfo {
            valid: true,
            netdiff: self.netdiff.max(other.netdiff),
            exec: self.exec.max(other.exec),
        }
    }

    /// `operator+` — concatenation.
    fn cat(self, other: SatInfo) -> SatInfo {
        if !self.valid || !other.valid {
            return SatInfo::EMPTY;
        }
        SatInfo {
            valid: true,
            netdiff: self.netdiff + other.netdiff,
            exec: other.exec.max(other.netdiff + self.exec),
        }
    }
}

/// `internal::StackSize`.
#[derive(Clone, Copy, Debug)]
struct StackSize {
    sat: SatInfo,
    dsat: SatInfo,
}

/// `internal::WitnessSize`.
#[derive(Clone, Copy, Debug)]
struct WitnessSize {
    sat: MaxInt,
    dsat: MaxInt,
}

// ---- Node ---------------------------------------------------------

/// `miniscript::Node` — a parsed fragment with precomputed analysis
/// (ops, stack sizes, witness sizes, type, script length).
#[derive(Clone, Debug)]
pub struct Node {
    pub fragment: Fragment,
    pub k: u32,
    /// Key table indices (Core's `Key`).
    pub keys: Vec<usize>,
    /// Hash fragment payload.
    pub data: Vec<u8>,
    pub subs: Vec<Node>,
    ctx: MsContext,
    ops: Ops,
    ss: StackSize,
    ws: WitnessSize,
    typ: Type,
    scriptlen: usize,
    has_dup_keys: bool,
}

/// `KeyCtx` — the parser-facing context (`KeyParser`): key strings to
/// indices, indices back to canonical strings, and a comparator for
/// the duplicate-key check.
pub trait KeyCtx {
    fn ms_context(&self) -> MsContext;
    /// `KeyParser::FromString` — parse a key expression; returns its
    /// key index or `None` on failure.
    fn key_from_str(&mut self, text: &str) -> Option<usize>;
    /// `KeyParser::ToString` — the canonical key text.
    fn key_string(&self, key: usize) -> Option<String>;
    /// `KeyParser::KeyCompare` — ordering used by `DuplicateKeyCheck`.
    fn key_cmp(&self, a: usize, b: usize) -> std::cmp::Ordering;
}

/// `ScriptCtx` — the script-emission context (`ScriptMaker`): key
/// index to pubkey bytes / pubkey-hash bytes.
pub trait ScriptCtx {
    fn to_pk_bytes(&self, key: usize) -> Vec<u8>;
    fn to_pkh_bytes(&self, key: usize) -> Vec<u8>;
}

fn build_num(script: &mut Vec<u8>, n: u32) {
    // `CScript << CScriptNum`.
    if n == 0 {
        script.push(crate::script::OP_0);
    } else if n <= 16 {
        script.push(crate::script::OP_1 + n as u8 - 1);
    } else {
        let mut bytes = Vec::new();
        let mut v = n;
        while v != 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0);
        }
        script.extend_from_slice(&crate::script::push_slice(&bytes));
    }
}

fn build_script_len_num(n: u32) -> usize {
    // `BuildScript(k).size()` — opcode or minimally-encoded push.
    if n <= 16 {
        1
    } else {
        let mut bytes = 0usize;
        let mut v = n;
        while v != 0 {
            bytes += 1;
            v >>= 8;
        }
        // A set high bit in the top byte forces a sign-extension zero.
        if (n >> ((bytes - 1) * 8)) & 0x80 != 0 {
            bytes += 1;
        }
        1 + bytes
    }
}

impl Node {
    fn new(
        ctx: MsContext,
        fragment: Fragment,
        subs: Vec<Node>,
        keys: Vec<usize>,
        data: Vec<u8>,
        k: u32,
    ) -> Node {
        let ops = Self::calc_ops(fragment, &subs, keys.len(), k);
        let ss = Self::calc_stack_size(fragment, &subs, keys.len(), k);
        let ws = Self::calc_witness_size(fragment, &subs, keys.len(), k, ctx);
        let typ = Self::calc_type(fragment, &subs, keys.len(), data.len(), k, ctx);
        let scriptlen = Self::calc_script_len(fragment, &subs, keys.len(), k, ctx);
        Node {
            fragment,
            k,
            keys,
            data,
            subs,
            ctx,
            ops,
            ss,
            ws,
            typ,
            scriptlen,
            has_dup_keys: false,
        }
    }

    /// `CalcType` — `ComputeType` over sub-types + `SanitizeType`.
    fn calc_type(
        fragment: Fragment,
        subs: &[Node],
        n_keys: usize,
        data_size: usize,
        k: u32,
        ctx: MsContext,
    ) -> Type {
        let sub_types: Vec<Type> = if fragment == Fragment::Thresh {
            subs.iter().map(|s| s.typ).collect()
        } else {
            Vec::new()
        };
        let none = Type(0);
        let x = subs.first().map_or(none, |s| s.typ);
        let y = subs.get(1).map_or(none, |s| s.typ);
        let z = subs.get(2).map_or(none, |s| s.typ);
        sanitize_type(compute_type(
            fragment,
            x,
            y,
            z,
            &sub_types,
            k,
            data_size,
            subs.len(),
            n_keys,
            ctx,
        ))
    }

    /// `CalcScriptLen` — `ComputeScriptLen`.
    fn calc_script_len(
        fragment: Fragment,
        subs: &[Node],
        n_keys: usize,
        k: u32,
        ctx: MsContext,
    ) -> usize {
        let subsize: usize = subs.iter().map(|s| s.scriptlen).sum();
        let sub0typ = subs.first().map_or(Type(0), |s| s.typ);
        compute_script_len(fragment, sub0typ, subsize, k, subs.len(), n_keys, ctx)
    }

    /// `CalcOps` — the per-fragment opcode/key accounting.
    fn calc_ops(fragment: Fragment, subs: &[Node], n_keys: usize, k: u32) -> Ops {
        let ops = |count: u32, sat: MaxInt, dsat: MaxInt| Ops { count, sat, dsat };
        match fragment {
            Fragment::Just1 => ops(0, Some(0), None),
            Fragment::Just0 => ops(0, None, Some(0)),
            Fragment::PkK => ops(0, Some(0), Some(0)),
            Fragment::PkH => ops(3, Some(0), Some(0)),
            Fragment::Older | Fragment::After => ops(1, Some(0), None),
            Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160 => {
                ops(4, Some(0), None)
            }
            Fragment::AndV => ops(
                subs[0].ops.count + subs[1].ops.count,
                max_add(subs[0].ops.sat, subs[1].ops.sat),
                None,
            ),
            Fragment::AndB => {
                let count = 1 + subs[0].ops.count + subs[1].ops.count;
                let sat = max_add(subs[0].ops.sat, subs[1].ops.sat);
                let dsat = max_add(subs[0].ops.dsat, subs[1].ops.dsat);
                ops(count, sat, dsat)
            }
            Fragment::OrB => {
                let count = 1 + subs[0].ops.count + subs[1].ops.count;
                let sat = max_or(
                    max_add(subs[0].ops.sat, subs[1].ops.dsat),
                    max_add(subs[1].ops.sat, subs[0].ops.dsat),
                );
                let dsat = max_add(subs[0].ops.dsat, subs[1].ops.dsat);
                ops(count, sat, dsat)
            }
            Fragment::OrD => {
                let count = 3 + subs[0].ops.count + subs[1].ops.count;
                let sat = max_or(subs[0].ops.sat, max_add(subs[1].ops.sat, subs[0].ops.dsat));
                let dsat = max_add(subs[0].ops.dsat, subs[1].ops.dsat);
                ops(count, sat, dsat)
            }
            Fragment::OrC => {
                let count = 2 + subs[0].ops.count + subs[1].ops.count;
                let sat = max_or(subs[0].ops.sat, max_add(subs[1].ops.sat, subs[0].ops.dsat));
                ops(count, sat, None)
            }
            Fragment::OrI => {
                let count = 3 + subs[0].ops.count + subs[1].ops.count;
                let sat = max_or(subs[0].ops.sat, subs[1].ops.sat);
                let dsat = max_or(subs[0].ops.dsat, subs[1].ops.dsat);
                ops(count, sat, dsat)
            }
            Fragment::AndOr => {
                let count = 3 + subs[0].ops.count + subs[1].ops.count + subs[2].ops.count;
                let sat = max_or(
                    max_add(subs[1].ops.sat, subs[0].ops.sat),
                    max_add(subs[0].ops.dsat, subs[2].ops.sat),
                );
                let dsat = max_add(subs[0].ops.dsat, subs[2].ops.dsat);
                ops(count, sat, dsat)
            }
            Fragment::Multi => ops(1, Some(n_keys as u32), Some(n_keys as u32)),
            Fragment::MultiA => ops(n_keys as u32 + 1, Some(0), Some(0)),
            Fragment::WrapS | Fragment::WrapC | Fragment::WrapN => {
                ops(1 + subs[0].ops.count, subs[0].ops.sat, subs[0].ops.dsat)
            }
            Fragment::WrapA => ops(2 + subs[0].ops.count, subs[0].ops.sat, subs[0].ops.dsat),
            Fragment::WrapD => ops(3 + subs[0].ops.count, subs[0].ops.sat, Some(0)),
            Fragment::WrapJ => ops(4 + subs[0].ops.count, subs[0].ops.sat, Some(0)),
            Fragment::WrapV => ops(
                subs[0].ops.count + subs[0].typ.has_all(mst("x")) as u32,
                subs[0].ops.sat,
                None,
            ),
            Fragment::Thresh => {
                let mut count = 0u32;
                // sats[j] = max ops to satisfy j of the first i subs.
                let mut sats: Vec<MaxInt> = vec![Some(0)];
                for sub in subs {
                    count += sub.ops.count + 1;
                    let mut next = vec![max_add(sats[0], sub.ops.dsat)];
                    for j in 1..sats.len() {
                        next.push(max_or(
                            max_add(sats[j], sub.ops.dsat),
                            max_add(sats[j - 1], sub.ops.sat),
                        ));
                    }
                    next.push(max_add(sats[sats.len() - 1], sub.ops.sat));
                    sats = next;
                }
                ops(count, sats[k as usize], sats[0])
            }
        }
    }

    /// `CalcStackSize` — the SatInfo per-fragment table.
    fn calc_stack_size(fragment: Fragment, subs: &[Node], n_keys: usize, k: u32) -> StackSize {
        let ss = |sat: SatInfo, dsat: SatInfo| StackSize { sat, dsat };
        match fragment {
            Fragment::Just0 => ss(SatInfo::EMPTY, SatInfo::PUSH),
            Fragment::Just1 => ss(SatInfo::PUSH, SatInfo::EMPTY),
            Fragment::Older | Fragment::After => {
                ss(SatInfo::PUSH.cat(SatInfo::NOP), SatInfo::EMPTY)
            }
            Fragment::PkK => ss(SatInfo::PUSH, SatInfo::PUSH),
            Fragment::PkH => ss(
                SatInfo::OP_DUP
                    .cat(SatInfo::HASH)
                    .cat(SatInfo::PUSH)
                    .cat(SatInfo::OP_EQUALVERIFY),
                SatInfo::PUSH.cat(SatInfo::PUSH),
            ),
            Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160 => ss(
                SatInfo::OP_SIZE
                    .cat(SatInfo::PUSH)
                    .cat(SatInfo::OP_EQUALVERIFY)
                    .cat(SatInfo::HASH)
                    .cat(SatInfo::PUSH)
                    .cat(SatInfo::OP_EQUAL),
                SatInfo::PUSH,
            ),
            Fragment::AndOr => {
                let x = subs[0].ss;
                let y = subs[1].ss;
                let z = subs[2].ss;
                ss(
                    (x.sat.cat(SatInfo::IF).cat(y.sat)).union(x.dsat.cat(SatInfo::IF).cat(z.sat)),
                    x.dsat.cat(SatInfo::IF).cat(z.dsat),
                )
            }
            Fragment::AndV => ss(subs[0].ss.sat.cat(subs[1].ss.sat), SatInfo::EMPTY),
            Fragment::AndB => ss(
                subs[0].ss.sat.cat(subs[1].ss.sat).cat(SatInfo::BINARY_OP),
                subs[0].ss.dsat.cat(subs[1].ss.dsat).cat(SatInfo::BINARY_OP),
            ),
            Fragment::OrB => {
                let x = subs[0].ss;
                let y = subs[1].ss;
                ss(
                    (x.sat.cat(y.dsat).union(x.dsat.cat(y.sat))).cat(SatInfo::BINARY_OP),
                    x.dsat.cat(y.dsat).cat(SatInfo::BINARY_OP),
                )
            }
            Fragment::OrC => {
                let x = subs[0].ss;
                let y = subs[1].ss;
                ss(
                    (x.sat.cat(SatInfo::IF)).union(x.dsat.cat(SatInfo::IF).cat(y.sat)),
                    SatInfo::EMPTY,
                )
            }
            Fragment::OrD => {
                let x = subs[0].ss;
                let y = subs[1].ss;
                ss(
                    (x.sat.cat(SatInfo::ifdup(true)).cat(SatInfo::IF)).union(
                        x.dsat
                            .cat(SatInfo::ifdup(false))
                            .cat(SatInfo::IF)
                            .cat(y.sat),
                    ),
                    x.dsat
                        .cat(SatInfo::ifdup(false))
                        .cat(SatInfo::IF)
                        .cat(y.dsat),
                )
            }
            Fragment::OrI => {
                let x = subs[0].ss;
                let y = subs[1].ss;
                ss(
                    SatInfo::IF.cat(x.sat.union(y.sat)),
                    SatInfo::IF.cat(x.dsat.union(y.dsat)),
                )
            }
            Fragment::Multi => ss(
                SatInfo {
                    valid: true,
                    netdiff: k as i32,
                    exec: (k as usize + n_keys + 2) as i32,
                },
                SatInfo {
                    valid: true,
                    netdiff: k as i32,
                    exec: (k as usize + n_keys + 2) as i32,
                },
            ),
            Fragment::MultiA => ss(
                SatInfo {
                    valid: true,
                    netdiff: n_keys as i32 - 1,
                    exec: n_keys as i32,
                },
                SatInfo {
                    valid: true,
                    netdiff: n_keys as i32 - 1,
                    exec: n_keys as i32,
                },
            ),
            Fragment::WrapA | Fragment::WrapN | Fragment::WrapS => subs[0].ss,
            Fragment::WrapC => ss(
                subs[0].ss.sat.cat(SatInfo::OP_CHECKSIG),
                subs[0].ss.dsat.cat(SatInfo::OP_CHECKSIG),
            ),
            Fragment::WrapD => ss(
                SatInfo::OP_DUP.cat(SatInfo::IF).cat(subs[0].ss.sat),
                SatInfo::ZERO,
            ),
            Fragment::WrapJ => ss(
                SatInfo::OP_SIZE
                    .cat(SatInfo::OP_0NOTEQUAL)
                    .cat(SatInfo::IF)
                    .cat(subs[0].ss.sat),
                SatInfo::ZERO,
            ),
            Fragment::WrapV => ss(
                subs[0].ss.sat.cat(if subs[0].typ.has_all(mst("x")) {
                    SatInfo::OP_VERIFY
                } else {
                    SatInfo::ZERO
                }),
                SatInfo::EMPTY,
            ),
            Fragment::Thresh => {
                // sats[j] = best SatInfo satisfying j of the last i subs.
                let mut sats = vec![SatInfo::ZERO];
                let mut dsats = SatInfo::ZERO;
                for sub in subs {
                    dsats = dsats.cat(sub.ss.dsat).cat(SatInfo::BINARY_OP);
                    // next[j] = (sats[j]+dsat) | (sats[j-1]+sat), per
                    // Core's dynamic-programming construction.
                    let mut next = Vec::with_capacity(sats.len() + 1);
                    next.push(sats[0].cat(sub.ss.dsat).cat(SatInfo::BINARY_OP));
                    for j in 1..sats.len() {
                        next.push(
                            sats[j]
                                .cat(sub.ss.dsat)
                                .cat(SatInfo::BINARY_OP)
                                .union(sats[j - 1].cat(sub.ss.sat).cat(SatInfo::BINARY_OP)),
                        );
                    }
                    next.push(sats[sats.len() - 1].cat(sub.ss.sat).cat(SatInfo::BINARY_OP));
                    sats = next;
                }
                ss(sats[k as usize], dsats)
            }
        }
    }

    /// `CalcWitnessSize`.
    fn calc_witness_size(
        fragment: Fragment,
        subs: &[Node],
        n_keys: usize,
        k: u32,
        ctx: MsContext,
    ) -> WitnessSize {
        let sig_size = if is_tapscript(ctx) { 1 + 65 } else { 1 + 72 };
        let pubkey_size = if is_tapscript(ctx) { 1 + 32 } else { 1 + 33 };
        let w = |sat: MaxInt, dsat: MaxInt| WitnessSize { sat, dsat };
        match fragment {
            Fragment::Just0 => w(None, Some(0)),
            Fragment::Just1 | Fragment::Older | Fragment::After => w(Some(0), None),
            Fragment::PkK => w(Some(sig_size), Some(1)),
            Fragment::PkH => w(Some(sig_size + pubkey_size), Some(1 + pubkey_size)),
            Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160 => {
                w(Some(1 + 32), None)
            }
            Fragment::AndOr => {
                let sat = max_or(
                    max_add(subs[0].ws.sat, subs[1].ws.sat),
                    max_add(subs[0].ws.dsat, subs[2].ws.sat),
                );
                let dsat = max_add(subs[0].ws.dsat, subs[2].ws.dsat);
                w(sat, dsat)
            }
            Fragment::AndV => w(max_add(subs[0].ws.sat, subs[1].ws.sat), None),
            Fragment::AndB => w(
                max_add(subs[0].ws.sat, subs[1].ws.sat),
                max_add(subs[0].ws.dsat, subs[1].ws.dsat),
            ),
            Fragment::OrB => {
                let sat = max_or(
                    max_add(subs[0].ws.dsat, subs[1].ws.sat),
                    max_add(subs[0].ws.sat, subs[1].ws.dsat),
                );
                w(sat, max_add(subs[0].ws.dsat, subs[1].ws.dsat))
            }
            Fragment::OrC => w(
                max_or(subs[0].ws.sat, max_add(subs[0].ws.dsat, subs[1].ws.sat)),
                None,
            ),
            Fragment::OrD => w(
                max_or(subs[0].ws.sat, max_add(subs[0].ws.dsat, subs[1].ws.sat)),
                max_add(subs[0].ws.dsat, subs[1].ws.dsat),
            ),
            Fragment::OrI => w(
                max_or(
                    max_add(subs[0].ws.sat, Some(1 + 1)),
                    max_add(subs[1].ws.sat, Some(1)),
                ),
                max_or(
                    max_add(subs[0].ws.dsat, Some(1 + 1)),
                    max_add(subs[1].ws.dsat, Some(1)),
                ),
            ),
            Fragment::Multi => w(Some(k * sig_size + 1), Some(k + 1)),
            Fragment::MultiA => w(Some(k * sig_size + n_keys as u32 - k), Some(n_keys as u32)),
            Fragment::WrapA | Fragment::WrapN | Fragment::WrapS | Fragment::WrapC => subs[0].ws,
            Fragment::WrapD => w(max_add(Some(1 + 1), subs[0].ws.sat), Some(1)),
            Fragment::WrapV => w(subs[0].ws.sat, None),
            Fragment::WrapJ => w(subs[0].ws.sat, Some(1)),
            Fragment::Thresh => {
                let mut sats: Vec<MaxInt> = vec![Some(0)];
                for sub in subs {
                    let mut next = vec![max_add(sats[0], sub.ws.dsat)];
                    for j in 1..sats.len() {
                        next.push(max_or(
                            max_add(sats[j], sub.ws.dsat),
                            max_add(sats[j - 1], sub.ws.sat),
                        ));
                    }
                    next.push(max_add(sats[sats.len() - 1], sub.ws.sat));
                    sats = next;
                }
                w(sats[k as usize], sats[0])
            }
        }
    }

    /// `DuplicateKeyCheck` — post-order merge of per-node key sets;
    /// `key_cmp` resolves indices to canonical order. Sets
    /// `has_dup_keys` on every visited node.
    fn duplicate_key_check(&mut self, ctx: &dyn KeyCtx) {
        fn walk(node: &mut Node, ctx: &dyn KeyCtx) -> Option<Vec<usize>> {
            if node.has_dup_keys {
                return None;
            }
            let mut sub_sets = Vec::with_capacity(node.subs.len());
            for sub in &mut node.subs {
                match walk(sub, ctx) {
                    Some(set) => sub_sets.push(set),
                    None => {
                        node.has_dup_keys = true;
                        return None;
                    }
                }
            }
            // Merge this node's own keys + all child sets, sorted by
            // KeyCompare — a size drop on union means a duplicate.
            let mut keys_count = node.keys.len();
            let mut set: Vec<usize> = node.keys.clone();
            set.sort_by(|a, b| ctx.key_cmp(*a, *b));
            set.dedup_by(|a, b| ctx.key_cmp(*a, *b) == std::cmp::Ordering::Equal);
            if set.len() != keys_count {
                node.has_dup_keys = true;
                return None;
            }
            for sub_set in sub_sets {
                keys_count += sub_set.len();
                // Union the two sorted sets.
                let mut merged = Vec::with_capacity(set.len() + sub_set.len());
                let (mut i, mut j) = (0, 0);
                while i < set.len() || j < sub_set.len() {
                    let pick_a = if j == sub_set.len() {
                        true
                    } else if i == set.len() {
                        false
                    } else {
                        ctx.key_cmp(set[i], sub_set[j]) != std::cmp::Ordering::Greater
                    };
                    if pick_a {
                        merged.push(set[i]);
                        i += 1;
                    } else {
                        merged.push(sub_set[j]);
                        j += 1;
                    }
                }
                merged.dedup_by(|a, b| ctx.key_cmp(*a, *b) == std::cmp::Ordering::Equal);
                if merged.len() != keys_count {
                    node.has_dup_keys = true;
                    return None;
                }
                set = merged;
            }
            node.has_dup_keys = false;
            Some(set)
        }
        walk(self, ctx);
    }

    // ---- queries ----------------------------------------------------

    /// `GetType`.
    pub fn get_type(&self) -> Type {
        self.typ
    }

    /// `GetMsCtx`.
    pub fn ms_context(&self) -> MsContext {
        self.ctx
    }

    /// `ScriptSize`.
    pub fn script_size(&self) -> usize {
        self.scriptlen
    }

    /// `GetOps` — static + possibly-executed sigops, `None` if any
    /// satisfaction is impossible.
    fn get_ops(&self) -> Option<u32> {
        self.ops.sat.map(|s| self.ops.count + s)
    }

    /// `CheckOpsLimit`.
    fn check_ops_limit(&self) -> bool {
        if is_tapscript(self.ctx) {
            return true;
        }
        self.get_ops().is_none_or(|o| o <= MAX_OPS_PER_SCRIPT)
    }

    /// `IsBKW` — anything but V.
    fn is_bkw(&self) -> bool {
        self.typ.any("BKW")
    }

    /// `GetStackSize` — max initial stack elements for a non-malleable
    /// satisfaction; `None` = unsatisfiable.
    fn get_stack_size(&self) -> Option<u32> {
        if !self.ss.sat.valid {
            return None;
        }
        Some((self.ss.sat.netdiff + self.is_bkw() as i32) as u32)
    }

    /// `GetExecStackSize` — max stack height during execution.
    fn get_exec_stack_size(&self) -> Option<u32> {
        if !self.ss.sat.valid {
            return None;
        }
        Some((self.ss.sat.exec + self.is_bkw() as i32) as u32)
    }

    /// `CheckStackSize` — the P2WSH standardness / tapscript consensus
    /// bound.
    fn check_stack_size(&self) -> bool {
        if is_tapscript(self.ctx) {
            return self
                .get_exec_stack_size()
                .is_none_or(|s| s <= MAX_STACK_SIZE);
        }
        self.get_stack_size()
            .is_none_or(|s| s <= MAX_STANDARD_P2WSH_STACK_ITEMS)
    }

    /// `IsNotSatisfiable`.
    pub fn is_not_satisfiable(&self) -> bool {
        self.get_stack_size().is_none()
    }

    /// `IsValid` — computable type + size in context bounds.
    pub fn is_valid(&self) -> bool {
        self.typ != Type(0) && self.scriptlen <= max_script_size(self.ctx) as usize
    }

    /// `IsValidTopLevel` — a usable script on its own (type B).
    pub fn is_valid_top_level(&self) -> bool {
        self.is_valid() && self.typ.has_all(mst("B"))
    }

    /// `IsNonMalleable` — 'm' property.
    pub fn is_non_malleable(&self) -> bool {
        self.typ.has_all(mst("m"))
    }

    /// `NeedsSignature` — 's' property.
    pub fn needs_signature(&self) -> bool {
        self.typ.has_all(mst("s"))
    }

    /// `CheckTimeLocksMix` — 'k' property (no height+time mixes).
    pub fn check_timelocks_mix(&self) -> bool {
        self.typ.has_all(mst("k"))
    }

    /// `CheckDuplicateKey`.
    pub fn check_duplicate_key(&self) -> bool {
        !self.has_dup_keys
    }

    /// `ValidSatisfactions`.
    pub fn valid_satisfactions(&self) -> bool {
        self.is_valid() && self.check_ops_limit() && self.check_stack_size()
    }

    /// `IsSaneSubexpression`.
    pub fn is_sane_subexpression(&self) -> bool {
        self.valid_satisfactions()
            && self.is_non_malleable()
            && self.check_timelocks_mix()
            && self.check_duplicate_key()
    }

    /// `IsSane` — safe as a standalone script.
    pub fn is_sane(&self) -> bool {
        self.is_valid_top_level() && self.is_sane_subexpression() && self.needs_signature()
    }

    /// `FindInsaneSub` — first insane subnode without insane children.
    pub fn find_insane_sub(&self) -> Option<&Node> {
        for sub in &self.subs {
            if let Some(n) = sub.find_insane_sub() {
                return Some(n);
            }
        }
        if !self.is_sane_subexpression() {
            return Some(self);
        }
        None
    }

    // ---- ToScript ---------------------------------------------------

    /// `ToScript` — emit the script with resolved keys.
    pub fn to_script<SC: ScriptCtx>(&self, ctx: &SC) -> Vec<u8> {
        // TreeEval<bool>: `verify` state downward, script upward.
        let downfn = |verify: &bool, node: &Node, index: usize| -> bool {
            if node.fragment == Fragment::WrapV {
                return true;
            }
            if node.fragment == Fragment::WrapS || (node.fragment == Fragment::AndV && index == 1) {
                return *verify;
            }
            false
        };
        let tapscript = is_tapscript(self.ctx);
        let upfn = |verify: bool, node: &Node, subs: Vec<Vec<u8>>| -> Option<Vec<u8>> {
            let mut script = Vec::new();
            let mut sub_iter = subs.into_iter();
            let mut next_sub = |script: &mut Vec<u8>| {
                script.extend_from_slice(&sub_iter.next().unwrap_or_default());
            };
            match node.fragment {
                Fragment::PkK => script
                    .extend_from_slice(&crate::script::push_slice(&ctx.to_pk_bytes(node.keys[0]))),
                Fragment::PkH => {
                    script.push(crate::script::OP_DUP);
                    script.push(crate::script::OP_HASH160);
                    script.extend_from_slice(&crate::script::push_slice(
                        &ctx.to_pkh_bytes(node.keys[0]),
                    ));
                    script.push(crate::script::OP_EQUALVERIFY);
                }
                Fragment::Older => {
                    build_num(&mut script, node.k);
                    script.push(crate::script::OP_CSV);
                }
                Fragment::After => {
                    build_num(&mut script, node.k);
                    script.push(crate::script::OP_CLTV);
                }
                Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160 => {
                    script.push(crate::script::OP_SIZE);
                    build_num(&mut script, 32);
                    script.push(crate::script::OP_EQUALVERIFY);
                    script.push(match node.fragment {
                        Fragment::Sha256 => crate::script::OP_SHA256,
                        Fragment::Ripemd160 => crate::script::OP_RIPEMD160,
                        Fragment::Hash256 => crate::script::OP_HASH256,
                        _ => crate::script::OP_HASH160,
                    });
                    script.extend_from_slice(&crate::script::push_slice(&node.data));
                    script.push(if verify {
                        crate::script::OP_EQUALVERIFY
                    } else {
                        crate::script::OP_EQUAL
                    });
                }
                Fragment::WrapA => {
                    script.push(crate::script::OP_TOALTSTACK);
                    next_sub(&mut script);
                    script.push(crate::script::OP_FROMALTSTACK);
                }
                Fragment::WrapS => {
                    script.push(crate::script::OP_SWAP);
                    next_sub(&mut script);
                }
                Fragment::WrapC => {
                    next_sub(&mut script);
                    script.push(if verify {
                        crate::script::OP_CHECKSIGVERIFY
                    } else {
                        crate::script::OP_CHECKSIG
                    });
                }
                Fragment::WrapD => {
                    script.push(crate::script::OP_DUP);
                    script.push(crate::script::OP_IF);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::WrapV => {
                    next_sub(&mut script);
                    // 'x' = last opcode isn't fusable — append VERIFY;
                    // without 'x' the sub already emitted -VERIFY form.
                    if node.subs[0].typ.has_all(mst("x")) {
                        script.push(crate::script::OP_VERIFY);
                    }
                }
                Fragment::WrapJ => {
                    script.push(crate::script::OP_SIZE);
                    script.push(crate::script::OP_0NOTEQUAL);
                    script.push(crate::script::OP_IF);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::WrapN => {
                    next_sub(&mut script);
                    script.push(crate::script::OP_0NOTEQUAL);
                }
                Fragment::Just1 => script.push(crate::script::OP_1),
                Fragment::Just0 => script.push(crate::script::OP_0),
                Fragment::AndV => {
                    next_sub(&mut script);
                    next_sub(&mut script);
                }
                Fragment::AndB => {
                    next_sub(&mut script);
                    next_sub(&mut script);
                    script.push(crate::script::OP_BOOLAND);
                }
                Fragment::OrB => {
                    next_sub(&mut script);
                    next_sub(&mut script);
                    script.push(crate::script::OP_BOOLOR);
                }
                Fragment::OrC => {
                    next_sub(&mut script);
                    script.push(crate::script::OP_NOTIF);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::OrD => {
                    next_sub(&mut script);
                    script.push(crate::script::OP_IFDUP);
                    script.push(crate::script::OP_NOTIF);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::OrI => {
                    script.push(crate::script::OP_IF);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ELSE);
                    next_sub(&mut script);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::AndOr => {
                    // subs[0] NOTIF subs[2] ELSE subs[1] ENDIF.
                    next_sub(&mut script);
                    script.push(crate::script::OP_NOTIF);
                    let else_branch = sub_iter.next().unwrap_or_default();
                    let then_branch = sub_iter.next().unwrap_or_default();
                    script.extend_from_slice(&then_branch);
                    script.push(crate::script::OP_ELSE);
                    script.extend_from_slice(&else_branch);
                    script.push(crate::script::OP_ENDIF);
                }
                Fragment::Multi => {
                    debug_assert!(!tapscript);
                    build_num(&mut script, node.k);
                    for &key in &node.keys {
                        script.extend_from_slice(&crate::script::push_slice(&ctx.to_pk_bytes(key)));
                    }
                    build_num(&mut script, node.keys.len() as u32);
                    script.push(if verify {
                        crate::script::OP_CHECKMULTISIGVERIFY
                    } else {
                        crate::script::OP_CHECKMULTISIG
                    });
                }
                Fragment::MultiA => {
                    debug_assert!(tapscript);
                    script.extend_from_slice(&crate::script::push_slice(
                        &ctx.to_pk_bytes(node.keys[0]),
                    ));
                    script.push(crate::script::OP_CHECKSIG);
                    for &key in &node.keys[1..] {
                        script.extend_from_slice(&crate::script::push_slice(&ctx.to_pk_bytes(key)));
                        script.push(crate::script::OP_CHECKSIGADD);
                    }
                    build_num(&mut script, node.k);
                    script.push(if verify {
                        crate::script::OP_NUMEQUALVERIFY
                    } else {
                        crate::script::OP_NUMEQUAL
                    });
                }
                Fragment::Thresh => {
                    next_sub(&mut script);
                    for _ in 1..node.subs.len() {
                        next_sub(&mut script);
                        script.push(crate::script::OP_ADD);
                    }
                    build_num(&mut script, node.k);
                    script.push(if verify {
                        crate::script::OP_EQUALVERIFY
                    } else {
                        crate::script::OP_EQUAL
                    });
                }
            }
            Some(script)
        };
        tree_eval(self, false, downfn, upfn).unwrap_or_default()
    }

    // ---- ToString ---------------------------------------------------

    /// `ToString` — canonical serialization with the wrapper sugar.
    pub fn to_string<KC: KeyCtx>(&self, ctx: &KC) -> Option<String> {
        let downfn = |_: &bool, node: &Node, _: usize| -> bool {
            matches!(
                node.fragment,
                Fragment::WrapA
                    | Fragment::WrapS
                    | Fragment::WrapD
                    | Fragment::WrapV
                    | Fragment::WrapJ
                    | Fragment::WrapN
                    | Fragment::WrapC
            ) || (node.fragment == Fragment::AndV && node.subs[1].fragment == Fragment::Just1)
                || (node.fragment == Fragment::OrI && node.subs[0].fragment == Fragment::Just0)
                || (node.fragment == Fragment::OrI && node.subs[1].fragment == Fragment::Just0)
        };
        let upfn = |wrapped: bool, node: &Node, subs: Vec<String>| -> Option<String> {
            let ret = if wrapped { ":" } else { "" }.to_string();
            match node.fragment {
                Fragment::WrapA => return Some(format!("a{}", subs[0])),
                Fragment::WrapS => return Some(format!("s{}", subs[0])),
                Fragment::WrapC => {
                    if node.subs[0].fragment == Fragment::PkK {
                        return Some(format!(
                            "{ret}pk({})",
                            ctx.key_string(node.subs[0].keys[0])?
                        ));
                    }
                    if node.subs[0].fragment == Fragment::PkH {
                        return Some(format!(
                            "{ret}pkh({})",
                            ctx.key_string(node.subs[0].keys[0])?
                        ));
                    }
                    return Some(format!("c{}", subs[0]));
                }
                Fragment::WrapD => return Some(format!("d{}", subs[0])),
                Fragment::WrapV => return Some(format!("v{}", subs[0])),
                Fragment::WrapJ => return Some(format!("j{}", subs[0])),
                Fragment::WrapN => return Some(format!("n{}", subs[0])),
                Fragment::AndV if node.subs[1].fragment == Fragment::Just1 => {
                    return Some(format!("t{}", subs[0]));
                }
                Fragment::OrI if node.subs[0].fragment == Fragment::Just0 => {
                    return Some(format!("l{}", subs[1]));
                }
                Fragment::OrI if node.subs[1].fragment == Fragment::Just0 => {
                    return Some(format!("u{}", subs[0]));
                }
                _ => {}
            }
            Some(match node.fragment {
                Fragment::PkK => format!("{ret}pk_k({})", ctx.key_string(node.keys[0])?),
                Fragment::PkH => format!("{ret}pk_h({})", ctx.key_string(node.keys[0])?),
                Fragment::After => format!("{ret}after({})", node.k),
                Fragment::Older => format!("{ret}older({})", node.k),
                Fragment::Hash256 => format!("{ret}hash256({})", crate::hex::encode(&node.data)),
                Fragment::Hash160 => format!("{ret}hash160({})", crate::hex::encode(&node.data)),
                Fragment::Sha256 => format!("{ret}sha256({})", crate::hex::encode(&node.data)),
                Fragment::Ripemd160 => {
                    format!("{ret}ripemd160({})", crate::hex::encode(&node.data))
                }
                Fragment::Just1 => format!("{ret}1"),
                Fragment::Just0 => format!("{ret}0"),
                Fragment::AndV => format!("{ret}and_v({},{})", subs[0], subs[1]),
                Fragment::AndB => format!("{ret}and_b({},{})", subs[0], subs[1]),
                Fragment::OrB => format!("{ret}or_b({},{})", subs[0], subs[1]),
                Fragment::OrD => format!("{ret}or_d({},{})", subs[0], subs[1]),
                Fragment::OrC => format!("{ret}or_c({},{})", subs[0], subs[1]),
                Fragment::OrI => format!("{ret}or_i({},{})", subs[0], subs[1]),
                Fragment::AndOr => {
                    if node.subs[2].fragment == Fragment::Just0 {
                        format!("{ret}and_n({},{})", subs[0], subs[1])
                    } else {
                        format!("{ret}andor({},{},{})", subs[0], subs[1], subs[2])
                    }
                }
                Fragment::Multi => {
                    debug_assert!(!is_tapscript(node.ctx));
                    let mut s = format!("{ret}multi({}", node.k);
                    for &key in &node.keys {
                        s += &format!(",{}", ctx.key_string(key)?);
                    }
                    format!("{s})")
                }
                Fragment::MultiA => {
                    debug_assert!(is_tapscript(node.ctx));
                    let mut s = format!("{ret}multi_a({}", node.k);
                    for &key in &node.keys {
                        s += &format!(",{}", ctx.key_string(key)?);
                    }
                    format!("{s})")
                }
                Fragment::Thresh => {
                    let mut s = format!("{ret}thresh({}", node.k);
                    for sub in &subs {
                        s += &format!(",{sub}");
                    }
                    format!("{s})")
                }
                _ => unreachable!(),
            })
        };
        tree_eval(self, false, downfn, upfn)
    }
}

/// `TreeEval` — iterative pre-order state pass + post-order result
/// pass; states travel down, results travel up (Core's algorithm,
/// avoiding recursion on adversarial depth).
fn tree_eval<T, S: Clone, D, U>(root: &Node, init: S, downfn: D, upfn: U) -> Option<T>
where
    D: Fn(&S, &Node, usize) -> S,
    U: Fn(S, &Node, Vec<T>) -> Option<T>,
{
    // Pre-order traversal recording (node, state).
    let mut order: Vec<(&Node, S)> = Vec::new();
    let mut stack: Vec<(&Node, S)> = vec![(root, init)];
    while let Some((node, state)) = stack.pop() {
        for (i, sub) in node.subs.iter().enumerate().rev() {
            stack.push((sub, downfn(&state, node, i)));
        }
        order.push((node, state));
    }
    // order is pre-order (parents before children); reversed, every
    // child precedes its parent — post-order for evaluation.
    let mut results: Vec<(usize, T)> = Vec::with_capacity(order.len());
    for (node, state) in order.into_iter().rev() {
        let node_addr = node as *const Node as usize;
        let subs_t: Vec<T> = node
            .subs
            .iter()
            .filter_map(|s| {
                let addr = s as *const Node as usize;
                let pos = results.iter().rposition(|(a, _)| *a == addr)?;
                Some(results.swap_remove(pos).1)
            })
            .collect();
        let t = upfn(state, node, subs_t)?;
        results.push((node_addr, t));
    }
    results.pop().map(|(_, t)| t)
}

// ---- ComputeType / ComputeScriptLen -------------------------------

/// `internal::ComputeType` — the per-fragment type rule table.
#[allow(clippy::too_many_arguments)]
fn compute_type(
    fragment: Fragment,
    x: Type,
    y: Type,
    z: Type,
    sub_types: &[Type],
    k: u32,
    data_size: usize,
    n_subs: usize,
    n_keys: usize,
    ctx: MsContext,
) -> Type {
    // Sanity checks (Core asserts).
    debug_assert!(!matches!(fragment, Fragment::Sha256 | Fragment::Hash256) || data_size == 32);
    debug_assert!(!matches!(fragment, Fragment::Ripemd160 | Fragment::Hash160) || data_size == 20);
    debug_assert!(
        matches!(
            fragment,
            Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160
        ) || data_size == 0
    );
    debug_assert!(
        !matches!(fragment, Fragment::Older | Fragment::After) || (1..0x8000_0000).contains(&k)
    );
    debug_assert!(
        !matches!(fragment, Fragment::Multi | Fragment::MultiA) || (k >= 1 && k <= n_keys as u32)
    );
    debug_assert!(fragment != Fragment::Thresh || (k >= 1 && k <= n_subs as u32));
    debug_assert!(
        matches!(
            fragment,
            Fragment::Older
                | Fragment::After
                | Fragment::Multi
                | Fragment::MultiA
                | Fragment::Thresh
        ) || k == 0
    );

    let tl_conflict = |a: Type, b: Type| {
        (a.has_all(mst("g")) && b.has_all(mst("h")))
            || (a.has_all(mst("h")) && b.has_all(mst("g")))
            || (a.has_all(mst("i")) && b.has_all(mst("j")))
            || (a.has_all(mst("j")) && b.has_all(mst("i")))
    };
    match fragment {
        Fragment::PkK => mst("Konudemsxk"),
        Fragment::PkH => mst("Knudemsxk"),
        Fragment::Older => mst("g")
            .if_(k & SEQUENCE_LOCKTIME_TYPE_FLAG != 0)
            .union(mst("h").if_(k & SEQUENCE_LOCKTIME_TYPE_FLAG == 0))
            .union(mst("Bzfmxk")),
        Fragment::After => mst("i")
            .if_(k >= LOCKTIME_THRESHOLD)
            .union(mst("j").if_(k < LOCKTIME_THRESHOLD))
            .union(mst("Bzfmxk")),
        Fragment::Sha256 | Fragment::Ripemd160 | Fragment::Hash256 | Fragment::Hash160 => {
            mst("Bonudmk")
        }
        Fragment::Just1 => mst("Bzufmxk"),
        Fragment::Just0 => mst("Bzudemsxk"),
        Fragment::WrapA => mst("W")
            .if_(x.has_all(mst("B")))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("udfems")))
            .union(mst("x")),
        Fragment::WrapS => mst("W")
            .if_(x.has_all(mst("Bo")))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("udfemsx"))),
        Fragment::WrapC => mst("B")
            .if_(x.has_all(mst("K")))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("ondfem")))
            .union(mst("us")),
        Fragment::WrapD => mst("B")
            .if_(x.has_all(mst("Vz")))
            .union(mst("o").if_(x.has_all(mst("z"))))
            .union(mst("e").if_(x.has_all(mst("f"))))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("ms")))
            .union(mst("u").if_(is_tapscript(ctx)))
            .union(mst("ndx")),
        Fragment::WrapV => mst("V")
            .if_(x.has_all(mst("B")))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("zonms")))
            .union(mst("fx")),
        Fragment::WrapJ => mst("B")
            .if_(x.has_all(mst("Bn")))
            .union(mst("e").if_(x.has_all(mst("f"))))
            .union(x.inter(mst("ghijk")))
            .union(x.inter(mst("oums")))
            .union(mst("ndx")),
        Fragment::WrapN => x
            .inter(mst("ghijk"))
            .union(x.inter(mst("Bzondfems")))
            .union(mst("ux")),
        Fragment::AndV => (y.inter(mst("KVB")))
            .if_(x.has_all(mst("V")))
            .union(x.inter(mst("n")))
            .union(y.inter(mst("n")).if_(x.has_all(mst("z"))))
            .union(
                (x.union(y))
                    .inter(mst("o"))
                    .if_((x.union(y)).has_all(mst("z"))),
            )
            .union(x.inter(y).inter(mst("dmz")))
            .union((x.union(y)).inter(mst("s")))
            .union(mst("f").if_(y.has_all(mst("f")) || x.has_all(mst("s"))))
            .union(y.inter(mst("ux")))
            .union((x.union(y)).inter(mst("ghij")))
            .union(mst("k").if_(x.has_all(mst("k")) && y.has_all(mst("k")) && !tl_conflict(x, y))),
        Fragment::AndB => x
            .inter(mst("B"))
            .if_(y.has_all(mst("W")))
            .union(
                (x.union(y))
                    .inter(mst("o"))
                    .if_((x.union(y)).has_all(mst("z"))),
            )
            .union(x.inter(mst("n")))
            .union(y.inter(mst("n")).if_(x.has_all(mst("z"))))
            .union(
                x.inter(y)
                    .inter(mst("e"))
                    .if_((x.inter(y)).has_all(mst("s"))),
            )
            .union(x.inter(y).inter(mst("dzm")))
            .union(mst("f").if_(
                (x.inter(y)).has_all(mst("f")) || x.has_all(mst("sf")) || y.has_all(mst("sf")),
            ))
            .union((x.union(y)).inter(mst("s")))
            .union(mst("ux"))
            .union((x.union(y)).inter(mst("ghij")))
            .union(mst("k").if_(x.has_all(mst("k")) && y.has_all(mst("k")) && !tl_conflict(x, y))),
        Fragment::OrB => mst("B")
            .if_(x.has_all(mst("Bd")) && y.has_all(mst("Wd")))
            .union(
                (x.union(y))
                    .inter(mst("o"))
                    .if_((x.union(y)).has_all(mst("z"))),
            )
            .union(
                x.inter(y)
                    .inter(mst("m"))
                    .if_((x.union(y)).has_all(mst("s")) && (x.inter(y)).has_all(mst("e"))),
            )
            .union(x.inter(y).inter(mst("zse")))
            .union(mst("dux"))
            .union((x.union(y)).inter(mst("ghij")))
            .union(x.inter(y).inter(mst("k"))),
        Fragment::OrD => y
            .inter(mst("B"))
            .if_(x.has_all(mst("Bdu")))
            .union(x.inter(mst("o")).if_(y.has_all(mst("z"))))
            .union(
                x.inter(y)
                    .inter(mst("m"))
                    .if_(x.has_all(mst("e")) && (x.union(y)).has_all(mst("s"))),
            )
            .union(x.inter(y).inter(mst("zs")))
            .union(y.inter(mst("ufde")))
            .union(mst("x"))
            .union((x.union(y)).inter(mst("ghij")))
            .union(x.inter(y).inter(mst("k"))),
        Fragment::OrC => y
            .inter(mst("V"))
            .if_(x.has_all(mst("Bdu")))
            .union(x.inter(mst("o")).if_(y.has_all(mst("z"))))
            .union(
                x.inter(y)
                    .inter(mst("m"))
                    .if_(x.has_all(mst("e")) && (x.union(y)).has_all(mst("s"))),
            )
            .union(x.inter(y).inter(mst("zs")))
            .union(mst("fx"))
            .union((x.union(y)).inter(mst("ghij")))
            .union(x.inter(y).inter(mst("k"))),
        Fragment::OrI => x
            .inter(y)
            .inter(mst("VBKufs"))
            .union(mst("o").if_((x.inter(y)).has_all(mst("z"))))
            .union(
                (x.union(y))
                    .inter(mst("e"))
                    .if_((x.union(y)).has_all(mst("f"))),
            )
            .union(
                x.inter(y)
                    .inter(mst("m"))
                    .if_((x.union(y)).has_all(mst("s"))),
            )
            .union((x.union(y)).inter(mst("d")))
            .union(mst("x"))
            .union((x.union(y)).inter(mst("ghij")))
            .union(x.inter(y).inter(mst("k"))),
        Fragment::AndOr => (y.inter(z).inter(mst("BKV")))
            .if_(x.has_all(mst("Bdu")))
            .union(x.inter(y).inter(z).inter(mst("z")))
            .union(
                (x.union(y.inter(z)))
                    .inter(mst("o"))
                    .if_((x.union(y.inter(z))).has_all(mst("z"))),
            )
            .union(y.inter(z).inter(mst("u")))
            .union(
                z.inter(mst("f"))
                    .if_(x.has_all(mst("s")) || y.has_all(mst("f"))),
            )
            .union(z.inter(mst("d")))
            .union(
                z.inter(mst("e"))
                    .if_(x.has_all(mst("s")) || y.has_all(mst("f"))),
            )
            .union(
                x.inter(y)
                    .inter(z)
                    .inter(mst("m"))
                    .if_(x.has_all(mst("e")) && (x.union(y).union(z)).has_all(mst("s"))),
            )
            .union(z.inter(x.union(y)).inter(mst("s")))
            .union(mst("x"))
            .union((x.union(y).union(z)).inter(mst("ghij")))
            .union(mst("k").if_(
                x.has_all(mst("k"))
                    && y.has_all(mst("k"))
                    && z.has_all(mst("k"))
                    && !tl_conflict(x, y),
            )),
        Fragment::Multi => mst("Bnudemsk"),
        Fragment::MultiA => mst("Budemsk"),
        Fragment::Thresh => {
            let mut all_e = true;
            let mut all_m = true;
            let mut args = 0u32;
            let mut num_s = 0usize;
            let mut acc_tl = mst("k");
            for (i, &t) in sub_types.iter().enumerate() {
                let need = if i == 0 { mst("Bdu") } else { mst("Wdu") };
                if !t.has_all(need) {
                    return Type(0);
                }
                if !t.has_all(mst("e")) {
                    all_e = false;
                }
                if !t.has_all(mst("m")) {
                    all_m = false;
                }
                if t.has_all(mst("s")) {
                    num_s += 1;
                }
                args += if t.has_all(mst("z")) {
                    0
                } else if t.has_all(mst("o")) {
                    1
                } else {
                    2
                };
                acc_tl =
                    acc_tl.union(t).inter(mst("ghij")).union(mst("k").if_(
                        acc_tl.inter(t).has_all(mst("k")) && (k <= 1 || !tl_conflict(acc_tl, t)),
                    ));
            }
            mst("Bdu")
                .union(mst("z").if_(args == 0))
                .union(mst("o").if_(args == 1))
                .union(mst("e").if_(all_e && num_s == n_subs))
                .union(mst("m").if_(all_e && all_m && num_s >= n_subs - k as usize))
                .union(mst("s").if_(num_s > n_subs - k as usize))
                .union(acc_tl)
        }
    }
}

/// `internal::ComputeScriptLen`.
fn compute_script_len(
    fragment: Fragment,
    sub0typ: Type,
    subsize: usize,
    k: u32,
    n_subs: usize,
    n_keys: usize,
    ctx: MsContext,
) -> usize {
    match fragment {
        Fragment::Just1 | Fragment::Just0 => 1,
        Fragment::PkK => {
            if is_tapscript(ctx) {
                33
            } else {
                34
            }
        }
        Fragment::PkH => 3 + 21,
        Fragment::Older | Fragment::After => 1 + build_script_len_num(k),
        Fragment::Hash256 | Fragment::Sha256 => 4 + 2 + 33,
        Fragment::Hash160 | Fragment::Ripemd160 => 4 + 2 + 21,
        Fragment::Multi => {
            1 + build_script_len_num(n_keys as u32) + build_script_len_num(k) + 34 * n_keys
        }
        Fragment::MultiA => (1 + 32 + 1) * n_keys + build_script_len_num(k) + 1,
        Fragment::AndV => subsize,
        Fragment::WrapV => subsize + subs_typ_x(sub0typ) as usize,
        Fragment::WrapS | Fragment::WrapC | Fragment::WrapN | Fragment::AndB | Fragment::OrB => {
            subsize + 1
        }
        Fragment::WrapA | Fragment::OrC => subsize + 2,
        Fragment::WrapD | Fragment::OrD | Fragment::OrI | Fragment::AndOr => subsize + 3,
        Fragment::WrapJ => subsize + 4,
        Fragment::Thresh => subsize + n_subs + build_script_len_num(k),
    }
}

fn subs_typ_x(t: Type) -> u32 {
    t.has_all(mst("x")) as u32
}

// ---- the string grammar (miniscript::FromString) ------------------

/// `ParseContext` — the parse stack machine states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pc {
    WrappedExpr,
    Expr,
    Swap,
    Alt,
    Check,
    DupIf,
    Verify,
    NonZero,
    ZeroNotEqual,
    WrapU,
    WrapT,
    AndN,
    AndV,
    AndB,
    AndOr,
    OrB,
    OrC,
    OrD,
    OrI,
    Thresh,
    Comma,
    CloseBracket,
}

/// `internal::FindNextChar` — index of `m` within the current paren
/// level, `-1` when a `)` comes first or it isn't found.
fn find_next_char(input: &[u8], m: u8) -> i64 {
    for (i, &c) in input.iter().enumerate() {
        if c == m {
            return i as i64;
        }
        if c == b')' {
            break;
        }
    }
    -1
}

/// `ToIntegral` — strict non-negative integer parse (no signs/junk).
fn to_i64(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// `const` — consume `s` if it prefixes `input`.
fn pconst(s: &str, input: &mut &[u8]) -> bool {
    if input.len() >= s.len() && &input[..s.len()] == s.as_bytes() {
        *input = &input[s.len()..];
        true
    } else {
        false
    }
}

/// `ParseKeyEnd` — a key expression ending at the next `)`.
fn parse_key_end<KC: KeyCtx>(input: &[u8], ctx: &mut KC) -> Option<(usize, i64)> {
    let key_size = find_next_char(input, b')');
    if key_size < 1 {
        return None;
    }
    let text = std::str::from_utf8(&input[..key_size as usize]).ok()?;
    let key = ctx.key_from_str(text)?;
    Some((key, key_size))
}

/// `ParseHexStrEnd` — a hex string ending at `)`, `expected_size` bytes.
fn parse_hex_str_end(input: &[u8], expected_size: usize) -> Option<(Vec<u8>, i64)> {
    let size = find_next_char(input, b')');
    if size < 1 {
        return None;
    }
    let text = std::str::from_utf8(&input[..size as usize]).ok()?;
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hash = crate::hex::decode(text).ok()?;
    if hash.len() != expected_size {
        return None;
    }
    Some((hash, size))
}

/// `BuildBack` — wrap the top two constructed nodes in `nt`.
fn build_back(ctx: MsContext, nt: Fragment, constructed: &mut Vec<Node>, reverse: bool) {
    let (Some(child), Some(other)) = (constructed.pop(), constructed.pop()) else {
        return;
    };
    let subs = if reverse {
        vec![child, other]
    } else {
        vec![other, child]
    };
    constructed.push(Node::new(ctx, nt, subs, Vec::new(), Vec::new(), 0));
}

/// `miniscript::FromString` / `internal::Parse` — the stack-machine
/// grammar. Returns the root `Node` (already dup-key-checked) or
/// `None` on any parse failure.
pub fn from_string<KC: KeyCtx>(text: &str, ctx: &mut KC) -> Option<Node> {
    let mut input = text.as_bytes();
    let ms_ctx = ctx.ms_context();
    let mut script_size: usize = 1;
    let max_size = max_script_size(ms_ctx) as usize;

    let mut to_parse: Vec<(Pc, i64, i64)> = vec![(Pc::WrappedExpr, -1, -1)];
    let mut constructed: Vec<Node> = Vec::new();

    // `parse_multi_exp` — multi()/multi_a() tail.
    macro_rules! parse_multi_exp {
        ($input:expr, $is_a:expr) => {{
            let input: &mut &[u8] = $input;
            let is_a: bool = $is_a;
            let max_keys = if is_a {
                MAX_PUBKEYS_PER_MULTI_A
            } else {
                MAX_PUBKEYS_PER_MULTISIG
            };
            let required_ctx = if is_a {
                MsContext::Tapscript
            } else {
                MsContext::P2wsh
            };
            let mut ok = ms_ctx == required_ctx;
            if ok {
                let next_comma = find_next_char(input, b',');
                if next_comma < 1 {
                    ok = false;
                } else {
                    let k = std::str::from_utf8(&(*$input)[..next_comma as usize])
                        .ok()
                        .and_then(to_i64);
                    match k {
                        Some(k) => {
                            *$input = &(*$input)[next_comma as usize + 1..];
                            let mut keys: Vec<usize> = Vec::new();
                            let mut comma = next_comma;
                            while comma != -1 && ok {
                                comma = find_next_char($input, b',');
                                let key_length = if comma == -1 {
                                    find_next_char($input, b')')
                                } else {
                                    comma
                                };
                                if key_length < 1 {
                                    ok = false;
                                    break;
                                }
                                let text =
                                    std::str::from_utf8(&(*$input)[..key_length as usize]).ok();
                                match text.and_then(|t| ctx.key_from_str(t)) {
                                    Some(key) => keys.push(key),
                                    None => {
                                        ok = false;
                                        break;
                                    }
                                }
                                *$input = &(*$input)[key_length as usize + 1..];
                            }
                            if ok && (keys.is_empty() || keys.len() > max_keys) {
                                ok = false;
                            }
                            if ok && (k < 1 || k > keys.len() as i64) {
                                ok = false;
                            }
                            if ok {
                                if is_a {
                                    script_size +=
                                        (1 + 32 + 1) * keys.len() + build_script_len_num(k as u32);
                                    constructed.push(Node::new(
                                        ms_ctx,
                                        Fragment::MultiA,
                                        Vec::new(),
                                        keys,
                                        Vec::new(),
                                        k as u32,
                                    ));
                                } else {
                                    script_size += 2
                                        + usize::from(keys.len() > 16)
                                        + usize::from(k > 16)
                                        + 34 * keys.len();
                                    constructed.push(Node::new(
                                        ms_ctx,
                                        Fragment::Multi,
                                        Vec::new(),
                                        keys,
                                        Vec::new(),
                                        k as u32,
                                    ));
                                }
                            }
                        }
                        None => ok = false,
                    }
                }
            }
            ok
        }};
    }

    while let Some((cur, n, k)) = to_parse.pop() {
        if script_size > max_size {
            return None;
        }
        match cur {
            Pc::WrappedExpr => {
                // Find a lowercase wrapper prefix ending at ':'.
                let mut colon_index = None;
                for (i, &b) in input.iter().enumerate().skip(1) {
                    if b == b':' {
                        colon_index = Some(i);
                        break;
                    }
                    if !b.is_ascii_lowercase() {
                        break;
                    }
                }
                let mut last_was_v = false;
                if let Some(ci) = colon_index {
                    for &w in input.iter().take(ci) {
                        if script_size > max_size {
                            return None;
                        }
                        match w {
                            b'a' => {
                                script_size += 2;
                                to_parse.push((Pc::Alt, -1, -1));
                            }
                            b's' => {
                                script_size += 1;
                                to_parse.push((Pc::Swap, -1, -1));
                            }
                            b'c' => {
                                script_size += 1;
                                to_parse.push((Pc::Check, -1, -1));
                            }
                            b'd' => {
                                script_size += 3;
                                to_parse.push((Pc::DupIf, -1, -1));
                            }
                            b'j' => {
                                script_size += 4;
                                to_parse.push((Pc::NonZero, -1, -1));
                            }
                            b'n' => {
                                script_size += 1;
                                to_parse.push((Pc::ZeroNotEqual, -1, -1));
                            }
                            b'v' => {
                                if last_was_v {
                                    return None;
                                }
                                to_parse.push((Pc::Verify, -1, -1));
                            }
                            b'u' => {
                                script_size += 4;
                                to_parse.push((Pc::WrapU, -1, -1));
                            }
                            b't' => {
                                script_size += 1;
                                to_parse.push((Pc::WrapT, -1, -1));
                            }
                            b'l' => {
                                script_size += 4;
                                constructed.push(Node::new(
                                    ms_ctx,
                                    Fragment::Just0,
                                    Vec::new(),
                                    Vec::new(),
                                    Vec::new(),
                                    0,
                                ));
                                to_parse.push((Pc::OrI, -1, -1));
                            }
                            _ => return None,
                        }
                        last_was_v = w == b'v';
                    }
                }
                to_parse.push((Pc::Expr, -1, -1));
                if let Some(ci) = colon_index {
                    input = &input[ci + 1..];
                }
            }
            Pc::Expr => {
                if pconst("0", &mut input) {
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Just0,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        0,
                    ));
                } else if pconst("1", &mut input) {
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Just1,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        0,
                    ));
                } else if pconst("pk(", &mut input) {
                    let (key, key_size) = parse_key_end(input, ctx)?;
                    let inner =
                        Node::new(ms_ctx, Fragment::PkK, Vec::new(), vec![key], Vec::new(), 0);
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::WrapC,
                        vec![inner],
                        Vec::new(),
                        Vec::new(),
                        0,
                    ));
                    input = &input[key_size as usize + 1..];
                    script_size += if is_tapscript(ms_ctx) { 33 } else { 34 };
                } else if pconst("pkh(", &mut input) {
                    let (key, key_size) = parse_key_end(input, ctx)?;
                    let inner =
                        Node::new(ms_ctx, Fragment::PkH, Vec::new(), vec![key], Vec::new(), 0);
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::WrapC,
                        vec![inner],
                        Vec::new(),
                        Vec::new(),
                        0,
                    ));
                    input = &input[key_size as usize + 1..];
                    script_size += 24;
                } else if pconst("pk_k(", &mut input) {
                    let (key, key_size) = parse_key_end(input, ctx)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::PkK,
                        Vec::new(),
                        vec![key],
                        Vec::new(),
                        0,
                    ));
                    input = &input[key_size as usize + 1..];
                    script_size += if is_tapscript(ms_ctx) { 32 } else { 33 };
                } else if pconst("pk_h(", &mut input) {
                    let (key, key_size) = parse_key_end(input, ctx)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::PkH,
                        Vec::new(),
                        vec![key],
                        Vec::new(),
                        0,
                    ));
                    input = &input[key_size as usize + 1..];
                    script_size += 23;
                } else if pconst("sha256(", &mut input) {
                    let (hash, size) = parse_hex_str_end(input, 32)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Sha256,
                        Vec::new(),
                        Vec::new(),
                        hash,
                        0,
                    ));
                    input = &input[size as usize + 1..];
                    script_size += 38;
                } else if pconst("ripemd160(", &mut input) {
                    let (hash, size) = parse_hex_str_end(input, 20)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Ripemd160,
                        Vec::new(),
                        Vec::new(),
                        hash,
                        0,
                    ));
                    input = &input[size as usize + 1..];
                    script_size += 26;
                } else if pconst("hash256(", &mut input) {
                    let (hash, size) = parse_hex_str_end(input, 32)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Hash256,
                        Vec::new(),
                        Vec::new(),
                        hash,
                        0,
                    ));
                    input = &input[size as usize + 1..];
                    script_size += 38;
                } else if pconst("hash160(", &mut input) {
                    let (hash, size) = parse_hex_str_end(input, 20)?;
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Hash160,
                        Vec::new(),
                        Vec::new(),
                        hash,
                        0,
                    ));
                    input = &input[size as usize + 1..];
                    script_size += 26;
                } else if pconst("after(", &mut input) {
                    let arg_size = find_next_char(input, b')');
                    if arg_size < 1 {
                        return None;
                    }
                    let num = std::str::from_utf8(&input[..arg_size as usize])
                        .ok()
                        .and_then(to_i64)?;
                    if !(1..0x8000_0000).contains(&num) {
                        return None;
                    }
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::After,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        num as u32,
                    ));
                    input = &input[arg_size as usize + 1..];
                    script_size += 1
                        + usize::from(num > 16)
                        + usize::from(num > 0x7f)
                        + usize::from(num > 0x7fff)
                        + usize::from(num > 0x7fffff);
                } else if pconst("older(", &mut input) {
                    let arg_size = find_next_char(input, b')');
                    if arg_size < 1 {
                        return None;
                    }
                    let num = std::str::from_utf8(&input[..arg_size as usize])
                        .ok()
                        .and_then(to_i64)?;
                    if !(1..0x8000_0000).contains(&num) {
                        return None;
                    }
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Older,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        num as u32,
                    ));
                    input = &input[arg_size as usize + 1..];
                    script_size += 1
                        + usize::from(num > 16)
                        + usize::from(num > 0x7f)
                        + usize::from(num > 0x7fff)
                        + usize::from(num > 0x7fffff);
                } else if pconst("multi(", &mut input) {
                    if !parse_multi_exp!(&mut input, false) {
                        return None;
                    }
                } else if pconst("multi_a(", &mut input) {
                    if !parse_multi_exp!(&mut input, true) {
                        return None;
                    }
                } else if pconst("thresh(", &mut input) {
                    let next_comma = find_next_char(input, b',');
                    if next_comma < 1 {
                        return None;
                    }
                    let k = std::str::from_utf8(&input[..next_comma as usize])
                        .ok()
                        .and_then(to_i64)?;
                    if k < 1 {
                        return None;
                    }
                    input = &input[next_comma as usize + 1..];
                    to_parse.push((Pc::Thresh, 1, k));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    script_size += 2
                        + usize::from(k > 16)
                        + usize::from(k > 0x7f)
                        + usize::from(k > 0x7fff)
                        + usize::from(k > 0x7fffff);
                } else if pconst("andor(", &mut input) {
                    to_parse.push((Pc::AndOr, -1, -1));
                    to_parse.push((Pc::CloseBracket, -1, -1));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    to_parse.push((Pc::Comma, -1, -1));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    to_parse.push((Pc::Comma, -1, -1));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    script_size += 5;
                } else {
                    let (pc, add) = if pconst("and_n(", &mut input) {
                        (Pc::AndN, 5)
                    } else if pconst("and_b(", &mut input) {
                        (Pc::AndB, 2)
                    } else if pconst("and_v(", &mut input) {
                        (Pc::AndV, 1)
                    } else if pconst("or_b(", &mut input) {
                        (Pc::OrB, 2)
                    } else if pconst("or_c(", &mut input) {
                        (Pc::OrC, 3)
                    } else if pconst("or_d(", &mut input) {
                        (Pc::OrD, 4)
                    } else if pconst("or_i(", &mut input) {
                        (Pc::OrI, 4)
                    } else {
                        return None;
                    };
                    to_parse.push((pc, -1, -1));
                    to_parse.push((Pc::CloseBracket, -1, -1));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    to_parse.push((Pc::Comma, -1, -1));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    script_size += add;
                }
            }
            Pc::Alt => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapA,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::Swap => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapS,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::Check => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapC,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::DupIf => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapD,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::NonZero => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapJ,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::ZeroNotEqual => {
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapN,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::Verify => {
                script_size += subs_typ_x(constructed.last()?.typ) as usize;
                let sub = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::WrapV,
                    vec![sub],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::WrapU => {
                let sub = constructed.pop()?;
                let zero = Node::new(
                    ms_ctx,
                    Fragment::Just0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    0,
                );
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::OrI,
                    vec![sub, zero],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::WrapT => {
                let sub = constructed.pop()?;
                let one = Node::new(
                    ms_ctx,
                    Fragment::Just1,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    0,
                );
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::AndV,
                    vec![sub, one],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::AndB => build_back(ms_ctx, Fragment::AndB, &mut constructed, false),
            Pc::AndN => {
                let mid = constructed.pop()?;
                let left = constructed.pop()?;
                let zero = Node::new(
                    ms_ctx,
                    Fragment::Just0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    0,
                );
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::AndOr,
                    vec![left, mid, zero],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::AndV => build_back(ms_ctx, Fragment::AndV, &mut constructed, false),
            Pc::OrB => build_back(ms_ctx, Fragment::OrB, &mut constructed, false),
            Pc::OrC => build_back(ms_ctx, Fragment::OrC, &mut constructed, false),
            Pc::OrD => build_back(ms_ctx, Fragment::OrD, &mut constructed, false),
            Pc::OrI => build_back(ms_ctx, Fragment::OrI, &mut constructed, false),
            Pc::AndOr => {
                let right = constructed.pop()?;
                let mid = constructed.pop()?;
                let left = constructed.pop()?;
                constructed.push(Node::new(
                    ms_ctx,
                    Fragment::AndOr,
                    vec![left, mid, right],
                    Vec::new(),
                    Vec::new(),
                    0,
                ));
            }
            Pc::Thresh => {
                if input.is_empty() {
                    return None;
                }
                if input[0] == b',' {
                    input = &input[1..];
                    to_parse.push((Pc::Thresh, n + 1, k));
                    to_parse.push((Pc::WrappedExpr, -1, -1));
                    script_size += 2;
                } else if input[0] == b')' {
                    if k > n {
                        return None;
                    }
                    input = &input[1..];
                    let mut subs = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        subs.push(constructed.pop()?);
                    }
                    subs.reverse();
                    constructed.push(Node::new(
                        ms_ctx,
                        Fragment::Thresh,
                        subs,
                        Vec::new(),
                        Vec::new(),
                        k as u32,
                    ));
                } else {
                    return None;
                }
            }
            Pc::Comma => {
                if input.first() != Some(&b',') {
                    return None;
                }
                input = &input[1..];
            }
            Pc::CloseBracket => {
                if input.first() != Some(&b')') {
                    return None;
                }
                input = &input[1..];
            }
        }
    }

    debug_assert_eq!(constructed.len(), 1);
    debug_assert_eq!(constructed[0].scriptlen, script_size);
    if !input.is_empty() {
        return None;
    }
    let mut node = constructed.into_iter().next()?;
    node.duplicate_key_check(ctx);
    Some(node)
}
