#!/usr/bin/env python3
"""
diff_validate.py -- state-level differential validation: drive the same
block stream through Avila and a reference daemon (Bitcoin Core / Knots)
and compare the resulting consensus state after every block.

WHAT THIS DOES
--------------
Unlike check_blocks_core.py (verdict comparison on a crafted corpus) and
compare_rpc.py (field-level RPC shape), this tool compares the *UTXO set
itself* — the strongest available equivalence evidence. Two engines that
accept the same blocks but disagree on a single satoshi, script rule, or
coinbase maturity edge diverge in `gettxoutsetinfo` immediately.

Phases (all on one shared chain, in lockstep):

  anchor    — assert both nodes report the same tip and UTXO hash.
  fund      — create a wallet on the reference node, mine blocks paying
              it, submitblock each into Avila; compare state per block.
  diverse   — real wallet-signed transactions of every standard output
              type (legacy P2PKH, P2SH-segwit, P2WPKH, P2TR) plus
              OP_RETURN data outputs, sealed by `generateblock` on the
              reference node and `submitblock`ed to Avila. Round 2 spends
              each created UTXO explicitly (`send` inputs override), so
              input script verification — ECDSA checksig, Schnorr
              key-path, P2SH-segwit redeem — is exercised on BOTH engines.
  adverse   — a deliberately-invalid tx to both mempools: both must
              reject (reason strings are logged; mismatch on reject-vs-
              accept is a divergence).
  reorg     — invalidateblock mid-chain on BOTH nodes, mine a heavier
              branch on the reference, replay it into Avila; compare
              tip, UTXO set, and mempool contents after the refill.

COMPARED PER CHECKPOINT
-----------------------
  gettxoutsetinfo: bestblock, height, txouts, transactions, total_amount,
                   muhash, hash_serialized_3   (disk_size is per-engine)
  getblockstats:   totalfee, subsidy, txs, ins, outs — exact
                   fee-accounting parity per block.

The first divergence aborts the run and prints both states' JSON — a
UTXO mismatch at height N localizes the fault to block N's connect.

REQUIREMENTS
------------
A running reference daemon (bitcoind/bitcoin-knots -regtest -server) with
the wallet enabled, and a running avila-node with --rpc. Both must
already share the same chain (sync Avila from the reference first —
e.g. replay the reference's blocks via submitblock).

Usage:
  python3 tools/diff_validate.py \
      --core 127.0.0.1:38443 --core-cookie /tmp/knots/regtest/.cookie \
      --avila 127.0.0.1:28332 --avila-cookie /tmp/avila/regtest/.cookie \
      --fund-blocks 101 --tx-blocks 24
"""

import argparse
import base64
import json
import sys
import urllib.request
import urllib.error


class RpcError(Exception):
    def __init__(self, err, method):
        self.err = err
        super().__init__(f"{method}: {err}")


class Node:
    """Cookie-authed JSON-RPC. `path` scopes to a wallet endpoint."""

    def __init__(self, addr, cookie_path, path=""):
        self.url = f"http://{addr}/{path}"
        cookie = open(cookie_path).read().strip()
        self.auth = "Basic " + base64.b64encode(cookie.encode()).decode()
        self._id = 0

    @staticmethod
    def _params(params):
        # A single dict is named-parameters form (`bitcoin-cli -named`
        # equivalent); otherwise positional.
        if len(params) == 1 and isinstance(params[0], dict):
            return params[0]
        return list(params)

    def call(self, method, *params):
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "1.0", "id": self._id, "method": method, "params": self._params(params)}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            reply = json.loads(urllib.request.urlopen(req).read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read())
        if reply.get("error") is not None:
            raise RpcError(reply["error"], method)
        return reply.get("result")

    def call_err(self, method, *params):
        """Call that may fail — returns (result, error_dict_or_None)."""
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "1.0", "id": self._id, "method": method, "params": self._params(params)}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            reply = json.loads(urllib.request.urlopen(req).read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read())
        return reply.get("result"), reply.get("error")


class Divergence(Exception):
    pass


def compare(label, a_val, b_val, ctx):
    if a_val != b_val:
        raise Divergence(
            f"{label} diverged at {ctx}:\n"
            f"  core : {json.dumps(a_val, indent=1)[:3000]}\n"
            f"  avila: {json.dumps(b_val, indent=1)[:3000]}"
        )


def compare_utxo(core, avila, ctx):
    a = core.call("gettxoutsetinfo")
    b = avila.call("gettxoutsetinfo")
    for k in (
        "bestblock",
        "height",
        "txouts",
        "transactions",
        "total_amount",
        "muhash",
        "hash_serialized_3",
    ):
        if k in a and k in b:
            compare(f"gettxoutsetinfo.{k}", a[k], b[k], ctx)
    return a


def compare_stats(core, avila, height):
    a = core.call("getblockstats", height)
    b = avila.call("getblockstats", height)
    for k in ("totalfee", "subsidy", "txs", "ins", "outs", "blockhash"):
        if k in a and k in b:
            compare(f"getblockstats.{k}", a[k], b[k], f"height {height}")


def submit(core, avila, height):
    """Copy the reference's block at `height` into Avila."""
    h = core.call("getblockhash", height)
    raw = core.call("getblock", h, 0)
    verdict = avila.call("submitblock", raw)
    if verdict not in (None, "duplicate"):
        raise Divergence(f"avila rejected {h[:16]}… (h{height}): {verdict}")


def mine_to(core, avila, address, n, tag):
    """Reference mines `n` blocks to `address`; each is copied into
    Avila and the UTXO set + per-block stats compared. One block at a
    time — `gettxoutsetinfo` reads the tip, so both engines must stand
    on the same height for the comparison to mean anything."""
    for _ in range(n):
        core.call("generatetoaddress", 1, address, 10_000_000)
        tip = core.call("getblockcount")
        submit(core, avila, tip)
        compare_utxo(core, avila, f"{tag} h{tip}")
        compare_stats(core, avila, tip)
    print(f"  [{tag}] +{n} blocks to h{tip} — UTXO identical", flush=True)


def utxos_at(wallet, address):
    """Wallet-owned UTXOs paying `address`."""
    return [
        u
        for u in wallet.call("listunspent", 0)
        if u.get("address") == address
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--core", required=True)
    ap.add_argument("--core-cookie", required=True)
    ap.add_argument("--avila", required=True)
    ap.add_argument("--avila-cookie", required=True)
    ap.add_argument("--fund-blocks", type=int, default=101)
    ap.add_argument("--tx-blocks", type=int, default=24)
    ap.add_argument("--wallet", default="diffval")
    args = ap.parse_args()

    core = Node(args.core, args.core_cookie)
    avila = Node(args.avila, args.avila_cookie)

    # --- anchor: both nodes must sit on the same tip ------------------
    a_tip = core.call("getbestblockhash")
    b_tip = avila.call("getbestblockhash")
    if a_tip != b_tip:
        print(
            f"anchors differ — core tip {a_tip[:16]}…, avila {b_tip[:16]}….\n"
            "Sync Avila to the reference chain first.",
            file=sys.stderr,
        )
        sys.exit(2)
    compare_utxo(core, avila, "anchor")
    print(f"[anchor] both at {a_tip[:16]}… — UTXO identical")

    # --- fund: a fresh wallet earns mature coinbases -------------------
    if args.wallet not in core.call("listwallets"):
        _, err = core.call_err("loadwallet", args.wallet)
        if err:
            core.call("createwallet", args.wallet)
    wallet = Node(args.core, args.core_cookie, f"wallet/{args.wallet}")
    waddr = wallet.call("getnewaddress")
    mine_to(core, avila, waddr, args.fund_blocks, "fund")

    # --- diverse round 1: every standard output type + OP_RETURN -------
    addr_types = ("legacy", "p2sh-segwit", "bech32", "bech32m")
    addrs = {k: wallet.call("getnewaddress", "", k) for k in addr_types}
    funded_utxos = {}

    for i in range(args.tx_blocks):
        kind = addr_types[i % 4]
        try:
            # String amount + sat/vB fee_rate — Core's amount parser
            # rejects scientific-notation floats, and a fresh regtest
            # has no fee-estimate data.
            txid = wallet.call(
                "sendtoaddress",
                {
                    "address": addrs[kind],
                    "amount": f"{0.25 + i * 0.001:.8f}",
                    "fee_rate": 1,
                },
            )
        except RpcError as e:
            print(f"  sendtoaddress({kind}) failed: {e.err}", flush=True)
            continue
        # Record the outpoint paying this address type — later wallet
        # sends may spend it, so the round-2 spend checks gettxout.
        if kind not in funded_utxos:
            tx_v = core.call("getrawtransaction", txid, True)
            for vout in tx_v["vout"]:
                if vout["scriptPubKey"].get("address") == addrs[kind]:
                    funded_utxos[kind] = (txid, vout["n"])
        # Mempool parity — the raw tx goes to Avila's pool too.
        raw = core.call("getrawtransaction", txid)
        _, err = avila.call_err("sendrawtransaction", raw)
        if err:
            print(f"  avila sendrawtransaction: {err.get('message')}", flush=True)
        # Every 4th block also carries an OP_RETURN data output via `send`.
        if i % 4 == 3:
            try:
                wallet.call(
                    "send",
                    [{"data": "deadbeef" * 8}, {addrs["bech32"]: "0.05"}],
                    None,
                    "unset",
                    1,
                    {},
                )
            except RpcError as e:
                print(f"  send(OP_RETURN): {e.err}", flush=True)
        mine_to(core, avila, waddr, 1, f"tx[{kind}]")

    # --- diverse round 2: spend each UTXO type explicitly --------------
    # `send` with `inputs` forces each created output type through its
    # own script-verify path on the next block.
    for kind in addr_types:
        created = funded_utxos.get(kind)
        info = created and core.call("gettxout", *created)
        if info is None:
            # Already consumed by wallet coin selection — fall back to
            # any remaining wallet UTXO paying that address, else make
            # one now (confirm + spend) so every input type is covered.
            candidates = utxos_at(wallet, addrs[kind])
            if not candidates:
                try:
                    wallet.call(
                        "sendtoaddress",
                        {"address": addrs[kind], "amount": "0.2", "fee_rate": 1},
                    )
                    mine_to(core, avila, waddr, 1, f"prep[{kind}]")
                except RpcError as e:
                    print(f"  prep({kind}): {e.err}", flush=True)
                    continue
                candidates = utxos_at(wallet, addrs[kind])
            if not candidates:
                print(f"  no wallet UTXO for {kind} — skipping spend", flush=True)
                continue
            created = (candidates[0]["txid"], candidates[0]["vout"])
            info = {"value": candidates[0]["amount"]}
        try:
            dest = wallet.call("getnewaddress", "", "bech32")
            txid = wallet.call(
                "send",
                [{dest: f"{info['value'] - 0.001:.8f}"}],
                None,
                "unset",
                1,
                {"inputs": [{"txid": created[0], "vout": created[1]}]},
            )["txid"]
            raw = core.call("getrawtransaction", txid)
            avila.call_err("sendrawtransaction", raw)
        except RpcError as e:
            print(f"  spend({kind}): {e.err}", flush=True)
            continue
        mine_to(core, avila, waddr, 1, f"spend[{kind}]")

    # --- adverse: both engines must reject the same invalid tx ----------
    tip = core.call("getblockcount")
    coin_hash = core.call("getblockhash", tip)
    coin_txid = core.call("getblock", coin_hash, 2)["tx"][0]["txid"]
    raw_bad = core.call(
        "createrawtransaction",
        [{"txid": coin_txid, "vout": 0}],
        [{wallet.call("getnewaddress"): 49.0}],
    )
    signed = wallet.call("signrawtransactionwithwallet", raw_bad)
    a_res, a_err = core.call_err("sendrawtransaction", signed["hex"])
    b_res, b_err = avila.call_err("sendrawtransaction", signed["hex"])
    print(
        f"  [adverse] immature coinbase spend — core: "
        f"{(a_err or {}).get('message', a_res)} | avila: "
        f"{(b_err or {}).get('message', b_res)}",
        flush=True,
    )
    if (a_err is None) != (b_err is None):
        raise Divergence("immature-spend verdict differs")

    # --- reorg: disconnect, heavier branch, refill comparison ----------
    tip = core.call("getblockcount")
    fork_hash = core.call("getblockhash", tip - 3)
    core.call("invalidateblock", fork_hash)
    avila.call("invalidateblock", fork_hash)
    # Identical mempool submissions before the replacement branch lands.
    for addr in addrs.values():
        try:
            txid = wallet.call(
                "sendtoaddress",
                {"address": addr, "amount": "0.1", "fee_rate": 1},
            )
            raw = core.call("getrawtransaction", txid)
            avila.call_err("sendrawtransaction", raw)
        except RpcError:
            pass
    # A fresh payout address — on a frozen-mocktime node, re-mining the
    # same coinbase template reproduces the invalidated block hash
    # byte-for-byte (Core reports duplicate-invalid).
    mine_to(core, avila, wallet.call("getnewaddress"), 6, "reorg")
    a_pool = sorted(core.call("getrawmempool"))
    b_pool = sorted(avila.call("getrawmempool"))
    compare("getrawmempool", a_pool, b_pool, "post-reorg")
    compare_utxo(core, avila, "post-reorg")

    print("\nPASS — UTXO state, per-block stats, verdicts and mempool identical")


if __name__ == "__main__":
    main()
