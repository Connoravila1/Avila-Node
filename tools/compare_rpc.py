#!/usr/bin/env python3
"""Field-level RPC compatibility comparison: Avila vs Bitcoin Core/Knots.

Calls the same method with the same parameters on both endpoints and
reports, per method: fields that match exactly, fields whose values
differ, and fields present on only one side. Both endpoints use Core's
`.cookie` auth (`__cookie__:<token>` over HTTP Basic).

This is evidence tooling, not a test suite: it prints a matrix and
writes JSON diffs to stdout. Dynamic or node-specific fields (time,
peer agents, uptime) are reported but flagged as EXPECTED-DIFF so a
human can separate honest divergence from real incompatibility.

Usage:
  python3 tools/compare_rpc.py \
      --avila 127.0.0.1:18443 --avila-cookie data/regtest/.cookie \
      --core 127.0.0.1:58321 --core-cookie <core-datadir>/regtest/.cookie \
      --height 100
"""

import argparse
import base64
import json
import sys
import urllib.request
import urllib.error


# Methods whose scalar results are inherently per-node — different
# text or counters — so any value difference is expected.
# `getrawmempool` (unverbose) reports pool membership itself — content
# differences are per-node state, not incompatibility.
# `savemempool` reports each daemon's own datadir path — presence is
# checked, the path value itself is per-installation.
DYNAMIC_METHODS = {"uptime", "help", "getrawmempool", "savemempool"}

# Keys whose values are legitimately node- or time-specific. They are
# still compared (structural presence is checked) but a value
# difference is reported as expected rather than a failure.
DYNAMIC_KEYS = {
    "time", "mediantime", "curtime", "mintime", "longpollid", "uptime",
    "connections", "connections_in", "connections_out", "relayfee",
    "incrementalfee", "bytes", "usage", "mempoolminfee", "minrelaytxfee",
    "difficulty", "chainwork", "verificationprogress", "initialblockdownload",
    "size_on_disk", "warnings", "subversion", "version", "protocolversion",
    "localservices", "localservicesnames", "localaddresses", "networks",
    "networkactive", "reachable", "proxy", "timeoffset", "getblocktemplate",
    "blocksonly", "networkhashps", "pooledtx", "currentblockweight",
    "currentblocktx", "currentblocksize", "errors", "header", "balance", "keypoolsize",
    "loaded", "pruned", "pruneheight", "automatic_pruning",
    "prune_target", "softforks", "unbans", "banscore", "deprecation",
    "startingheight", "synced_headers", "synced_blocks", "inflight",
    "addr_processed", "addr_rate_limited", "byterecv", "bytesrecv_per_msg",
    "bytessent", "bytessent_per_msg", "conntime", "last_block_time",
    "last_transaction", "lastannounce", "lastrecv", "lastsend",
    "minping", "pingtime", "pingwait", "presynced_headers",
    "synced_blocks", "synced_headers", "inbound", "bip152_hb_from",
    "bip152_hb_to", "permissions", "addr_relay_enabled", "addrfee_enabled",
    "transport_protocol_type", "session_id", "relaytxes", "minfeefilter",
    "services", "servicesnames", "feerate", "estimates", "headers",
    "commit", "target",
    # Pool-content dependent — diverge whenever the two mempools differ.
    "transactions", "coinbasevalue", "default_witness_commitment",
    # Direction-dependent — each daemon sees the other as the opposite
    # connection direction, so inbound-only fields legitimately differ.
    "addrbind", "addrlocal", "forced_inbound", "cpu_load",
    "last_block_announcement",
    # Pool-membership counters — we don't persist the pool across
    # restarts like Core's mempool.dat, so these reflect each daemon's
    # live pool.
    "size", "total_fee", "unbroadcastcount", "maxmempool",
    # getnettotals — cumulative wire bytes and wall-clock millis are
    # per-node counters.
    "totalbytesrecv", "totalbytessent", "timemillis",
}

# Method -> params factory. `h` is a recent height valid on both nodes;
# `hh` is its hash (resolved live so the caller needn't know it).
def build_calls(height):
    return [
        ("getblockcount", []),
        ("getbestblockhash", []),
        ("getblockchaininfo", []),
        ("getdifficulty", []),
        ("getblockhash", [height]),
        ("getblockheader", ["HASH"]),
        ("getblock", ["HASH", 1]),
        ("getblock", ["HASH", 0]),
        ("getblock", ["HASH", 2]),
        # Genesis at verbosity 0 exercises the synthesized body path —
        # Core serves genesis bytes from its blk files, we build them
        # from params; the payloads must be byte-identical.
        ("getblock", ["GHASH", 0]),
        # getblockstats: by height and by hash, genesis (synthesized
        # body), the stats filter, and the error paths.
        ("getblockstats", [height]),
        ("getblockstats", [0]),
        ("getblockstats", ["HASH"]),
        ("getblockstats", ["HASH", ["avgfee", "txs", "utxo_increase"]]),
        ("getblockstats", [999999]),
        ("getblockstats", ["deadbeef"]),
        ("getrawtransaction", ["TXID", 1]),
        ("gettxout", ["TXID", 0]),
        # decoderawtransaction: the shared-height coinbase hex plus
        # each error class — bad hex, bad tx, wrong-type iswitness.
        ("decoderawtransaction", ["RAWTX"]),
        ("decoderawtransaction", ["RAWTX", True]),
        ("decoderawtransaction", ["RAWTX", False]),
        ("decoderawtransaction", ["RAWTX", 2]),
        ("decoderawtransaction", ["zz"]),
        # gettxspendingprevout: an unspent outpoint (the coinbase's
        # vout 0 is unspent in both mempools' spend index — the
        # mempool only tracks *spends*, not UTXO membership) plus the
        # deterministic error paths.
        ("gettxspendingprevout", [[{"txid": "TXID", "vout": 0}]]),
        ("gettxspendingprevout", [[{"txid": "zz", "vout": 0}]]),
        ("gettxspendingprevout", [[{"vout": 0}]]),
        ("gettxspendingprevout", [[]]),
        ("getindexinfo", []),
        # decodescript: one call per standard template family — the
        # values below are regtest scripts exercised against Knots.
        ("decodescript", ["76a914ba602196720c6f0c47c823e106405d9b0dc71dc088ac"]),
        ("decodescript", ["51201d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb"]),
        ("decodescript", ["600228e0"]),
        ("decodescript", ["76"]),
        ("getchaintips", []),
        ("getmempoolinfo", []),
        ("getrawmempool", []),
        ("getnetworkinfo", []),
        ("getnettotals", []),
        ("getconnectioncount", []),
        ("getmininginfo", []),
        ("getblocktemplate", [{"rules": ["segwit"]}]),
        ("estimatesmartfee", [6]),
        ("estimatesmartfee", [0]),
        ("estimatesmartfee", ["x"]),
        ("estimatesmartfee", [6, "bogus"]),
        # getnetworkhashps: default window, -1 (since last retarget),
        # a specific height, and each error class.
        ("getnetworkhashps", []),
        ("getnetworkhashps", [-1]),
        ("getnetworkhashps", [120, height]),
        ("getnetworkhashps", [0]),
        ("getnetworkhashps", [120, 999999]),
        # sendrawtransaction: deterministic error paths only — a valid
        # tx can't be in the static matrix since pool state differs per
        # daemon (verified live separately).
        ("sendrawtransaction", ["00ff"]),
        ("sendrawtransaction", ["02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff010000000000000000015100000000"]),
        # Resubmitting a known block is deterministic: "duplicate" both
        # sides. The end-to-end mine+connect path is verified live.
        ("submitblock", ["BLOCKHEX"]),
        ("submitblock", ["aabb"]),
        ("uptime", []),
        ("getpeerinfo", []),
        ("getorphantxs", []),
        ("savemempool", []),
        # validateaddress: valid P2PKH/P2SH/bech32/bech32m plus each
        # error class — wrong-network, bad checksum, mixed case, junk.
        ("validateaddress", ["mzuLyXXJdpC2ZJvBwfZJz7vfRtWFzch3HE"]),
        ("validateaddress", ["2N16To2TZ3V9DaveY9e57kAGtKhVFuPCMbK"]),
        ("validateaddress", ["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]),
        ("validateaddress", ["BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080"]),
        ("validateaddress", ["bcrt1pnqmehk4fjszhda70em7gqsfyqx839hgjmnypf4esl5raq3sur33qp3q8s8"]),
        ("validateaddress", ["bcrt1znqmehk4fjszhda70em7gqsfyqx839hgjmnypf4esl5raq3sur33qfveg7v"]),
        ("validateaddress", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        ("validateaddress", ["bcrt1QW508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]),
        ("validateaddress", ["bcrt1p5xu6lmdlytyj4e3hajxw2u0jfyr8g7mh5zszs0axkzfq2tdlymqkwm4h7a"]),
        ("validateaddress", ["1111111111111111111114oLvT2"]),
        ("validateaddress", ["notanaddress"]),
        ("help", []),
        ("stop-token-check", None),  # placeholder, never called
    ]


def read_auth(cookie_path):
    with open(cookie_path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    return "Basic " + base64.b64encode(raw.encode()).decode()


def call(endpoint, auth, method, params, timeout=15):
    body = json.dumps({"method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(
        f"http://{endpoint}", data=body,
        headers={"Authorization": auth, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read())
            if payload.get("error") is not None:
                return ("rpc-error", payload["error"])
            return ("ok", payload.get("result"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
            if payload.get("error") is not None:
                return ("rpc-error", payload["error"])
        except Exception:
            pass
        return ("http-error", e.code)
    except Exception as e:
        return ("transport-error", str(e))


def flatten(obj, prefix=""):
    """Flatten nested JSON to 'path' -> scalar for field-level diffing."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        out[prefix.rstrip(".")] = f"<list[{len(obj)}]>"
        for i, v in enumerate(obj):
            if isinstance(v, dict):
                # Don't index list items positionally; compare the set of
                # keys the union of items carries instead.
                for k in v:
                    out.setdefault(f"{prefix}*.{k}", "<present>")
            else:
                out[f"{prefix}*"] = repr(v)
    else:
        out[prefix.rstrip(".")] = obj
    return out


def compare(a, c):
    """Return (matched, expected_diffs, diffs, only_a, only_c)."""
    fa, fc = flatten(a), flatten(c)
    matched, expected, diffs = [], [], []
    for k in sorted(fa.keys() & fc.keys()):
        parts = k.split(".")
        dynamic = bool(set(parts[-2:]) & DYNAMIC_KEYS)
        if fa[k] == fc[k]:
            matched.append(k)
        elif dynamic:
            expected.append((k, fa[k], fc[k]))
        else:
            diffs.append((k, fa[k], fc[k]))
    only_a = sorted(set(fa) - set(fc))
    only_c = sorted(set(fc) - set(fa))
    return matched, expected, diffs, only_a, only_c


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--avila", default="127.0.0.1:18443")
    p.add_argument("--avila-cookie", required=True)
    p.add_argument("--core", default="127.0.0.1:58321")
    p.add_argument("--core-cookie", required=True)
    p.add_argument("--height", type=int, default=100)
    args = p.parse_args()

    auth_a = read_auth(args.avila_cookie)
    auth_c = read_auth(args.core_cookie)

    # Resolve the block hash + a coinbase txid at the shared height so
    # both nodes answer identical queries.
    h = args.height
    s, core_hash = call(args.core, auth_c, "getblockhash", [h])
    if s != "ok":
        print(f"core unreachable or height invalid: {core_hash}")
        return 2
    s, core_block = call(args.core, auth_c, "getblock", [core_hash, 1])
    txid = core_block["tx"][0] if s == "ok" and core_block.get("tx") else None
    s, core_block_hex = call(args.core, auth_c, "getblock", [core_hash, 0])
    blockhex = core_block_hex if s == "ok" else None
    s, ghash = call(args.core, auth_c, "getblockhash", [0])
    ghash = ghash if s == "ok" else None
    # The coinbase's raw hex — named-block lookup works without a
    # txindex on the Core side.
    s, rawtx = call(args.core, auth_c, "getrawtransaction",
                    [txid, 0, core_hash]) if txid else ("err", None)
    rawtx = rawtx if s == "ok" else None

    calls = build_calls(h)
    total = {"MATCH": 0, "EXPECTED-DIFF": 0, "DIFFERS": 0,
             "AVILA-ERROR": 0, "CORE-ERROR": 0, "BOTH-ERROR": 0, "SKIPPED": 0}
    print(f"{'method':<24} {'result':<14} {'match':>5} {'exp':>4} {'diff':>4} "
          f"{'a-only':>6} {'c-only':>6}")
    print("-" * 78)
    for method, params in calls:
        if method == "stop-token-check":
            continue
        placeholders = {"HASH": core_hash, "TXID": txid,
                        "BLOCKHEX": blockhex, "GHASH": ghash,
                        "RAWTX": rawtx}

        def resolve(v):
            if isinstance(v, str) and v in placeholders:
                return placeholders[v]
            if isinstance(v, list):
                return [resolve(x) for x in v]
            if isinstance(v, dict):
                return {k: resolve(x) for k, x in v.items()}
            return v

        resolved = resolve(params)

        def has_none(v):
            if v is None:
                return True
            if isinstance(v, list):
                return any(has_none(x) for x in v)
            if isinstance(v, dict):
                return any(has_none(x) for x in v.values())
            return False

        if has_none(resolved):
            total["SKIPPED"] += 1
            continue
        sa, ra = call(args.avila, auth_a, method, resolved)
        sc, rc = call(args.core, auth_c, method, resolved)
        if sa != "ok" and sc != "ok":
            print(f"{method:<24} {'BOTH-ERROR':<14}")
            total["BOTH-ERROR"] += 1
            continue
        if sa != "ok":
            print(f"{method:<24} {'AVILA-ERROR':<14} {str(ra)[:50]}")
            total["AVILA-ERROR"] += 1
            continue
        if sc != "ok":
            print(f"{method:<24} {'CORE-ERROR':<14} {str(rc)[:50]}")
            total["CORE-ERROR"] += 1
            continue
        matched, expected, diffs, only_a, only_c = compare(ra, rc)
        if diffs and method in DYNAMIC_METHODS:
            expected.extend(diffs)
            diffs = []
        verdict = "MATCH" if not diffs and not only_a and not only_c \
            else "EXPECTED-DIFF" if not diffs else "DIFFERS"
        total[verdict] += 1
        print(f"{method:<24} {verdict:<14} {len(matched):>5} "
              f"{len(expected):>4} {len(diffs):>4} {len(only_a):>6} "
              f"{len(only_c):>6}")
        for k, va, vc in diffs:
            print(f"    DIFF  {k}: avila={str(va)[:40]!r} core={str(vc)[:40]!r}")
        for k in only_a:
            print(f"    A-ONLY {k}")
        for k in only_c:
            print(f"    C-ONLY {k}")
    print("-" * 78)
    print("summary:", " ".join(f"{k}={v}" for k, v in total.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
