#!/usr/bin/env python3
"""make_spend_fixture.py -- generate a spend-dense regtest block
fixture for connect_bench / diff tooling.

Spins up nothing itself: point it at a running regtest reference
daemon (Knots/Core -regtest -server). Funds a wallet, then produces
BLOCKS blocks each containing SENDS real wallet-signed txs
(P2WPKH spends — genuine ECDSA checksig work on replay), sealed via
`generateblock` and dumped in `[magic][len][block]` wire format.

Usage:
  python3 tools/make_spend_fixture.py \
      --core 127.0.0.1:19500 --core-cookie /tmp/perf-knots/regtest/.cookie \
      --out /tmp/spend-fixture.dat --blocks 300 --sends 40
"""

import argparse
import base64
import json
import sys
import urllib.request

MAGIC = bytes([0xfa, 0xbf, 0xb5, 0xda])  # regtest


class Node:
    def __init__(self, addr, cookie_path, path=""):
        self.url = f"http://{addr}/{path}"
        cookie = open(cookie_path).read().strip()
        self.auth = "Basic " + base64.b64encode(cookie.encode()).decode()
        self._id = 0

    def call(self, method, *params):
        self._id += 1
        body = json.dumps({"method": method, "params": list(params), "id": self._id}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Authorization": self.auth})
        try:
            return json.load(urllib.request.urlopen(req, timeout=60))["result"]
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method}: {e.read().decode()[:200]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--core-cookie", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--blocks", type=int, default=300)
    ap.add_argument("--sends", type=int, default=40)
    ap.add_argument("--fund-blocks", type=int, default=120)
    args = ap.parse_args()

    core = Node(args.core, args.core_cookie)
    wallet = Node(args.core, args.core_cookie, "wallet/fixture")

    try:
        wallet.call("loadwallet", "fixture")
    except RuntimeError as e:
        if "already loaded" in str(e):
            pass
        elif "does not exist" in str(e):
            wallet.call("createwallet", "fixture")
        elif "already exists" in str(e):
            # Directory exists but unloaded — wipe and recreate.
            import shutil, os
            shutil.rmtree(os.path.join(os.path.dirname(args.core_cookie), "..", "wallets", "fixture"), ignore_errors=True)
            wallet.call("createwallet", "fixture")
        else:
            raise

    addr = wallet.call("getnewaddress")
    tip = core.call("getblockcount")
    if tip < args.fund_blocks:
        wallet.call("generatetoaddress", args.fund_blocks - tip, addr)

    # Spread funding: a few sendmany txs fan the wallet out into
    # thousands of confirmed 0.5-coin UTXOs, so every bench-block send
    # spends a *confirmed* input — no unconfirmed chains, no mempool
    # ancestor limits.
    spread = max(4, args.blocks * args.sends // 200 + 2)
    for _ in range(spread):
        outs = {}
        for _ in range(200):
            outs[wallet.call("getnewaddress")] = 0.5
        wallet.call("sendmany", "", outs, None, "", [], True, None, "unset", 1)
        wallet.call("generatetoaddress", 1, addr)

    f = open(args.out, "wb")

    def dump(hash_):
        raw = bytes.fromhex(core.call("getblock", hash_, 0))
        f.write(MAGIC + len(raw).to_bytes(4, "little") + raw)

    # Funding blocks are parents + coin sources — the fixture must be
    # self-contained from height 1.
    tip = core.call("getblockcount")
    for h in range(1, tip + 1):
        dump(core.call("getblockhash", h))
    written = tip

    for b in range(args.blocks):
        for _ in range(args.sends):
            dst = wallet.call("getnewaddress")
            try:
                wallet.call("send", {dst: 0.001}, None, None, 1)
            except RuntimeError as e:
                if b == 0:
                    raise
                print(f"    block {b}: send stopped early ({e})", file=sys.stderr)
                break
        dump(wallet.call("generatetoaddress", 1, addr)[0])
        written += 1
        if written % 50 == 0:
            print(f"  {written} blocks", file=sys.stderr, flush=True)
    f.close()
    print(f"wrote {written} blocks -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
