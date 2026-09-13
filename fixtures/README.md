# Bitcoin chain fixtures

Real Bitcoin (mainnet), testnet4, and signet chain data, bounded in size,
used by consensus tests and benchmarks. All data is public blockchain
history; only small, fixed slices of it are committed here. Larger or
additional ranges should be produced on demand by re-running (a variant
of) `tools/fetch_fixtures.py`, not committed.

Total size of everything in this directory is kept under 1.3 MiB; every
individual block file is under 64 KiB.

## Files

### Header fixtures

Raw 80-byte block headers concatenated in height order, with **no** length
prefixes and **no** transaction counts (i.e. just `count * 80` bytes).

| File | Network | Heights | Count | Bytes | Notes |
|---|---|---|---|---|---|
| `mainnet-headers-000000-004031.bin` | mainnet | 0..=4031 | 4032 | 322560 | Genesis through two full difficulty periods (2016 blocks each). |
| `mainnet-headers-030229-032257.bin` | mainnet | 30229..=32257 | 2029 | 162320 | Contains mainnet's first real difficulty retarget: height 32256 has nBits `0x1d00d86a`, down from `0x1d00ffff` at height 32255. |
| `testnet4-headers-000000-004031.bin` | testnet4 | 0..=4031 | 4032 | 322560 | |
| `signet-headers-000000-002047.bin` | signet (default) | 0..=2047 | 2048 | 163840 | |

### Block fixtures

Raw serialized blocks (header + tx count + transactions, with witness data
included where present), exactly as returned by the source.

| File | Network | Height | Hash (display order) | tx_count | size | weight |
|---|---|---|---|---|---|---|
| `mainnet-block-000000.bin` | mainnet | 0 | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` | 1 | 285 | 1140 |
| `mainnet-block-000001.bin` | mainnet | 1 | `00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048` | 1 | 215 | 860 |
| `mainnet-block-000170.bin` | mainnet | 170 | `00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee` | 2 | 490 | 1960 |
| `mainnet-block-100000.bin` | mainnet | 100000 | `000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506` | 4 | 957 | 3828 |
| `mainnet-block-segwit-small.bin` | mainnet | 482229 (auto-selected) | `00000000000000000136ce1ea2813e3980c69ba6d1030e55910730edde2e43ea` | 31 | 9246 | 36876 |
| `mainnet-block-taproot-era-small.bin` | mainnet | 709645 (auto-selected) | `000000000000000000093c20b1a0cb944a26b22de731aa1be7cc6aa941d5122c` | 15 | 9183 | 24576 |
| `testnet4-block-000000.bin` | testnet4 | 0 | `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` | 1 | 261 | 1044 |
| `signet-block-000000.bin` | signet | 0 | `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` | 1 | 285 | 1140 |
| `signet-block-000001.bin` | signet | 1 | `00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53` | 1 | 329 | 1208 |

The two "small" blocks were chosen by scanning forward from the network's
segwit/taproot activation heights for the first block satisfying
`2 <= tx_count <= 60`, `size <= 32768`, and `weight < 4 * size` (the last
condition proves at least one non-coinbase transaction carries witness
data). See `fixtures/manifest.json` for the exact selection notes.

### Provenance and integrity

- `manifest.json` — machine-readable provenance for every fixture above:
  network, height range/hash(es), byte count, sha256, and the exact P2P
  peer or HTTPS URL that supplied it. Also records the sha256 of the full
  contiguous mainnet header run (heights 0..=32257) that was fetched in
  memory to produce the retarget-window fixture, plus the observed nBits
  at heights 32255/32256, under the `observed` key.
- `SHA256SUMS` — standard `sha256sum` manifest for every fixture binary.

## Verifying checksums

```sh
cd fixtures
sha256sum -c SHA256SUMS
```

## Regenerating

Everything here is reproducible from `tools/fetch_fixtures.py` (Python 3
standard library only, no dependencies):

```sh
python3 tools/fetch_fixtures.py            # regenerate every fixture + manifest
python3 tools/fetch_fixtures.py --only mainnet-block-100000.bin   # just one
python3 tools/fetch_fixtures.py --list     # list fixture names
```

Headers are fetched directly over the Bitcoin P2P protocol (TCP,
`version`/`verack` handshake, `getheaders`/`headers`, with the genesis
header itself pulled via a single `getdata`/`block` round trip since
`getheaders` never returns the header matched by its own locator). If P2P
is unavailable, the script falls back to fetching headers one at a time
over HTTPS from a public esplora-style API. Full blocks are always
fetched over HTTPS (Blockstream for mainnet with a mempool.space
fallback; mempool.space for testnet4/signet). Every header and block is
independently re-verified after being written (hash linkage, genesis
match, block-header-hash match) and the script's own summary re-checks
`sha256sum -c SHA256SUMS` as a final sanity check. See the module
docstring in `tools/fetch_fixtures.py` for full details.

## A note on scale

These files are deliberately tiny relative to the real chain (the
mainnet header set alone is currently hundreds of megabytes). They exist
to give consensus tests and benchmarks fast, deterministic, offline
access to a few real difficulty periods, the first real retarget, a
handful of well-known early blocks, and one small segwit-era and one
small taproot-era block with genuine witness data — not to mirror the
chain. If a test needs more data than this, extend
`tools/fetch_fixtures.py` and regenerate rather than committing larger
blobs.
