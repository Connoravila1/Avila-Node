# Verified-artifact bundle: distribution format

Status: design spec — every piece below has a working implementation
or measured prototype; the *packaging* (one reproducible artifact) is
what's specified here.

## The problem

Avila's speedups share one shape: **precomputed hints, verified before
use, never trusted**. Three artifacts already exist:

1. **Snapshot file** — Core-format `utxo.dat`, verified against the
   chainparams `AssumeutxoHash` (`snapverify.rs`,
   `activate_snapshot_overlay`).
2. **Sparse group index** — `SnapshotRun`'s per-stride first-key table,
   regenerable by anyone holding the file (`sortedrun.rs::index`).
3. **SHA-256 midstate hints** — `snapverify::Hint` records splitting
   the commitment check into parallel intervals
   (`snapverify.rs` module docs).
4. **ECDSA sig-advice** — astra's replay: R-point data per sig,
   verified against signature algebra; 23.7% CPU reduction retained,
   ~24× smaller sidecar (`2026-09-24-ecdsa-advice-economics.md`).

Each travels separately today. A node wanting the ~90s-to-usable path
needs them together — so the bundle is one file, one anchor, one
reproduction recipe.

## The anchor chain

Everything verifies against a single already-public commitment — the
chainparams `assumeutxo` table entry for the snapshot base:

```
hash_serialized_3  (chainparams — Core-compatible anchor)
        │
        ├─ snapshot file  → streaming SHA-256d equals it
        │       │
        │       ├─ sparse index  → rebuilt from the file, any mismatch
        │       │                  means the INDEX is wrong (discard,
        │       │                  re-index — the file is canonical)
        │       │
        │       ├─ midstate hints → each interval's end-state recomputed
        │       │                    from file bytes; wrong hints can
        │       │                    only cause fallback, never a pass
        │       │
        │       └─ sig-advice    → each R-point checked against the
        │                            signature algebra; a lying hint
        │                            fails verification, never accepts
        │
        └─ future artifacts anchor the same way
```

**The anchor is never the bundle's own hash.** A bundle hash would
only prove the bundle matches the *producer*; we anchor to what Core
already publishes (`hash_serialized_3` in chainparams / headers).
Producers cannot lie profitably — worst case is wasted CPU, never a
wrong acceptance.

## Invariants (non-negotiable)

1. **Slow path is forever first-class.** Every hint has a no-hint
   fallback; the blockchain remains the sole *required* input. If
   hints ever affect *what* is accepted rather than *how fast*, the
   design is broken by definition.
2. **Hints are recomputed, not believed.** Verification re-derives
   the claim from primary data and compares.
3. **Anyone can produce.** Every artifact regenerates from the
   snapshot file alone — no producer-only secret, no special
   hardware. (`index_with` and `verify_stream` both do this today.)
4. **Bounded bad-input cost.** A corrupt bundle's worst cost is the
   fallback path + bounded wasted work — never unbounded decode
   effort (sketch capacity caps, group-size bounds, interval caps).

## Layout (v0 — sidecar set, not a container)

v0 stays a **directory of files** rather than an invented container —
Core's snapshot format is already a streamable file; wrapping it adds
a format to review for no gain. The bundle IS the set:

```
<bundle-dir>/
    utxo.dat            # Core-format snapshot (unchanged — the anchor)
    utxo.index          # SnapshotRun sparse index
    utxo.midstates      # snapverify::Hint stream (8 words + off + coins)
    utxo.sigadvice      # astra's advice stream (per-sig R-points)
    MANIFEST            # sizes, strides, producer identity, version
```

`MANIFEST` (text, key=value — diffable, greppable, no parser needed):

```
version = 1
network = mainnet
base_blockhash = 0000…
base_height = 840000
coins_count = 169…
files:
  utxo.dat        <bytes>
  utxo.index      <bytes>   stride=65536
  utxo.midstates  <bytes>   spacing=67108864
  utxo.sigadvice  <bytes>
producer = <impl/version>        # informational only
```

## Consumption order (the ~90s path)

1. Read `MANIFEST` — sanity-check against local params.
2. `activate_snapshot_overlay("utxo.dat")` — one sequential pass:
   index builds, hash verifies on a worker (~seconds at mainnet with
   midstate hints, ~9s single-threaded without).
3. Midstates make step 2 parallel *now* rather than optional — apply
   them via `snapverify::verify_stream` with hints when present,
   plain single-pass otherwise.
4. Sig-advice loads lazily — consumed by the background-validation
   replay (post-activation), never blocking time-to-usable.
5. Missing/corrupt sidecars fall back independently: re-index, ignore
   hints, plain replay. The only fatal artifact is `utxo.dat` itself
   (it IS the state).

## Producer recipe (reproducibility contract)

Anyone with `utxo.dat` regenerates the full sidecar set:

- `utxo.index` — `SnapshotRun::index(path, 65536)` — one read.
- `utxo.midstates` — `snapverify::verify_stream` emits hints at 64 MiB
  spacing — one read (~17 KB output at mainnet).
- `utxo.sigadvice` — produced during an honest validation pass (the
  producer pays ~4 CPU-seconds extra over ordinary validation per
  astra's economics); NOT regenerable from the file alone — it needs
  the signature set, which lives in the *blocks*, not the snapshot.

That asymmetry is honest and belongs in the spec: **three artifacts
are file-derived; sig-advice is validation-derived.** A producer who
never validated cannot mint advice — which is exactly why advice
provenance means something, and why the manifest records the producer.

## What this buys

- **~90s to usable**: file download (bounded by link) + one-pass
  activate (seconds) — vs hours-to-days IBD or minutes for
  Core's import path.
- **Faster background validation**: midstates parallelize the
  commitment check; sig-advice cuts replay CPU ~24%.
- **One ecosystem, not three**: one fetch, one anchor, one manifest —
  the "advice economy" shipped as a single artifact.

## Open items

- **Sig-advice scope**: current prototype covers replayed history;
  the bundle needs it keyed to a *range* (which blocks' sigs) — the
  manifest must carry `advice_range = lo..hi`.
- **Container vs directory**: a single file helps transport
  (Content-Range, torrents); revisit once fetching is real.
- **Cross-verification**: sig-advice should also verify against the
  *block* it claims — bind `advice_range` to the base height so a
  bundle can't ship advice for a different chain.
- **Signing**: optional producer signatures ( informational
  provenance only — never part of the trust decision).
