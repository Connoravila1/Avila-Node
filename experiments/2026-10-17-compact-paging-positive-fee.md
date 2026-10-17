# Compact output paging and positive-fee rendering

This follow-up qualifies two previously open native GUI cases using the
already-installed attached GUI and real mainnet block data: output page 2 at
760×600, and display of a positive fee in selected transaction detail. It makes
no claim about completion of IBD or about whether matching undo was read from
the in-memory tail or persisted backend.

## Compact output paging

At 760×600 and 100% scale, block 275318
(`00000000000000028f7229a62048c5401bc1f9e939ff144c15abdf38c0c31091`, 1,339
transactions) was inspected. Transaction index 291,
`42af068a6fede69b672226affacb35083a6f4c226e17d0798f8f8436db272cf4`, has one
input and 111 outputs. With 500 transaction summaries loaded, the native view
showed output pages 1–100 → 101–111 → 1–100. The last page showed output index
100 at 0.01000000 BTC and no Next control. The attempt required request retries
and repositioning the outer page; this does not establish automatic retry.

This supersedes the earlier #92 attempt, which confirmed only page 1 at this
viewport. The earlier proof and its installed-binary hash remain historical and
unchanged. The previously verified 1440×900/100% path remains separately
recorded in the [output-paging note](2026-10-17-native-output-paging.md).

## Positive fee

At 760×600 and 1440×900, both at 100% scale, the view showed selected
transaction index 2 in active mainnet block 293782
(`00000000000000000fede2a0cc2ae865a2689baab5870ace25decda418cbfb5a`):

- Txid: `03fb74fc931fbcf8f0bf194cd5c97328f3459ef60b266f8305443e29711f1276`
- Inputs/outputs: 1 / 2
- Input total: 613.289 BTC
- Output total: 613.2889 BTC
- Fee: 10,000 sat (0.0001 BTC)
- Weight and virtual size: 900 WU / 225 vB
- Fee rate: 44.44 sat/vB
- Displayed source: matching block undo

The two viewport captures use the same retained detail lookup snapshot; resizing
did not make a fresh RPC request. The RPC identifies the amount source as block
undo but does not distinguish the in-memory undo tail from coinsdb. Therefore
this proves a known block-undo-derived positive fee in the GUI, not a specific
storage tier. Earlier candidates at blocks 291926 and 292819 returned positive
fees over RPC but displayed unknown after GUI detail errors/reselection; that is
consistent with incomplete persisted admission coverage, though exact tier and
timing were not proven. A third candidate search timed out and its GUI actions
were skipped. No GUI parsing defect was found in these attempts.

The bounded candidate finder was invoked four times. Each run had a 12-RPC-call
hard cap, a 2 MiB response cap, and a 15-second per-request timeout. The
successful fourth run used seven calls and completed in two seconds under a
128 MiB cap / 128 MiB reserve, peaking at 12 MiB. Finder timing is not GUI
latency evidence.

## Build identity, close behavior, and limits

No Rust source or binary changed for this follow-up. The tested GUI binary SHA-256
was `2d36a706dfbb69fcf1e7975d76b4d91e510bbdb646464fdfff3d3b5b4d42af9c`; its
source fingerprint was
`2007ef695d70273d2aa9723e7d82871065a386b9c00a739a00e708888b1ce96c` (source
commit `77f32fe`, build revision `fc95eda+dirty`). The native GUI run used a
512 MiB cap / 512 MiB reserve, peaked at 85 MiB over 431 seconds, and exited 0
with zero GUI windows after Node → Close monitor. The same CLI PID 1,358,692
was observed afterward at checked height 294,471 / 971,839 headers, with no AssumeValid
checkpoint and historical scripts required. IBD remains incomplete.

This is one selected transaction at 100% scale. Screen-reader behavior,
cross-platform behavior, missing-cookie recovery, automatic retry, general
delayed-RPC behavior, other zoom levels, and persisted undo availability for
databases with incomplete admission coverage remain unqualified.
