# Self-hosted mainnet Swift hint check

The published source candidate was `ba710e101cefc73ecdb6b89834631eda530a2869`
(tree `9a6c8470443cc5ecbaac0393cee5a1fe9c3bb52c`, public main commit
`156e874d7e2dd3708d9916f3fd9f731043c3bd44`). The scoped release tests,
Clippy, rustdoc, and formatting checks ran on the same tracked Rust source
blobs immediately before the source commit; the summary preserves observed
counts and outcomes but the original test stdout was not written to files. The
release CLI was built from the committed source and its artifact had SHA256
`dc64cf2d9a684239b355c143bfdfec835423d50bba85a39a1508830081576570`.
The fixture source is pinned at
`fixtures/mainnet-blocks-000000-000500.dat`, 114,278 bytes, SHA256
`ef9cb1e45eaaafa55d23016d7dfce3e8f64f56609573e18b9a8940b8b1ac3d73`.

`tools/swift_local_mainnet.py` parses only that bounded fixture, derives
untrusted BIP456 survivor hints and BIP455 spent-coin replies, and serves the
claims over a loopback v1 peer that advertises the BIP434 feature. Because this
500-block mainnet prefix is below the configured minimum-chain-work gate, the
tool first accepts the headers through the ordinary `submitheader` RPC on a
fresh private node. It preserves production mainnet parameters and then runs
three isolated phases: the Swift checkpoint, an ordinary `--assumevalid 0`
oracle, and a negative run with a mutated survivor hint. RPC/P2P endpoints are
loopback-only, runs are deadline and resource bounded, and no operator datadir
is opened by the tool.

The positive run served ten spent-coin claim records. Swift promoted height 500
with state version 5, fully validated pruned-history floor 212, snapshot base
zero, an externalized coin set and durable live index. Its h1 body was absent
below the rollback floor while the ordinary oracle retained its h1 body. The
ordinary and promoted states agreed on:

- height 500, block hash
  `000000004ff664bfa7d217f6df64c1627089061429408e1da5ef903b8f3c77db`;
- 503 live outputs;
- MuHash `2c374ef3463616c9785085b1d2430cd743f7457433d0b3d992305253d0bc6a6f`;
- full-validation coverage, no AssumeValid checkpoint, and historical script
  checks required.

In the negative control, the peer served ten claims but a false survivor hint
caused the full-coin audit to mismatch. The run exited without publishing the
Swift checkpoint. `operator_datadir_touched` was false.

The retained private result JSON has SHA256
`a9305403dfbf17f9063d612529754f934f2cf6890943f9f62b5ff42c6361d7e1`; the
guarded command output has SHA256
`efb1b67afa69e32708c351bd627a91303f976f42e3c4a4edee4944346ab298da`. The
release test gate summary is recorded privately in `validation/`; it is not
part of the source tree. Reproduce the experiment using the command in
[`tools/README-swift-local-mainnet.md`](../tools/README-swift-local-mainnet.md).

This is a self-supplied historical h0–500 correctness exercise, not modern
witness coverage, a deployed/public helper demonstration, or a first-time
mainnet IBD performance result. BIP455/BIP456 remain draft protocol inputs.
