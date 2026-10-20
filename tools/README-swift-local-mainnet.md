# Self-hosted Swift IBD check

`swift_local_mainnet.py` exercises the installed CLI's opt-in Swift path with
the checked-in mainnet block slice from heights 0 through 500. It derives the
BIP456 survivor hints and BIP455 spent-coin replies from those same blocks,
serves them over loopback TCP, and compares the promoted database with an
ordinary `--assumevalid 0` replay of the same slice. A second run mutates one
survivor hint and requires the audit to reject it without publishing the Swift
checkpoint.

The helper first seeds a private, header-only datadir by submitting all 500
fixture headers through the CLI's ordinary `submitheader` RPC. This lets the
low-work fixture prefix use the production mainnet parameters unchanged. The
header seed, Swift sync, ordinary oracle, and negative control each use fresh
private datadirs. RPC and P2P listeners/connects are loopback-only. The script
checks the fixture's exact size and SHA256, uses strict parser, byte, count and
deadline limits, and preserves its private work directory for inspection.

Run it from the repository root with an empty output directory and the installed
CLI. The tool verifies its SHA256 against the adjacent `validated.json` install
receipt, so the command follows the currently installed qualified artifact:

```sh
RUN="$HOME/.local/state/avila-review/swift-local-mainnet-$(date +%Y%m%d-%H%M%S)"
AVILA_COINS_CACHE_MB=32 MALLOC_ARENA_MAX=2 \
  tools/guard_run.sh --max 1024 --reserve 768 -- \
  python3 tools/swift_local_mainnet.py \
    --binary "$HOME/.local/opt/avila-node/avila-node" \
    --workdir "$RUN"
```

For an intentional candidate test, pass `--allow-other-binary`; its actual
binary hash is still recorded. The tool writes the complete JSON result to
`result.json` inside the private run directory and prints the same result to
stdout. It records the fixture, checkpoint, provider-claim, strict
validation-policy, promotion, and negative-control evidence. On failure, the
script prints the retained artifact directory.

This is a bounded historical fixture test, not a first-time mainnet IBD,
modern witness-coverage, public helper availability, or performance result.
The BIP455/BIP456 formats remain draft protocol inputs; helper data is
untrusted and is never itself an acceptance authority.
