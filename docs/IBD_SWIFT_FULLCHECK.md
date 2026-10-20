# Experimental full-check Swift IBD

`avila-node sync` has an explicit, bounded Swift path for a locally supplied
draft BIP456 hints file and peers that negotiate draft BIP455
`blockspentcoinsv1`. It validates every block through the selected checkpoint
with the ordinary consensus connector and `assumevalid=0`; untrusted spent-coin
claims only supply candidate prevouts. It does not trust helper-provided
outputs or publish the provisional tip. After the full audit succeeds, the
node promotes the result into a new conventional datadir and continues with
ordinary validation.

Example invocation:

```text
avila-node sync --blocks 900000 \
  --swift-checkpoint-height 850000 \
  --swift-checkpoint-hash <checkpoint-hash> \
  --swift-hints /path/to/bip456-hints.dat \
  --swift-workspace /var/lib/avila/swift-staging \
  --swift-data-dir /var/lib/avila/mainnet-swift-result
```

The checkpoint, hints file, private workspace, and new output datadir must be
chosen by the operator. The output datadir must be empty and separate from the
configured live datadir. The workspace holds the keyed audit, compact live
outpoint state, and temporary peer files; protect it as private node state.
An unavailable hints file, exhausted resource bound, unsupported provider,
protocol error, or audit mismatch switches to ordinary genesis validation.
The command never writes a provisional checkpoint into the configured live
datadir.

This remains experimental. Draft BIP455/BIP456 support is not deployed by
ordinary Bitcoin peers, and the node does not discover or download trusted
hintfiles. Users need a compatible provider and a locally acquired hints file;
without both, this path falls back to ordinary sync. It is not enabled by
`run` or by default.
