# Rustreexo 0.7 implicit-addition shadow differential

**Status:** all 615 final-state differential cases passed. The change remains
test-only; no production behavior or consensus acceptance was changed.

The new test-only Cargo alias pins upstream `rustreexo` to exactly `0.7.0`
while the production dependency remains `0.6.0`. The verified crate archive
SHA-256 is
`b936c4e0be58f59785a9bcd9c222f17e12f5303f3d7c44daffe10ccd432be034`.
Its VCS commit is
`b73cbac1f425f0e849faa279982ef4f5ec9f3754`, matching the peeled official
[`v0.7.0` tag](https://github.com/mit-dci/rustreexo/tree/v0.7.0) and the
[crates.io 0.7.0 release](https://crates.io/crates/rustreexo/0.7.0).

`swift_stump::tests::final_implicit_additions_match_rustreexo_v07_and_explicit_memforest`
compares only completed checkpoint states. It covers 41 output counts (0–40),
three patterns (all live, mixed, and all implicitly deleted), and five batch
sizes (1, 3, 5, 8, and 13), for 615 pattern/batch combinations. Each final leaf
count and root list is compared among upstream v0.7 `Stump::modify` using empty
hash additions, Avila's root-carry builder, and the v0.6 explicit-deletion
`MemForest` oracle. The cases exercise power-of-two carry boundaries and
different batch partitions. Intermediate roots are deliberately not asserted.

The native gate passed 1,152 Rust tests (five ignored), 14 Python tests, and
workspace Clippy. It completed in 239 seconds under a 2,560 MiB cap with
1,680 MiB peak. A subsequent single P2P rustdoc-link correction left the
implementation unchanged; the verified source hash was reconstructed, and
documentation, build, and smoke checks passed in 91 seconds with 1,090 MiB
peak. Test-gate source digest: `8bd92eef...`; doc/build source digest:
`ef2115dc...`.

The test checks root arithmetic only. It does not authenticate spentness
hints, validate scripts or blocks, establish interoperability, or demonstrate
performance. The builder remains isolated and shadow-only; v0.7 is dev-only.
The newly deployed CLI (`fd20c6eb...`) restarted cleanly with mainnet proof
155,785 → 155,788, but full script validation remains enabled and IBD is not
complete. There is no production integration of v0.7 and no performance claim.
