# Privacy failure matrix — the enforced-network-policy test suite

Status: active spec + test suite. This is the reproducible answer to
"if the operator chooses private operation, which code path could
still leak?" Every outbound-capable path is enumerated below with its
mechanism and the test that proves the guarantee.

**The contract:** with `--proxy` set, no byte of node-originated
traffic may leave except through the proxy. A failed proxy means
queued transactions and zero peers — never a clearnet fallback.
The one permitted destination is the proxy endpoint itself.

## Outbound dial surface (complete inventory)

| Path | Mechanism | Proof |
|---|---|---|
| Automatic outbounds (`maintain_outbounds` → `queue_dial`) | `dial_via` — every attempt opens a SOCKS5 connection **to the proxy**; the far-end address travels inside SOCKS5. No clearnet branch exists. | `manager::tests::proxy_mode_never_touches_cleared` — mock proxy observes the dial; clearnet bypass would show as "proxy saw nothing". |
| Retries after dial failure | The retry is another `queue_dial` → `dial_via` — same code path, no state carries a clearnet route. | `manager::tests::proxy_retries_also_ride_the_proxy` — two maintain rounds produce ≥2 observed proxy connections, still zero peers. |
| `--connect` / explicit peers | `sync::run` chooses `connect_via` when `cfg.proxy` is set; the direct `connect` only runs with no proxy configured. | Code gate at `sync.rs` (~line 407) — the match is on `cfg.proxy`, not on success. |
| v2→v1 downgrade | `dial_via`'s `V1Fallback` branch re-opens **through `socks5_connect`** — the v1 redial rides the proxy. The attacker who forces a downgrade gains nothing on the routing dimension. | Code inspection + `dial_via` fallback branch; live v1-fallback-under-proxy wire test open. |
| DNS seeds | **Skipped under proxy** — `resolve_seeds` is a local `to_socket_addrs` lookup, which would leak the resolver even though the resulting dials ride the proxy. Gate added: `cfg.connect.is_empty() && cfg.proxy.is_none()`. | Code gate in `sync::run`; regtest ships no seeds so the path is mainnet-relevant only. |
| Inbound listener | Passive — accepts connections, never originates. | n/a |
| Electrum server / SV2 | Server-side listeners; their `TcpStream::connect` sites are test-only. | grep inventory — no production outbound dial exists in either module. |

## Transaction-origin surface

| Path | Mechanism | Status |
|---|---|---|
| Initial broadcast | Stem relay: one random established outbound peer, 2–15 s randomized delay, then fluff. Recon links excluded from stem sketches. | Shipped (#48, #64). |
| Broadcast pool | Locally submitted txs survive eviction so rebroadcast retries exist (`unbroadcastcount` in `getmempoolinfo`). | Shipped (#45). |
| Rebroadcast under dead proxy | No peers → nothing announced → tx stays `unbroadcast` and queued; when the proxy recovers the stem path resumes. No alternative route exists to leak through. | Mechanism-level (zero-peer ⇒ zero-announce); a node-level capture run stays open (#25). |
| `sendrawtransaction` | Submits to the mempool → the same stem path. Not a separate broadcast channel. | Same as above. |

## Remaining honest gaps

- **Cell-mode residual**: `--cell-bytes` flattens write() sizes, but
  kernel TCP segmentation is observer-visible. A distinctive cell
  cadence could itself fingerprint Avila at low adoption — astra's
  warning; classification-resistance vs trained classifiers is
  unmeasured.
- **24h packet-capture artifact** (#25): the matrix proves the
  mechanism; the artifact would prove no stray packet crossed an
  interface under real uptime — startup, stall, recovery.
- **Downgrade telemetry**: a forced v2→v1 downgrade is currently
  silent; an event + optional `-v2required` policy is unbuilt.
- ~~**Proxy health visibility**~~ — closed: `proxy_unreachable`
  fires on the event ring after 3 consecutive failed dials.
- **DNS seeds under proxy** — closed this audit: `resolve_seeds` ran
  a LOCAL lookup even with `--proxy` set (a real resolver leak,
  same class as the June-2026 Core boundary advisory). Now gated:
  proxy mode never touches DNS seeds.
