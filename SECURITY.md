# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security-sensitive report.**

Report vulnerabilities privately to the repository owner through
GitHub's private vulnerability reporting ("Security" → "Report a
vulnerability"), or via the contact address listed on the maintainer's
GitHub profile. Include a description, affected components, and a
reproduction or proof-of-concept where possible. Reports are
acknowledged as soon as practical; follow-up coordination happens on
the private thread.

Scope notes:

- Consensus mis-validation, inflation paths, and DoS vectors are the
  highest-priority reports.
- Issues in the watch-only wallet, RPC surface, or Electrum service
  are in scope — including unauthenticated-access, resource-exhaustion,
  and memory-safety findings.
- Reports about third-party dependencies should include the affected
  version and ideally a public advisory link.

## Supported releases

Avila-Node is pre-release software under active development. Only the
`main` branch head receives fixes; there are no long-term-support
branches yet. A `0.x` release line will establish its supported-window
policy at first tagged release.

## Scope of trust

This node validates the Bitcoin consensus rules itself — nothing here
asks users to trust remote peers for correctness. That said:

- This codebase has not yet completed the full qualification matrix in
  `docs/SCORECARD.md`; treat it as experimental for funds-bearing use
  until the roadmap's qualification gates are met.
- The watch-only wallet holds no private spend keys; the silent-payment
  scan key detects receipts but cannot spend.
- RPC authentication uses HTTP Basic over loopback only — do not expose
  the RPC port off-host.
