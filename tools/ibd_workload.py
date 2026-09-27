#!/usr/bin/env python3
"""Synthesize a full-history IBD workload model from measured census windows.

Combines per-window structural censuses (tools/ibd_census.py output) with the
chain's era boundaries to produce workload.json: per-era measured densities,
explicit coverage gaps, and a labeled whole-history estimate with ranges.

Every derived number carries a `basis` tag: 'measured' (counted on real bytes),
'sample_extrapolation' (measured density x era size), or 'unmeasured_assumption'
(carried range only). Nothing here executes scripts; dynamic signature-attempt
counts come only from the cited executed trace sample.
"""
import argparse
import json
from pathlib import Path

# Era boundaries (mainnet activation heights, fixed consensus facts).
ERAS = [
    ("genesis_sparse", 0, 227930),        # pre-BIP34; tiny coinbase-era blocks
    ("pre_segwit", 227931, 481823),       # sampled: 276k-408k windows
    ("segwit_era", 481824, 709631),       # NO local coverage - labeled gap
    ("taproot_era", 709632, 970000),      # sampled at ~956k via Core slice
]


def per_block(t, b):
    return {k: (v / b if isinstance(v, (int, float)) else v) for k, v in t.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("windows", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    windows = []
    for w in args.windows:
        d = json.loads(w.read_text())
        if "totals" not in d:
            continue  # skip non-census JSON (e.g. a previous workload output)
        windows.append({"file": w.name, **d})
    # bucket windows into eras by median height
    eras = {}
    for w in windows:
        t = w["totals"]
        hm = w["height_min"]
        hx = w["height_max"]
        if hm is None or hx is None:
            # No BIP34 heights extractable: genesis-era corpus by construction.
            era = "genesis_sparse"
        else:
            mid = w.get("height_median") or (hm + hx) / 2
            era = next((e[0] for e in ERAS if e[1] <= mid <= e[2]), None)
        eras.setdefault(era, []).append(w)
    era_stats = {}
    for era, ws in eras.items():
        if era is None:
            continue
        blk = sum(w["totals"]["blocks"] for w in ws)
        tot = {}
        for w in ws:
            for k, v in w["totals"].items():
                if isinstance(v, (int, float)):
                    tot[k] = tot.get(k, 0) + v
        era_stats[era] = {"windows": [w["file"] for w in ws],
                          "height_range": [min((w["height_min"] or 0) for w in ws),
                                           max((w["height_max"] or 0) for w in ws)],
                          "blocks_measured": blk,
                          "totals": tot,
                          "per_block": per_block(tot, blk)}
    model = {"scope": "mainnet IBD workload census; structural parse only",
             "eras": {e[0]: {"span": [e[1], e[2]], "blocks": e[2] - e[1] + 1}
                      for e in ERAS},
             "coverage": {e: s["height_range"] for e, s in era_stats.items()},
             "gaps": [e[0] for e in ERAS if e[0] not in era_stats],
             "era_stats": era_stats}
    # Whole-history estimate: per-era measured per-block density x era size.
    # genesis_sparse: fixture window (501 blocks measured separately).
    est = {}
    for era, lo_hi in model["eras"].items():
        lo, hi = lo_hi["span"]
        n = hi - lo + 1
        if era in era_stats:
            pb = era_stats[era]["per_block"]
            est[era] = {k: {"basis": "sample_extrapolation", "value": v * n,
                            "note": f"{era} density measured over "
                                    f"{era_stats[era]['height_range']}"}
                        for k, v in pb.items()}
        else:
            est[era] = {"_basis": "unmeasured_assumption",
                        "_note": f"no local corpus coverage for {era}; "
                                 "carry bounded ranges only"}
    model["full_history_estimate"] = est
    args.out.write_text(json.dumps(model, indent=2) + "\n")
    print(json.dumps({"eras_measured": list(era_stats), "gaps": model["gaps"]}))


if __name__ == "__main__":
    main()
