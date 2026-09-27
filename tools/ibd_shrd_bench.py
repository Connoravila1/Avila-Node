#!/usr/bin/env python3
"""Bounded SHRD-replacement A/B experiment for libsecp256k1 field kernels.

Stages two private copies of the pinned secp256k1-sys dependency source
(never mutates the real workspace or ~/.cargo): one unmodified 'vanilla',
one 'patched' where u128_rshift(&x, 52) is rewritten so the 128-bit >>52
low-word extraction is expressed without the SHRD pattern
((lo>>52) ^ (hi<<12) — bits disjoint by construction, XOR == OR).

Builds experiments/code/ibd_cost_probe.c against each with identical flags,
verifies the patched object no longer emits `shrd` in fe_mul_inner /
fe_sqr_inner, then runs interleaved A/B/A/B/... timing reps on the mainnet
replay trace, pinned to one CPU at nice 19. Every trace record is
differentially checked by the harness on load (ordinary() == expected),
so a mis-verifying patch exits nonzero instead of reporting a bad time.

Outputs a results JSON with disassembly censuses, per-rep timings, and the
exact command lines. Research-only; nothing here touches production code.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROBE_SRC = REPO / "experiments" / "code" / "ibd_cost_probe.c"

RSHIFT_ORIG = """static SECP256K1_INLINE void {pfx}u128_rshift({pfx}uint128 *r, unsigned int n) {{
   VERIFY_CHECK(n < 128);
   *r >>= n;
}}"""

RSHIFT_PATCHED = """static SECP256K1_INLINE void {pfx}u128_rshift({pfx}uint128 *r, unsigned int n) {{
   VERIFY_CHECK(n < 128);
   if (n == 52) {{
       /* (lo>>52) | (hi<<12) written with XOR: the shifted halves are
        * bit-disjoint by construction, so XOR == OR; writing it this way
        * prevents the compiler from fusing the pair into SHRD, which is a
        * ~12+ cycle single-port instruction on Gracemont. */
       uint64_t lo = (uint64_t)*r;
       uint64_t hi = (uint64_t)(*r >> 64);
       *r = ((uint128_t)(hi >> 52) << 64) | ((lo >> 52) ^ (hi << 12));
   }} else {{
       *r >>= n;
   }}
}}"""


def find_secp():
    base = Path.home() / ".cargo" / "registry" / "src"
    for d in base.iterdir():
        cand = d / "secp256k1-sys-0.10.1" / "depend" / "secp256k1"
        if cand.is_dir():
            return cand
    sys.exit("secp256k1-sys-0.10.1 source not found under ~/.cargo/registry")


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def disasm_census(obj_or_bin, syms):
    # --no-show-raw-insn: the first token after the address colon is the
    # mnemonic (with raw bytes shown, a naive \t split picks up byte columns).
    out = {}
    dis = sh(["objdump", "-d", "--no-show-raw-insn", str(obj_or_bin)]).stdout
    for sym in syms:
        m = re.search(rf"<{re.escape(sym)}>:\n(.*?)(?=\n\S|\Z)", dis, re.S)
        if not m:
            continue
        body = m.group(1)
        counts = {}
        for line in body.splitlines():
            mm = re.match(r"\s*[0-9a-f]+:\s*([a-z0-9.]+)", line)
            if mm:
                op = mm.group(1)
                counts[op] = counts.get(op, 0) + 1
        total = sum(counts.values())
        if total == 0:
            sys.exit(f"disasm census: symbol {sym} produced no instructions; "
                     "refusing to record an all-zero result")
        out[sym] = {k: counts.get(k, 0)
                    for k in ("mul", "imul", "mulx", "shrd", "shr", "shl",
                              "adc", "adcx", "adox", "or", "xor")}
        out[sym]["total_instructions"] = total
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--count", type=int, default=2048)
    ap.add_argument("--repetitions", type=int, default=6)
    ap.add_argument("--cpu", type=int, default=7)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--march-native", action="store_true")
    args = ap.parse_args()
    if not 8 <= args.count <= 4096:
        ap.error("count bounded to 8..4096")

    secp = find_secp()
    outdir = args.output.parent
    outdir.mkdir(parents=True, exist_ok=True)
    vanilla = outdir / "secp-vanilla"
    patched = outdir / "secp-patched"

    for dst in (vanilla, patched):
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(secp, dst)

    impl = patched / "src" / "int128_native_impl.h"
    src = impl.read_text()
    # prefix names differ between vendored variants; discover the real one
    m = re.search(r"static SECP256K1_INLINE void (\w*?)u128_rshift", src)
    if not m:
        sys.exit("u128_rshift not found in int128_native_impl.h")
    pfx = m.group(1)
    orig = RSHIFT_ORIG.format(pfx=pfx)
    if orig not in src:
        sys.exit("expected u128_rshift body not found; inspect file")
    impl.write_text(src.replace(orig, RSHIFT_PATCHED.format(pfx=pfx)))

    flags = ["-std=c99", "-O3", "-msha", "-include", "stdio.h",
             "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
             "-Wno-unused-parameter", "-D_POSIX_C_SOURCE=200809L",
             "-DECMULT_WINDOW_SIZE=15", "-DECMULT_GEN_PREC_BITS=4"]
    if args.march_native:
        flags.append("-march=native")

    bins = {}
    commands = []
    for name, root in (("vanilla", vanilla), ("patched", patched)):
        binpath = outdir / f"probe-{name}"
        cmd = (["cc"] + flags +
               [f"-I{root}", f"-I{root / 'src'}", f"-I{root / 'include'}",
                str(PROBE_SRC), str(root / "src" / "precomputed_ecmult.c"),
                str(root / "src" / "precomputed_ecmult_gen.c"),
                "-o", str(binpath)])
        t0 = time.time()
        sh(cmd)
        commands.append({"label": f"build-{name}", "argv": cmd,
                         "seconds": round(time.time() - t0, 3)})
        bins[name] = binpath

    syms = [f"{pfx}fe_mul_inner", f"{pfx}fe_sqr_inner"]
    census = {name: disasm_census(b, syms) for name, b in bins.items()}

    # Interleaved A/B timing. The probe binary prints one JSON object per
    # timing rep; collect 'compressed_parse_and_verify' (full path).
    reps = []
    for rep in range(args.repetitions):
        order = ("vanilla", "patched") if rep % 2 == 0 else ("patched", "vanilla")
        for name in order:
            cmd = ["taskset", "-c", str(args.cpu), "nice", "-n", "19",
                   str(bins[name]), str(args.trace), str(args.count)]
            r = sh(cmd)
            commands.append({"label": f"run-{name}-{rep}", "argv": cmd})
            for line in r.stdout.splitlines():
                if '"timing"' in line:
                    reps.append({"rep": rep, "variant": name,
                                 **json.loads(line)})

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trace": str(args.trace),
        "trace_sha256": hashlib.sha256(args.trace.read_bytes()).hexdigest(),
        "count": args.count, "repetitions": args.repetitions,
        "cpu_pinned": args.cpu, "scheduler": "nice -n 19",
        "march_native": args.march_native,
        "secp_source": str(secp),
        "secp_source_sha256_manifest": "registry copy; patched tree diff in output dir",
        "disasm_census": census,
        "commands": commands,
        "timing": reps,
        "patch": RSHIFT_PATCHED.format(pfx=pfx),
    }
    args.output.write_text(json.dumps(results, indent=2) + "\n")

    # summary
    for mode in ("compressed_parse_and_verify", "preparsed_verify"):
        for name in ("vanilla", "patched"):
            vals = [r["cpu_seconds"] for r in reps
                    if r["variant"] == name and r["timing"] == mode]
            if vals:
                print(f"{mode:28s} {name:8s} cpu_s={['%.4f' % v for v in vals]}")
    vc = census.get("vanilla", {})
    pc = census.get("patched", {})
    for s in syms:
        if s in vc:
            print(f"{s}: shrd {vc[s].get('shrd')} -> {pc.get(s, {}).get('shrd')}, "
                  f"total insns {vc[s]['total_instructions']} -> "
                  f"{pc.get(s, {}).get('total_instructions')}")


if __name__ == "__main__":
    main()
