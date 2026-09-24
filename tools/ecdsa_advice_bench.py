#!/usr/bin/env python3
"""Build and measure the isolated ECDSA advice experiment on Linux.

Uses the already installed, Cargo.lock-pinned libsecp256k1 source read-only.
No dependency download, registry edit, Rust lint exception, or node integration.
Example: python3 tools/ecdsa_advice_bench.py --output target/ecdsa-advice/run-1
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--count", type=int, default=16384)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--secp-source", type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    if not 8 <= args.count <= 1048576 or not 1 <= args.repetitions <= 100:
        parser.error("count must be 8..1048576 and repetitions 1..100")
    root = Path(__file__).resolve().parents[1]
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    package = next(p for p in lock["package"] if p["name"] == "secp256k1-sys")
    if package["version"] != "0.10.1":
        parser.error("private API harness requires secp256k1-sys 0.10.1; review before updating")
    if args.secp_source:
        secp = args.secp_source.resolve(strict=True)
    else:
        cargo_root = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        matches = list((cargo_root / "registry/src").glob("*/secp256k1-sys-0.10.1/depend/secp256k1"))
        if len(matches) != 1:
            parser.error("cannot identify pinned cached source; supply --secp-source")
        secp = matches[0]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = root / "experiments/code/ecdsa_advice.c"
    vendor_hash = hashlib.sha256()
    for path in sorted(secp.rglob("*")):
        if path.is_file() and path.suffix in {".c", ".h"}:
            vendor_hash.update(str(path.relative_to(secp)).encode() + b"\0")
            vendor_hash.update(path.read_bytes())
    manifest = {
        "experiment": "ECDSA nonce-point advice and deterministic batch inversion",
        "scope": "synthetic signature kernel; not historical blocks, Script validation, or full IBD",
        "trust": "advice is untrusted; fresh local random coefficients; probabilistic batch acceptance; ordinary per-signature fallback; separate batch-inversion path needs no advice and retains deterministic individual checks",
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "compiler": subprocess.check_output([args.cc, "--version"], text=True).splitlines()[0],
        "platform": platform.platform(),
        "cpuinfo": Path("/proc/cpuinfo").read_text().split("\n\n")[0],
        "crate": package,
        "source_sha256": digest(source),
        "runner_sha256": digest(Path(__file__).resolve()),
        "vendor_c_h_sha256": vendor_hash.hexdigest(),
        "sanitizer_scope": "AddressSanitizer, UndefinedBehaviorSanitizer, and libsecp VERIFY assertions; LeakSanitizer disabled because the managed runner uses ptrace",
        "commands": [],
        "measurements": [],
    }

    def write_manifest():
        (output / "results.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def execute(label, argv, env=None):
        start = time.perf_counter()
        child = subprocess.run(list(map(str, argv)), cwd=root, env=env, capture_output=True, text=True)
        manifest["commands"].append({"label": label, "argv": list(map(str, argv)),
                                     "seconds": time.perf_counter() - start, "returncode": child.returncode})
        (output / f"{label}.stdout").write_text(child.stdout)
        (output / f"{label}.stderr").write_text(child.stderr)
        write_manifest()
        if child.returncode:
            print(child.stderr, flush=True)
        child.check_returncode()
        return child

    common = [
        args.cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
        "-Wno-unused-parameter", "-D_POSIX_C_SOURCE=200809L", "-include", "stdio.h",
        "-DECMULT_WINDOW_SIZE=15", "-DECMULT_GEN_PREC_BITS=4",
        f"-I{secp}", f"-I{secp / 'src'}", f"-I{secp / 'include'}",
        source, secp / "src/precomputed_ecmult.c", secp / "src/precomputed_ecmult_gen.c",
    ]
    binary = output / "probe"
    checked = output / "probe-checked"
    print("Building pinned arithmetic and running checked/adversarial tests...", flush=True)
    execute("build", [*common, "-O3", "-o", binary])
    execute("build-checked", [*common, "-O1", "-g", "-DVERIFY", "-fsanitize=address,undefined",
                              "-fno-omit-frame-pointer", "-o", checked])
    tested = execute("selftest", [checked, "256", "1"],
                     dict(os.environ, ADVICE_SELFTEST_ONLY="1", ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                          UBSAN_OPTIONS="halt_on_error=1"))
    manifest["sanitized_selftest"] = [json.loads(line) for line in tested.stdout.splitlines()]
    manifest["binary_sha256"] = digest(binary)
    print("Tests passed; timing ordinary verification, batch inversion, advice, and bad-advice fallback...", flush=True)
    measured = execute("benchmark", [binary, str(args.count), str(args.repetitions)])
    manifest["measurements"] = [json.loads(line) for line in measured.stdout.splitlines()]
    write_manifest()
    for row in manifest["measurements"]:
        print(json.dumps(row), flush=True)
    print(f"Results: {output / 'results.json'}", flush=True)


if __name__ == "__main__":
    main()
