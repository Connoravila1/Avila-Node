#!/usr/bin/env python3
"""Bounded single-core, low-priority arithmetic census and instruction probe.

Requires an existing 130-byte canonical ECDSA replay trace. This is not IBD and
does not open a live datadir. Copies pinned dependency sources; never edits them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
import tomllib


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--count', type=int, default=512)
    parser.add_argument('--native', action='store_true', help='also compile for the current CPU (-march=native)')
    args = parser.parse_args()
    if not 8 <= args.count <= 4096:
        parser.error('count must be 8..4096')
    root = Path(__file__).resolve().parents[1]
    package = next(p for p in tomllib.loads((root / 'Cargo.lock').read_text())['package'] if p['name'] == 'secp256k1-sys')
    if package['version'] != '0.10.1':
        parser.error('private API probe requires reviewed secp256k1-sys 0.10.1')
    registry = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')) / 'registry/src'
    matches = list(registry.glob('*/secp256k1-sys-0.10.1/depend/secp256k1'))
    if len(matches) != 1:
        parser.error('cannot uniquely identify pinned dependency source')
    secp = matches[0]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    trace = args.trace.resolve(strict=True)
    source = root / 'experiments/code/ibd_cost_probe.c'
    staged = out / 'secp-instrumented'
    shutil.copytree(secp, staged)
    points = [
        ('field_5x52_impl.h', 'fe_impl_mul'),
        ('field_5x52_impl.h', 'fe_impl_sqr'),
        ('field_5x52_impl.h', 'fe_impl_inv_var'),
        ('field_impl.h', 'fe_sqrt'),
        ('scalar_4x64_impl.h', 'scalar_inverse_var'),
        ('group_impl.h', 'gej_double_var'),
        ('group_impl.h', 'gej_add_ge_var'),
        ('group_impl.h', 'gej_add_zinv_var'),
        ('scalar_4x64_impl.h', 'scalar_mul'),
    ]
    for index, (filename, name) in enumerate(points):
        p = staged / 'src' / filename
        text = p.read_text()
        pattern = r'(\b' + re.escape('rustsecp256k1_v0_10_0_' + name) + r'\([^;{}]*\)\s*\{)'
        text, count = re.subn(pattern, lambda m: m[0] + '\n    if (cost_enabled) ++cost_counts[' + str(index) + '];', text)
        if count != 1:
            raise RuntimeError(f'expected one definition for {name}, got {count}')
        p.write_text(text)
    cpu = max(os.sched_getaffinity(0))
    manifest = {
        'scope': '512 by default evenly spaced canonical ECDSA attempts from an existing trace; operation census plus bounded single-core timings; not full IBD or a physical lower-bound proof',
        'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source_sha256': digest(source), 'runner_sha256': digest(Path(__file__)),
        'harness_sha256': digest(root / 'experiments/code/ecdsa_advice.c'),
        'trace': str(trace), 'trace_sha256': digest(trace), 'trace_bytes': trace.stat().st_size,
        'sampling': 'record floor(i * total_records / count), i=0..count-1',
        'count': args.count, 'native': args.native, 'cpu_affinity': cpu, 'nice_increment': 19,
        'cpuinfo': Path('/proc/cpuinfo').read_text().split('\n\n')[0],
        'platform': platform.platform(), 'loadavg_before': os.getloadavg(),
        'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
        'dependency': package, 'instrumented_points': points, 'commands': [], 'results': {},
    }
    vendor_hash = hashlib.sha256()
    for p in sorted(secp.rglob('*')):
        if p.is_file() and p.suffix in {'.h', '.c'}:
            vendor_hash.update(str(p.relative_to(secp)).encode() + b'\0')
            vendor_hash.update(p.read_bytes())
    manifest['vendor_c_h_sha256'] = vendor_hash.hexdigest()

    def low_priority():
        os.nice(19)
        os.sched_setaffinity(0, {cpu})

    def execute(label, argv):
        start = time.monotonic()
        child = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                               preexec_fn=low_priority, timeout=60)
        (out / (label + '.stdout')).write_text(child.stdout)
        (out / (label + '.stderr')).write_text(child.stderr)
        manifest['commands'].append({'label': label, 'argv': list(map(str, argv)), 'elapsed': time.monotonic() - start, 'returncode': child.returncode})
        (out / 'results.json').write_text(json.dumps(manifest, indent=2) + '\n')
        child.check_returncode()
        return child.stdout

    for label, directory, flags in [('count', staged, ['-DCOST_INSTRUMENTED']), ('timing', secp, [])]:
        binary = out / label
        argv = ['cc', '-std=c99', '-O3', '-msha', '-include', 'stdio.h', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-function', '-Wno-unused-parameter', '-D_POSIX_C_SOURCE=200809L',
                '-DECMULT_WINDOW_SIZE=15', '-DECMULT_GEN_PREC_BITS=4', *(['-march=native'] if args.native else []), *flags,
                '-I' + str(directory), '-I' + str(directory / 'src'), '-I' + str(directory / 'include'),
                source, directory / 'src/precomputed_ecmult.c', directory / 'src/precomputed_ecmult_gen.c', '-o', binary]
        execute('build-' + label, argv)
        manifest[label + '_binary_sha256'] = digest(binary)
        stdout = execute(label, [binary, trace, args.count])
        manifest['results'][label] = [json.loads(line) for line in stdout.splitlines()]
    manifest['loadavg_after'] = os.getloadavg()
    (out / 'results.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'output': str(out / 'results.json'), 'results': manifest['results']}, indent=2))


if __name__ == '__main__':
    main()
