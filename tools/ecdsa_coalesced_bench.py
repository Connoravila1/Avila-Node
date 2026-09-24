#!/usr/bin/env python3
"""Isolated repeated-public-key experiment; reuse the frozen Script replay.

Build, kernel, replay and checks are separate recorded phases. No node source,
live chainstate, network service, or cached dependency is modified.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import struct
import subprocess
import time
import tomllib

from ecdsa_economics_bench import EXPECTED, ROOT
from ecdsa_parallel_bench import frames
from ecdsa_replay_bench import digest


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--base', type=Path, default=ROOT / 'target/ecdsa-economics/batched-2')
    ap.add_argument('--trace', type=Path, default=ROOT / 'target/ecdsa-economics/final-1/mainnet.trace')
    ap.add_argument('--historical-corpus', type=Path,
                    default=ROOT / 'target/ecdsa-replay/corpus-linked-24/corpus.bin')
    ap.add_argument('--phase', required=True, choices=['build', 'kernel', 'replay', 'checks'])
    ap.add_argument('--repetitions', type=int, default=3)
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10:
        ap.error('repetition bound')
    out, base = args.output.resolve(), args.base.resolve()
    out.mkdir(parents=True, exist_ok=args.phase != 'build')
    source = ROOT / 'experiments/code/ecdsa_coalesced_worker.c'
    sources = {str(p.relative_to(ROOT)): digest(p) for p in [
        source, ROOT / 'experiments/code/ecdsa_advice.c', Path(__file__).resolve(),
        ROOT / 'tools/ecdsa_economics_bench.py', ROOT / 'tools/ecdsa_parallel_bench.py',
        ROOT / 'tools/ecdsa_replay_bench.py', ROOT / 'tools/check_ecdsa_economics.py',
        ROOT / 'tools/check_ecdsa_replay_worker.py']}
    results = {'phase': args.phase, 'sources': sources, 'commands': [], 'runs': [],
               'scope': 'advised signature arithmetic and fixed historical Script/chain fixtures; not full IBD',
               'platform': platform.platform(), 'repetitions': args.repetitions}

    def save():
        (out / f'{args.phase}-results.json').write_text(json.dumps(results, indent=2) + '\n')

    def run(label, argv, payload=None):
        print(label, flush=True)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        env = dict(os.environ, AVILA_COINS_ENGINE='redb',
                   ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        p = subprocess.run(list(map(str, argv)), input=payload, capture_output=True, env=env,
                           cwd=ROOT, timeout=600)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = {'label': label, 'argv': list(map(str, argv)), 'returncode': p.returncode,
               'wall_seconds': time.perf_counter() - start,
               'tree_cpu_seconds': after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
               'load_average': list(os.getloadavg())}
        (out / f'{label}.stdout').write_bytes(p.stdout)
        (out / f'{label}.stderr').write_bytes(p.stderr)
        results['commands'].append(row)
        save()
        if p.returncode:
            print(p.stderr[-6000:].decode(errors='replace'), flush=True)
        p.check_returncode()
        if b'AddressSanitizer' in p.stderr or b'runtime error:' in p.stderr:
            raise ValueError('sanitizer finding')
        return p.stdout, row

    if args.phase == 'build':
        lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
        package = next(p for p in lock['package'] if p['name'] == 'secp256k1-sys')
        if package['version'] != '0.10.1':
            raise ValueError('review private API before changing pinned dependency')
        cargo = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
        matches = list((cargo / 'registry/src').glob('*/secp256k1-sys-0.10.1/depend/secp256k1'))
        if len(matches) != 1:
            raise ValueError('cannot identify cached secp256k1-sys 0.10.1')
        secp = matches[0]
        vendor_hash = hashlib.sha256()
        for path in sorted(secp.rglob('*')):
            if path.is_file() and path.suffix in ('.c', '.h'):
                vendor_hash.update(str(path.relative_to(secp)).encode() + b'\0')
                vendor_hash.update(path.read_bytes())
        (out / 'sources').mkdir()
        for path in [source, ROOT / 'experiments/code/ecdsa_advice.c', Path(__file__)]:
            shutil.copy2(path, out / 'sources' / path.name)
        shutil.copy2(base / 'replay', out / 'replay')
        for name in ('cases', 'mainnet', 'regtest', 'disk', 'early'):
            for suffix in ('advice', 'hints'):
                shutil.copy2(base / f'{name}.{suffix}', out / f'{name}.{suffix}')
        common = ['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                  '-Wno-unused-parameter', '-D_POSIX_C_SOURCE=200809L', '-include', 'stdio.h',
                  '-DECMULT_WINDOW_SIZE=15', '-DECMULT_GEN_PREC_BITS=4',
                  f'-I{secp}', f'-I{secp / "src"}', f'-I{secp / "include"}',
                  out / 'sources' / source.name, secp / 'src/precomputed_ecmult.c',
                  secp / 'src/precomputed_ecmult_gen.c']
        for mode, name in enumerate(('original', 'coalesced', 'reuse')):
            run(f'build-{name}', [*common, '-O3', f'-DCOALESCE_MODE={mode}', '-o', out / f'worker-{name}'])
        run('build-checked', [*common, '-O1', '-g', '-DVERIFY', '-DCOALESCE_MODE=2',
                             '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-o', out / 'worker-checked'])
        data, _ = run('checked-selftest', [out / 'worker-checked', '--selftest'])
        results['selftests'] = [json.loads(line) for line in data.splitlines()]
        shutil.copy2(out / 'worker-reuse', out / 'worker')
        built = {'sources': sources, 'vendor_c_h_sha256': vendor_hash.hexdigest(), 'package': package,
                 'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                 'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                 'base_build': json.loads((base / 'build-manifest.json').read_text()),
                 'artifacts': {p.name: digest(p) for p in out.iterdir()
                               if p.is_file() and (p.name.startswith('worker') or p.name == 'replay'
                                                  or p.suffix in ('.advice', '.hints'))}}
        (out / 'build-manifest.json').write_text(json.dumps(built, indent=2) + '\n')
        results['build'] = built
        save()
        return

    built = json.loads((out / 'build-manifest.json').read_text())
    if built['sources'] != sources:
        raise ValueError('source identity changed; build in a fresh directory')
    for name, expected in built['artifacts'].items():
        if digest(out / name) != expected:
            raise ValueError(f'frozen artifact changed: {name}')
    results['build_manifest_sha256'] = digest(out / 'build-manifest.json')
    results['corpora'] = {str(p): digest(p) for p in [args.trace.resolve(), args.historical_corpus.resolve(),
                          ROOT / 'fixtures/mainnet-blocks-000000-000500.dat', Path('/tmp/spend-fixture.dat')]}

    if args.phase == 'kernel':
        entries = list(frames(args.trace.read_bytes(), b'AVTRACE3', 130))
        hints = dict(frames((out / 'mainnet.advice').read_bytes(), b'AVADVC03', 1))
        valid, raw = [], []
        for key, data in entries:
            advice = hints[key]
            if len(data) != len(advice) * 130:
                raise ValueError('trace/advice length mismatch')
            tx = []
            for i, hint in enumerate(advice):
                record = data[130*i:130*(i+1)]
                if bool(record[129]) != (hint < 4):
                    raise ValueError('trace/advice result mismatch')
                raw.append(record)
                if hint < 4:
                    tx.append(record[:129] + bytes([hint]))
            valid.append(tx)
        flat = [record for tx in valid for record in tx]
        keys = [record[96:129] for record in flat]
        results['reuse'] = {'valid_checks': len(keys), 'transactions': len(valid),
                            'unique_keys_global': len(set(keys)),
                            'sum_per_transaction_unique': sum(len({r[96:129] for r in tx}) for tx in valid),
                            'most_repeated_key_counts': [n for _, n in collections.Counter(keys).most_common(10)],
                            'trace_order_groups': []}
        for jobs in (64, 128, 512):
            chunks = []
            for i in range(0, len(valid), jobs):
                group = [r for tx in valid[i:i+jobs] for r in tx]
                chunks.extend(group[j:j+8192] for j in range(0, len(group), 8192) if len(group[j:j+8192]) >= 64)
            before = sum(2 * len(part) for part in chunks)
            after = sum(len(part) + len({r[96:129] for r in part}) for part in chunks)
            results['reuse']['trace_order_groups'].append({'jobs': jobs, 'points_before': before,
                'points_after': after, 'point_saving_fraction': 1 - after / before})
        (out / 'protocol.trace').write_bytes(b''.join(raw[:256]))
        run('checked-protocol', ['python3', ROOT / 'tools/check_ecdsa_replay_worker.py',
                                '--worker', out / 'worker-checked', '--trace', out / 'protocol.trace',
                                '--output', out / 'protocol-results.json'])
        workloads = {'historical': [b''.join(flat[i:i+8192]) for i in range(0, len(flat), 8192)]}
        for label, count in [('unique', 8192), ('repeated', 16)]:
            data, _ = run(f'generate-{label}', [out / 'worker-reuse', '--synthetic', 8192, count])
            if len(data) != 8192 * 130:
                raise ValueError('synthetic record length')
            workloads[label] = [data] * 4
        for label, chunks in workloads.items():
            packet = b''.join(b'B' + struct.pack('<I', len(c) // 130) + c for c in chunks)
            count = sum(len(c) // 130 for c in chunks)
            for rep in range(args.repetitions):
                modes = ['original', 'coalesced', 'reuse']
                for mode in modes[rep % 3:] + modes[:rep % 3]:
                    data, timing = run(f'kernel-{label}-{mode}-{rep}', [out / f'worker-{mode}'], packet)
                    if len(data) != 9 * len(chunks) or any(data[i] != 1 for i in range(0, len(data), 9)):
                        raise ValueError('valid batch rejected')
                    row = dict(timing, workload=label, mode=mode, rep=rep, records=count,
                               worker_cpu_seconds=sum(struct.unpack_from('<Q', data, i + 1)[0]
                                                      for i in range(0, len(data), 9)) / 1e9,
                               input_sha256=hashlib.sha256(packet).hexdigest())
                    results['runs'].append(row)
                    save()

    if args.phase == 'replay':
        for name in ('cases', 'mainnet', 'regtest', 'disk', 'early'):
            corpus = Path('/dev/null') if name == 'cases' else args.historical_corpus.resolve() if name == 'mainnet' else (
                ROOT / 'fixtures/mainnet-blocks-000000-000500.dat' if name == 'early' else Path('/tmp/spend-fixture.dat'))
            kind = 'cases' if name == 'cases' else 'scripts' if name == 'mainnet' else 'chain'
            reference = None
            for rep in range(1 if name in ('cases', 'early') else args.repetitions):
                modes = ['baseline', 'original', 'reuse']
                for mode in modes[rep % 3:] + modes[:rep % 3]:
                    label = f'replay-{name}-{mode}-{rep}'
                    storage = out / f'{label}.db' if name == 'disk' else 'ram'
                    data, timing = run(label, [out / 'replay', kind, corpus,
                        'baseline' if mode == 'baseline' else 'stream', out / f'{name}.hints',
                        out / ('worker-original' if mode == 'baseline' else f'worker-{mode}'),
                        8192, 0 if name == 'cases' else 64, 512, storage])
                    row = json.loads(data.strip().splitlines()[-1])
                    row.update(timing, name=name, arm=mode, rep=rep)
                    if row['result_hash'] != EXPECTED[name]:
                        raise ValueError('Script/state outcome mismatch')
                    counts = row['checks'], row['false_checks']
                    if reference is None:
                        reference = counts
                    if counts != reference or row['retry_groups'] or row['worker_errors']:
                        raise ValueError('unexpected execution/recovery difference')
                    results['runs'].append(row)
                    save()

    if args.phase == 'checks':
        run('boundary-checks', ['python3', ROOT / 'tools/check_ecdsa_economics.py',
                               '--build-dir', out, '--output', out / 'checks',
                               '--checked-worker', out / 'worker-checked', '--rare-cases',
                               '--producer-mode', 'produce-batch', '--only', 'cases', 'extras'])
        # Reuse the frozen, independently generated historical corruption fixtures.
        fixture_root = ROOT / 'target/ecdsa-economics/checks-2'
        for attack in ('bad-parity', 'all-bad', 'forged-true'):
            path = fixture_root / f'mainnet-{attack}.hints'
            data, timing = run(f'mainnet-{attack}', [out / 'replay', 'scripts', args.historical_corpus.resolve(),
                'stream', path, out / 'worker-reuse', 8192, 64, 512, 'ram'])
            row = json.loads(data.strip().splitlines()[-1])
            row.update(timing, attack=attack, sidecar_sha256=digest(path))
            if row['result_hash'] != EXPECTED['mainnet'] or not row['retry_groups'] or row['worker_errors']:
                raise ValueError('historical corruption was not recovered correctly')
            if row['max_retry_jobs'] > 512 or row['max_pending'] > 8192:
                raise ValueError('retry bound exceeded')
            results['runs'].append(row)
            save()
    save()
    print(f'Results: {out / (args.phase + "-results.json")}', flush=True)


if __name__ == '__main__':
    main()
