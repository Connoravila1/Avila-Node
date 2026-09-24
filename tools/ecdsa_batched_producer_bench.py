#!/usr/bin/env python3
"""Compare per-call and bounded batched exact producers in the same binary."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import resource

from ecdsa_economics_bench import EXPECTED, ROOT, cpu
from ecdsa_parallel_bench import frames
from ecdsa_replay_bench import digest, replace_once


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cargo-target', type=Path, default=ROOT / 'target/ecdsa-replay/build-1/cargo-target')
    ap.add_argument('--repetitions', type=int, default=3)
    ap.add_argument('--only', nargs='+', choices=['cases', 'mainnet', 'regtest', 'disk', 'early'])
    ap.add_argument('--build-only', action='store_true')
    ap.add_argument('--reuse-build', action='store_true')
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10:
        ap.error('repetition bound')
    base, out = args.base.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=args.reuse_build)
    stage, binary, worker = out / 'workspace', out / 'replay', out / 'worker'
    sources = {'hook': digest(ROOT / 'experiments/code/ecdsa_batched_producer_hook.rs'),
               'rare_cases': digest(ROOT / 'experiments/code/ecdsa_rare_cases.rs'),
               'runner': digest(Path(__file__)), 'helpers': digest(ROOT / 'tools/ecdsa_economics_bench.py')}
    result = {'scope': 'exact batched producer with bounded Script replay and memoization',
              'sources': sources, 'commands': [], 'runs': [], 'preparation': [],
              'base_build': json.loads((base / 'build-manifest.json').read_text())}

    def save():
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')

    def execute(label, argv, cwd=ROOT, env=None):
        print(label, flush=True)
        before = cpu(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        p = subprocess.run(list(map(str, argv)), capture_output=True, text=True, cwd=cwd, env=env, timeout=600)
        command = {'label': label, 'argv': list(map(str, argv)), 'wall_seconds': time.perf_counter() - start,
                   'tree_cpu_seconds': cpu(resource.RUSAGE_CHILDREN) - before,
                   'returncode': p.returncode, 'load_average': list(os.getloadavg())}
        (out / f'{label}.stdout').write_text(p.stdout)
        (out / f'{label}.stderr').write_text(p.stderr)
        result['commands'].append(command)
        save()
        if p.returncode:
            print(p.stderr[-10000:], flush=True)
        p.check_returncode()
        return p, command

    if args.reuse_build:
        build = json.loads((out / 'build-manifest.json').read_text())
        if build['sources'] != sources or digest(binary) != build['binary_sha256'] or digest(worker) != build['worker_sha256']:
            raise ValueError('source or immutable binary changed')
    else:
        shutil.copytree(base / 'workspace', stage)
        crate = stage / 'crates/avila-consensus'
        shutil.copy2(ROOT / 'experiments/code/ecdsa_batched_producer_hook.rs', crate / 'src/experimental_advice.rs')
        driver = crate / 'examples/ecdsa_economics_replay.rs'
        (crate / 'examples/ecdsa_rare_cases').mkdir()
        shutil.copy2(ROOT / 'experiments/code/ecdsa_rare_cases.rs', crate / 'examples/ecdsa_rare_cases/mod.rs')
        replace_once(driver, 'mod ecdsa_stream_cases;', 'mod ecdsa_stream_cases;\nmod ecdsa_rare_cases;')
        replace_once(driver, '    if kind == "cases" {', '    if kind == "rare" {\n        ecdsa_rare_cases::pack(&mut writer).map_err(|e| e.to_string())?;\n    } else if kind == "cases" {')
        replace_once(driver, '            "cases" => ecdsa_stream_cases::run(),',
                     '            "cases" => ecdsa_stream_cases::run(),\n            "rare" => ecdsa_rare_cases::run(),')
        replace_once(driver, r'\"produced\":{},',
                     r'\"produced\":{},\"producer_replays\":{},\"producer_skipped_transactions\":{},\"producer_skipped_checks\":{},\"producer_replay_checks\":{},\"producer_cache_hits\":{},\"producer_cache_overflow\":{},\"producer_peak_cache\":{},')
        replace_once(driver, '        stats.produced,', '''        stats.produced,
        stats.producer_replays,
        stats.producer_skipped_transactions,
        stats.producer_skipped_checks,
        stats.producer_replay_checks,
        stats.producer_cache_hits,
        stats.producer_cache_overflow,
        stats.producer_peak_cache,''')
        shutil.copy2(base / 'worker', worker)
        execute('build-replay', ['cargo', 'build', '--release', '--locked', '--offline', '-p', 'avila-consensus',
                                '--example', 'ecdsa_economics_replay'], cwd=stage,
                env=dict(os.environ, CARGO_TARGET_DIR=str(args.cargo_target.resolve())))
        shutil.copy2(args.cargo_target.resolve() / 'release/examples/ecdsa_economics_replay', binary)
        build = {'sources': sources, 'binary_sha256': digest(binary), 'worker_sha256': digest(worker),
                 'staged_sources': {str(p.relative_to(stage)): digest(p)
                                    for p in sorted((stage / 'crates/avila-consensus').rglob('*.rs'))}}
        (out / 'build-manifest.json').write_text(json.dumps(build, indent=2) + '\n')
    result['build'] = build
    save()
    if args.build_only:
        return

    for name in ['cases', 'mainnet', 'regtest', 'disk', 'early']:
        if args.only and name not in args.only:
            continue
        legacy, packed = out / f'{name}.advice', out / f'{name}.hints'
        shutil.copy2(base / f'{name}.advice', legacy)
        shutil.copy2(base / f'{name}.hints', packed)
        hints = dict(frames(legacy.read_bytes(), b'AVADVC03', 1))
        corpus = Path('/dev/null') if name == 'cases' else ROOT / 'target/ecdsa-replay/corpus-linked-24/corpus.bin' if name == 'mainnet' else (
            ROOT / 'fixtures/mainnet-blocks-000000-000500.dat' if name == 'early' else Path('/tmp/spend-fixture.dat'))
        kind = 'cases' if name == 'cases' else 'scripts' if name == 'mainnet' else 'chain'
        minimum = 0 if name == 'cases' else 64
        reference = None

        def run(label, mode, path, storage):
            p, command = execute(label, [binary, kind, corpus, mode, path, worker, 8192, minimum, 512, storage],
                                 env=dict(os.environ, AVILA_COINS_ENGINE='redb'))
            row = json.loads(p.stdout.strip().splitlines()[-1])
            row.update(label=label, name=name, tree_cpu_seconds=command['tree_cpu_seconds'])
            if mode != 'pack' and row['result_hash'] != EXPECTED[name]:
                raise ValueError('state or Script outcome mismatch')
            if mode != 'pack' and name == 'disk':
                row['database_bytes'] = sum(p.stat().st_size for p in Path(storage).rglob('*') if p.is_file())
            return row

        for rep in range(args.repetitions):
            modes = ['baseline', 'produce', 'produce-batch', 'stream']
            for mode in modes[rep % 4:] + modes[:rep % 4]:
                label = f'{name}-{mode}-{rep}'
                is_producer = mode.startswith('produce')
                path = out / f'{label}.advice' if is_producer else packed if mode == 'stream' else legacy
                storage = out / f'{label}.db' if name == 'disk' else 'ram'
                row = run(label, mode, path, storage)
                row['rep'] = rep
                if reference is None:
                    reference = row
                if (row['checks'], row['false_checks']) != (reference['checks'], reference['false_checks']):
                    raise ValueError('producer did not preserve actual Script execution')
                if row['worker_errors'] or row['retry_groups'] or row['producer_peak_cache'] > 8192:
                    raise ValueError('unexpected error or memory bound violation in healthy sample')
                if is_producer:
                    generated = list(frames(path.read_bytes(), b'AVADVC03', 1))
                    if len(dict(generated)) != len(generated) or dict(generated) != hints:
                        raise ValueError('exact producer hint mismatch')
                    row.update(exact_hints_match=True, producer_bytes=path.stat().st_size, producer_sha256=digest(path))
                result['runs'].append(row)
                save()
                if is_producer:
                    output = out / f'{label}.hints'
                    prepared = run(label + '-pack', 'pack', path, output)
                    if output.read_bytes() != packed.read_bytes():
                        raise ValueError('packed output mismatch')
                    prepared.update(packed_bytes=output.stat().st_size, packed_sha256=digest(output))
                    result['preparation'].append(prepared)
                    save()


if __name__ == '__main__':
    main()
