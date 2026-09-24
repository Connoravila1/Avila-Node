#!/usr/bin/env python3
"""Isolated follow-up: bounded stream transport and verification-time production.

Stage from the frozen parallel replay workspace so concurrent production changes
cannot contaminate the comparison. No live chainstate is opened or modified.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time

from ecdsa_replay_bench import digest, replace_once
from ecdsa_parallel_bench import frames, produce


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['ecdsa_stream_hook.rs', 'ecdsa_stream_codec.rs', 'ecdsa_stream_pool.rs',
           'ecdsa_economics_replay.rs', 'ecdsa_stream_cases.rs', 'ecdsa_stream_rollback.rs']
EXPECTED = {
    'cases': '26c99b5f964b84b96f818f43cab06fd2cfe4d024128a6313df36747a5f46d557',
    'mainnet': '63d23d5bae36386939c31d955fcc686266ae569d56ab3e9104dc23fe285aac92',
    'regtest': 'e5b0e2cbfffc9137ec750d631f05ad5d9bb74d0fba47be2f35c552c252633707',
    'disk': 'e5b0e2cbfffc9137ec750d631f05ad5d9bb74d0fba47be2f35c552c252633707',
    'rollback': 'e5b0e2cbfffc9137ec750d631f05ad5d9bb74d0fba47be2f35c552c252633707',
    'early': '9c3c4606df2ab3d7534227c3d39377382c438dda7c8dfe138ac7b1fcfbec0b23',
}


def cpu(kind):
    r = resource.getrusage(kind)
    return r.ru_utime + r.ru_stime


def stage_sources(base, stage):
    shutil.copytree(base, stage)
    crate = stage / 'crates/avila-consensus'
    for source, dest in [('ecdsa_stream_hook.rs', 'src/experimental_advice.rs'),
                         ('ecdsa_stream_codec.rs', 'src/experimental_advice_codec.rs'),
                         ('ecdsa_economics_replay.rs', 'examples/ecdsa_economics_replay.rs')]:
        shutil.copy2(ROOT / 'experiments/code' / source, crate / dest)
    for name in ['ecdsa_stream_cases', 'ecdsa_stream_rollback']:
        (crate / 'examples' / name).mkdir()
        shutil.copy2(ROOT / 'experiments/code' / f'{name}.rs', crate / 'examples' / name / 'mod.rs')
    with (crate / 'src/lib.rs').open('a') as f:
        f.write('\n// Isolated stream experiment.\npub mod experimental_advice_codec;\n')
    connect = crate / 'src/connect.rs'
    text = connect.read_text()
    begin = text.index('    fn worker(&self) {')
    end = text.index('    fn submit(&self, job: ScriptJob)', begin)
    text = text[:begin] + (ROOT / 'experiments/code/ecdsa_stream_pool.rs').read_text() + '\n' + text[end:]
    connect.write_text(text)
    replace_once(connect, 'struct ScriptJob {',
                 'struct ScriptJob {\n    advice: crate::experimental_advice::Token,')
    replace_once(connect, 'let mut owned_jobs: Vec<(Transaction, Vec<TxOut>)>',
                 'let mut owned_jobs: Vec<(usize, Transaction, Vec<TxOut>)>')
    replace_once(connect, 'owned_jobs.push((tx.clone(), spent_outs));',
                 'owned_jobs.push((i - 1, tx.clone(), spent_outs));')
    replace_once(connect, 'for (tx, outs) in owned_jobs {', '''let advice = crate::experimental_advice::begin_block(
                block.block_hash().as_bytes(), block.transactions.len() - 1);
            for (index, tx, outs) in owned_jobs {''')
    replace_once(connect, 'pool.submit(ScriptJob {\n                    tx,',
                 'pool.submit(ScriptJob {\n                    advice: crate::experimental_advice::token(&advice, index),\n                    tx,')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--base-workspace', type=Path, default=ROOT / 'target/ecdsa-parallel/final-1/workspace')
    ap.add_argument('--historical-corpus', type=Path, default=ROOT / 'target/ecdsa-replay/corpus-linked-24/corpus.bin')
    ap.add_argument('--chain-corpus', type=Path, default=Path('/tmp/spend-fixture.dat'))
    ap.add_argument('--reference-advice', type=Path, default=ROOT / 'target/ecdsa-parallel/final-1')
    ap.add_argument('--worker', type=Path, default=ROOT / 'target/ecdsa-parallel/final-1/worker')
    ap.add_argument('--cargo-target', type=Path, default=ROOT / 'target/ecdsa-replay/build-1/cargo-target')
    ap.add_argument('--reuse-build', action='store_true')
    ap.add_argument('--build-only', action='store_true')
    ap.add_argument('--repetitions', type=int, default=3)
    ap.add_argument('--only', nargs='+', choices=list(EXPECTED))
    ap.add_argument('--modes', nargs='+', choices=['baseline', 'candidate', 'stream', 'produce'],
                    default=['baseline', 'candidate', 'stream', 'produce'])
    ap.add_argument('--two-pass', action='store_true')
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10:
        ap.error('repetition bound')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=args.reuse_build)
    stage = out / 'workspace'
    binary, worker = out / 'replay', out / 'worker'
    sources = {name: digest(ROOT / 'experiments/code' / name) for name in SOURCES}
    sources.update(runner=digest(Path(__file__)), helpers=digest(ROOT / 'tools/ecdsa_parallel_bench.py'),
                   staging_helpers=digest(ROOT / 'tools/ecdsa_replay_bench.py'))
    result = {'scope': 'bounded block stream; one elliptic-curve pass producer; supplied-undo mainnet Scripts and complete regtest',
              'git_head_at_start': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'sources': sources, 'platform': platform.platform(), 'cpu_count': os.cpu_count(),
              'commands': [], 'runs': [], 'preparation': [], 'corpora': {}}

    def save():
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')

    def execute(label, argv, cwd=ROOT, env=None):
        print(label, flush=True)
        before = cpu(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        p = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True, text=True,
                           env=env, timeout=600)
        row = {'label': label, 'argv': list(map(str, argv)), 'wall_seconds': time.perf_counter() - start,
               'tree_cpu_seconds': cpu(resource.RUSAGE_CHILDREN) - before,
               'load_average': list(os.getloadavg()), 'returncode': p.returncode}
        (out / f'{label}.stdout').write_text(p.stdout)
        (out / f'{label}.stderr').write_text(p.stderr)
        result['commands'].append(row)
        save()
        if p.returncode:
            print(p.stderr[-12000:], flush=True)
        p.check_returncode()
        return p, row

    if args.reuse_build:
        build = json.loads((out / 'build-manifest.json').read_text())
        if build['sources'] != sources:
            raise ValueError('experiment sources changed; stage a fresh build')
        if build['binary_sha256'] != digest(binary) or build['worker_sha256'] != digest(worker):
            raise ValueError('immutable executable changed')
    else:
        stage_sources(args.base_workspace.resolve(), stage)
        shutil.copy2(args.worker.resolve(), worker)
        execute('build-replay', ['cargo', 'build', '--release', '--locked', '--offline', '-p',
                                'avila-consensus', '--example', 'ecdsa_economics_replay'], cwd=stage,
                env=dict(os.environ, CARGO_TARGET_DIR=str(args.cargo_target.resolve())))
        shutil.copy2(args.cargo_target.resolve() / 'release/examples/ecdsa_economics_replay', binary)
        build = {'sources': sources, 'base_workspace': str(args.base_workspace.resolve()),
                 'base_lock_sha256': digest(stage / 'Cargo.lock'),
                 'binary_sha256': digest(binary), 'worker_sha256': digest(worker),
                 'staged_sources': {str(p.relative_to(stage)): digest(p)
                                    for p in sorted((stage / 'crates/avila-consensus').rglob('*.rs'))}}
        (out / 'build-manifest.json').write_text(json.dumps(build, indent=2) + '\n')
    result['build'] = build
    save()
    if args.build_only:
        return

    datasets = [('cases', 'cases', Path('/dev/null')), ('mainnet', 'scripts', args.historical_corpus.resolve()),
                ('regtest', 'chain', args.chain_corpus.resolve()), ('disk', 'chain', args.chain_corpus.resolve()),
                ('early', 'chain', ROOT / 'fixtures/mainnet-blocks-000000-000500.dat'),
                ('rollback', 'rollback', args.chain_corpus.resolve())]
    for name, kind, corpus in datasets:
        if args.only and name not in args.only:
            continue
        result['corpora'][name] = {'sha256': digest(corpus), 'bytes': corpus.stat().st_size}
        legacy = out / f'{name}.advice'
        source = 'regtest' if name in ('disk', 'rollback') else name
        shutil.copy2(args.reference_advice.resolve() / f'{source}.advice', legacy)
        expected_hints = dict(frames(legacy.read_bytes(), b'AVADVC03', 1))
        packed = out / f'{name}.hints'

        def replay(label, mode, path, storage=None, minimum=None):
            if storage is None:
                storage = out / f'{label}.db' if name == 'disk' else 'ram'
            if minimum is None:
                minimum = 0 if name in ('cases', 'rollback') else 64
            p, command = execute(label, [binary, 'chain' if mode == 'pack' and kind == 'rollback' else kind,
                                        corpus, mode, path, worker, 8192, minimum, 512, storage],
                                 env=dict(os.environ, AVILA_COINS_ENGINE='redb'))
            row = json.loads(p.stdout.strip().splitlines()[-1])
            row.update(name=name, label=label, tree_cpu_seconds=command['tree_cpu_seconds'])
            if mode != 'pack' and row['result_hash'] != EXPECTED[name]:
                raise ValueError(f'{label}: final state or Script outcome mismatch')
            if name == 'disk' and mode != 'pack':
                row['database_bytes'] = sum(p.stat().st_size for p in Path(storage).rglob('*') if p.is_file())
            if mode == 'pack':
                row.update(packed_bytes=Path(storage).stat().st_size, packed_sha256=digest(Path(storage)))
            return row

        row = replay(f'{name}-pack-reference', 'pack', legacy, packed)
        result['preparation'].append(row)
        modes = [m for m in args.modes if not (name == 'rollback' and m == 'produce')]
        reference = None
        for rep in range(args.repetitions):
            order = modes[rep % len(modes):] + modes[:rep % len(modes)]
            for mode in order:
                label = f'{name}-{mode}-{rep}'
                output = out / f'{label}.advice'
                path = output if mode == 'produce' else packed if mode == 'stream' else legacy
                row = replay(label, mode, path)
                row['rep'] = rep
                if reference is None:
                    reference = row
                if name != 'rollback' and (row['checks'] != reference['checks'] or
                                           row['false_checks'] != reference['false_checks'] or row['retry_groups'] or
                                           row['stream_rejected'] or row['sidecar_rejected']):
                    raise ValueError(f'{label}: healthy advice did not reproduce the baseline')
                if name == 'rollback' and mode in ('stream', 'candidate') and not row['retry_groups']:
                    raise ValueError('invalid spend did not exercise ordinary recovery')
                if mode == 'produce':
                    hints = dict(frames(output.read_bytes(), b'AVADVC03', 1))
                    if hints != expected_hints:
                        raise ValueError(f'{label}: fused hints differ from the independent producer')
                    row.update(producer_bytes=output.stat().st_size, exact_hints_match=True,
                               producer_sha256=digest(output))
                result['runs'].append(row)
                save()
                if mode == 'produce':
                    packed_output = out / f'{label}.hints'
                    prepared = replay(label + '-pack', 'pack', output, packed_output)
                    if packed_output.read_bytes() != packed.read_bytes():
                        raise ValueError('producer packing mismatch')
                    result['preparation'].append(prepared)
                    save()
        if args.two_pass and name in ('cases', 'mainnet', 'regtest'):
            trace, two_pass = out / f'{name}.trace', out / f'{name}-two-pass.advice'
            captured = replay(f'{name}-capture', 'capture', trace, 'ram')
            result['preparation'].append(captured)
            before_self = cpu(resource.RUSAGE_SELF)
            prepared = produce(trace, two_pass, worker)
            prepared.update(name=name, mode='two-pass-produce', parent_cpu_seconds=cpu(resource.RUSAGE_SELF) - before_self)
            prepared['tree_cpu_seconds'] = prepared['parent_cpu_seconds'] + prepared['child_cpu_seconds']
            if dict(frames(two_pass.read_bytes(), b'AVADVC03', 1)) != expected_hints:
                raise ValueError('independent two-pass producer changed hints')
            result['preparation'].append(prepared)
            save()
        save()


if __name__ == '__main__':
    main()
