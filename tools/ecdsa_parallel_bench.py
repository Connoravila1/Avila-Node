#!/usr/bin/env python3
"""Reproducible bounded parallel advice experiment, in an isolated workspace.

Runs the existing persistent ScriptPool, preserves eight-block speculative
connect depth, charges native child CPU, and verifies durable reopen. Does not
change production sources or use a live node's chainstate.
"""
import argparse
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

from ecdsa_replay_bench import digest, replace_once


def frames(data, magic, width):
    if data[:8] != magic:
        raise ValueError("frame magic")
    offset = 8
    while offset < len(data):
        if len(data) - offset < 36:
            raise ValueError("frame header")
        key = data[offset:offset + 32]
        count = struct.unpack_from('<I', data, offset + 32)[0]
        offset += 36
        size = count * width
        if not 1 <= count <= 80_000 or size > len(data) - offset:
            raise ValueError("frame bound")
        yield key, data[offset:offset + size]
        offset += size


def encode_frames(items):
    return b'AVADVC03' + b''.join(key + struct.pack('<I', len(value)) + value for key, value in items)


def produce(trace, sidecar, worker):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    entries = list(frames(trace.read_bytes(), b'AVTRACE3', 130))
    records = b''.join(value for _, value in entries)
    process = subprocess.Popen([worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    hints = bytearray()
    cpu_ns = 0
    for offset in range(0, len(records), 8192 * 130):
        chunk = records[offset:offset + 8192 * 130]
        count = len(chunk) // 130
        process.stdin.write(b'P' + struct.pack('<I', count) + chunk)
        process.stdin.flush()
        answer = process.stdout.read(count)
        if len(answer) != count:
            raise ValueError("producer reply")
        for i, hint in enumerate(answer):
            if (hint < 4) != bool(chunk[130 * i + 129]):
                raise ValueError("producer disagrees with original verifier")
        hints.extend(answer)
        cpu_ns += struct.unpack('<Q', process.stdout.read(8))[0]
    process.stdin.close()
    if process.wait():
        raise ValueError("producer exit")
    output = {}
    offset = 0
    for key, value in entries:
        count = len(value) // 130
        hint = bytes(hints[offset:offset + count])
        if key in output and output[key] != hint:
            raise ValueError("context-dependent duplicate requires richer framing")
        output[key] = hint
        offset += count
    sidecar.write_bytes(encode_frames(sorted(output.items())))
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"mode": "produce", "wall_seconds": time.perf_counter() - start,
            "worker_cpu_seconds": cpu_ns / 1e9,
            "child_cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
            "records": len(records) // 130, "transactions": len(output),
            "sidecar_bytes": sidecar.stat().st_size, "payload_bytes": sum(map(len, output.values())),
            "trace_sha256": digest(trace), "sidecar_sha256": digest(sidecar)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--historical-corpus', type=Path, required=True)
    ap.add_argument('--chain-corpus', type=Path, default=Path('/tmp/spend-fixture.dat'))
    ap.add_argument('--cargo-target', type=Path)
    ap.add_argument('--reuse-build', action='store_true')
    ap.add_argument('--build-only', action='store_true')
    ap.add_argument('--reuse-advice', type=Path)
    ap.add_argument('--repetitions', type=int, default=3)
    ap.add_argument('--minimum', type=int, default=64)
    ap.add_argument('--group-jobs', type=int, default=512)
    ap.add_argument('--only', nargs='+', choices=['cases', 'mainnet', 'regtest', 'disk', 'early', 'rollback'])
    ap.add_argument('--skip-adversarial', action='store_true')
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10 or not 0 <= args.minimum <= 8192 or not 1 <= args.group_jobs <= 1024:
        ap.error('experiment bounds')
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=args.reuse_build)
    stage = out / 'workspace'
    target = args.cargo_target.resolve() if args.cargo_target else out / 'cargo-target'
    native = out / 'worker'
    names = ['ecdsa_advice.c', 'ecdsa_advice_worker.c', 'ecdsa_replay_hook.rs', 'ecdsa_replay_cases.rs',
             'ecdsa_parallel_hook.rs', 'ecdsa_parallel_pool.rs', 'ecdsa_parallel_replay.rs', 'ecdsa_parallel_rollback.rs']
    manifest = {"scope": "parallel ScriptPool; bounded job retry; supplied-undo mainnet scripts and complete chain replay",
                "git_head": subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                "platform": platform.platform(), "cpu_count": os.cpu_count(),
                "compiler": subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                "sources": {name: digest(root / 'experiments/code' / name) for name in names},
                "commands": [], "runs": [], "preparation": [], "corpora": {},
                "parameters": {"minimum": args.minimum, "group_jobs": args.group_jobs, "batch": 8192}}
    manifest['sources'].update(runner=digest(Path(__file__)), Cargo_lock=digest(root / 'Cargo.lock'),
                               staging_helpers=digest(root / 'tools/ecdsa_replay_bench.py'))
    if args.reuse_build:
        built = json.loads((out / 'build-manifest.json').read_text())
        if built['sources'] != manifest['sources']:
            raise ValueError('sources changed: rebuild in a fresh directory')
        manifest['build'] = built

    def save():
        (out / 'results.json').write_text(json.dumps(manifest, indent=2) + '\n')

    def execute(label, argv, cwd=root, env=None):
        print(label, flush=True)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = {"label": label, "argv": list(map(str, argv)), "wall_seconds": time.perf_counter() - start,
               "tree_cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
               "returncode": p.returncode, "load_average": list(os.getloadavg())}
        (out / f'{label}.stdout').write_text(p.stdout)
        (out / f'{label}.stderr').write_text(p.stderr)
        manifest['commands'].append(row)
        save()
        if p.returncode:
            print(p.stderr[-10000:], flush=True)
        p.check_returncode()
        return p, row

    if not args.reuse_build:
        stage.mkdir()
        for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']:
            shutil.copy2(root / name, stage / name)
        shutil.copytree(root / 'crates', stage / 'crates')
        shutil.copytree(root / 'fixtures', stage / 'fixtures')
        crate = stage / 'crates/avila-consensus'
        for source, dest in [('ecdsa_parallel_hook.rs', 'src/experimental_advice.rs'),
                             ('ecdsa_replay_hook.rs', 'src/experimental_replay_util.rs'),
                             ('ecdsa_parallel_replay.rs', 'examples/ecdsa_parallel_replay.rs')]:
            shutil.copy2(root / 'experiments/code' / source, crate / dest)
        (crate / 'examples/ecdsa_replay_cases').mkdir()
        shutil.copy2(root / 'experiments/code/ecdsa_replay_cases.rs', crate / 'examples/ecdsa_replay_cases/mod.rs')
        (crate / 'examples/ecdsa_parallel_rollback').mkdir()
        shutil.copy2(root / 'experiments/code/ecdsa_parallel_rollback.rs', crate / 'examples/ecdsa_parallel_rollback/mod.rs')
        with (crate / 'src/lib.rs').open('a') as f:
            f.write('\n// Isolated experiment.\npub mod experimental_advice;\npub mod experimental_replay_util;\n')
        sig = crate / 'src/sigchecker.rs'
        declaration = '    fn verify_ecdsa_signature(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {'
        replace_once(sig, declaration, declaration + '''
        crate::experimental_advice::verify(sig, pubkey, sighash, || {
            Self::verify_ecdsa_signature_untraced(sig, pubkey, sighash)
        })
    }
    fn verify_ecdsa_signature_untraced(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {''')
        declaration = '''pub fn check_input_scripts(
    tx: &Transaction,
    spent_outputs: &[TxOut],
    flags: crate::script::ScriptFlags,
) -> Result<(), ScriptError> {'''
        replace_once(sig, declaration, declaration + '''
    crate::experimental_advice::transaction(tx, || check_input_scripts_untraced(tx, spent_outputs, flags))
}
fn check_input_scripts_untraced(tx: &Transaction, spent_outputs: &[TxOut], flags: crate::script::ScriptFlags)
    -> Result<(), ScriptError> {''')
        connect = crate / 'src/connect.rs'
        s = connect.read_text()
        begin = s.index('    fn worker(&self) {')
        end = s.index('    fn submit(&self, job: ScriptJob)', begin)
        s = s[:begin] + (root / 'experiments/code/ecdsa_parallel_pool.rs').read_text() + '\n' + s[end:]
        connect.write_text(s)
        replace_once(connect, 'pub struct ScriptPool {', 'pub struct ScriptPool {\n    experimental_workers: usize,\n    experimental_active: std::sync::atomic::AtomicUsize,')
        replace_once(connect, 'queue: std::sync::Mutex::new(std::collections::VecDeque::new()),',
                     'queue: std::sync::Mutex::new(std::collections::VecDeque::new()),\n            experimental_workers: workers.max(1),\n            experimental_active: std::sync::atomic::AtomicUsize::new(0),')
        vendors = list((Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')) / 'registry/src').glob(
            '*/secp256k1-sys-0.10.1/depend/secp256k1'))
        if len(vendors) != 1:
            raise ValueError('pinned libsecp source')
        secp = vendors[0]
        common = ['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter',
                  '-D_POSIX_C_SOURCE=200809L', '-include', 'stdio.h', '-DECMULT_WINDOW_SIZE=15', '-DECMULT_GEN_PREC_BITS=4',
                  f'-I{secp}', f'-I{secp / "src"}', f'-I{secp / "include"}', root / 'experiments/code/ecdsa_advice_worker.c',
                  secp / 'src/precomputed_ecmult.c', secp / 'src/precomputed_ecmult_gen.c']
        execute('build-worker', [*common, '-O3', '-o', native])
        execute('build-replay', ['cargo', 'build', '--release', '--locked', '--offline', '-p', 'avila-consensus',
                                 '--example', 'ecdsa_parallel_replay'], cwd=stage,
                env=dict(os.environ, CARGO_TARGET_DIR=str(target)))
    binary = target / 'release/examples/ecdsa_parallel_replay'
    manifest['binary_sha256'] = digest(binary)
    manifest['worker_sha256'] = digest(native)
    if not args.reuse_build:
        manifest['staged_sources'] = {str(p.relative_to(stage)): digest(p)
                                      for p in sorted((stage / 'crates/avila-consensus').rglob('*.rs'))}
        (out / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    else:
        if manifest['binary_sha256'] != built['binary_sha256'] or manifest['worker_sha256'] != built['worker_sha256']:
            raise ValueError('built executable changed')
    save()
    if args.build_only:
        return

    datasets = [('cases', 'cases', Path('/dev/null')), ('mainnet', 'scripts', args.historical_corpus.resolve()),
                ('regtest', 'chain', args.chain_corpus.resolve()), ('disk', 'chain', args.chain_corpus.resolve()),
                ('early', 'chain', root / 'fixtures/mainnet-blocks-000000-000500.dat'),
                ('rollback', 'rollback', args.chain_corpus.resolve())]
    for name, kind, corpus in datasets:
        if args.only and name not in args.only:
            continue
        manifest['corpora'][name] = {'sha256': digest(corpus), 'bytes': corpus.stat().st_size}
        trace, sidecar = out / f'{name}.trace', out / f'{name}.advice'

        def replay(label, mode, path, worker=native, minimum=args.minimum):
            storage = out / f'{label}.db' if name == 'disk' else 'ram'
            p, command = execute(label, [binary, kind, corpus, mode, path, worker,
                                        8192, minimum, args.group_jobs, storage])
            row = json.loads(p.stdout.strip().splitlines()[-1])
            row.update(name=name, label=label, tree_cpu_seconds=command['tree_cpu_seconds'])
            if storage != 'ram':
                row['database_bytes'] = sum(p.stat().st_size for p in storage.rglob('*') if p.is_file())
            return row

        # Disk uses exactly the same fixture and transaction framing as RAM.
        source_name = 'regtest' if name in ('disk', 'rollback') else name
        existing = (args.reuse_advice.resolve() if args.reuse_advice else out) / f'{source_name}.advice'
        if existing.exists():
            if existing != sidecar:
                shutil.copy2(existing, sidecar)
            manifest['preparation'].append({'name': name, 'mode': 'reused', 'source': str(existing),
                                             'sidecar_sha256': digest(sidecar)})
        else:
            captured = replay(f'{name}-capture', 'capture', trace)
            manifest['preparation'].append(captured)
            prepared = produce(trace, sidecar, native)
            prepared['name'] = name
            manifest['preparation'].append(prepared)
            save()
        reference = None
        for rep in range(args.repetitions):
            for mode in (['baseline', 'candidate'] if rep % 2 == 0 else ['candidate', 'baseline']):
                row = replay(f'{name}-{mode}-{rep}', mode, sidecar, minimum=0 if name == 'rollback' else args.minimum)
                row['rep'] = rep
                if reference is None:
                    reference = row
                if (row['result_hash'], row['coins'], row['blocks']) != (
                        reference['result_hash'], reference['coins'], reference['blocks']):
                    raise ValueError('final state or Script outcome mismatch')
                if name != 'rollback' and (row['retry_groups'] or row['sidecar_rejected'] or row['checks'] != reference['checks']):
                    raise ValueError('unexpected failure with valid advice')
                if name == 'rollback' and mode == 'candidate' and not row['retry_groups']:
                    raise ValueError('invalid hinted spend must cause bounded ordinary recovery')
                manifest['runs'].append(row)
                save()
        if name == 'cases':
            expected = hashlib.sha256(hashlib.sha256(bytes([1, 1, 0, 1, 1, 1, 1, 1, 1])).digest()).hexdigest()
            if reference['result_hash'] != expected:
                raise ValueError('ordinary case outcomes')
        if args.skip_adversarial or name == 'rollback':
            continue
        items = list(frames(sidecar.read_bytes(), b'AVADVC03', 1))
        variants = {}
        for attack in ['bad-parity', 'false-claim', 'forged-true', 'all-bad']:
            edited = [(key, bytearray(value)) for key, value in items]
            done = False
            for _, values in edited:
                for i, hint in enumerate(values):
                    if (attack == 'forged-true' and hint == 255) or (attack != 'forged-true' and hint < 4):
                        values[i] = 0 if attack == 'forged-true' else (255 if attack == 'false-claim' else hint ^ 1)
                        done = True
                        if attack != 'all-bad':
                            break
                if done and attack != 'all-bad':
                    break
            if done:
                variants[attack] = encode_frames(edited)
        variants.update(missing_half=encode_frames(items[:len(items) // 2]),
                        reordered=encode_frames(list(reversed(items))),
                        truncated=sidecar.read_bytes()[:-1], empty=b'AVADVC03')
        if items:
            variants['duplicate'] = encode_frames([items[0], items[0]])
            variants['oversized-count'] = b'AVADVC03' + items[0][0] + struct.pack('<I', 0xffffffff)
        for attack, payload in variants.items():
            path = out / f'{name}-{attack}.advice'
            path.write_bytes(payload)
            # Force batching for small adversarial fixtures, including one-check groups.
            row = replay(f'{name}-{attack}', 'candidate', path, minimum=0)
            if row['result_hash'] != reference['result_hash'] or row['max_retry_jobs'] > args.group_jobs:
                raise ValueError('hostile advice changed outcome or exceeded recovery bound')
            manifest['runs'].append(row)
            save()
        for attack, path, worker in [('absent', out / 'does-not-exist', native),
                                     ('worker-exit', sidecar, Path('/bin/false'))]:
            row = replay(f'{name}-{attack}', 'candidate', path, worker, minimum=0)
            if row['result_hash'] != reference['result_hash']:
                raise ValueError('unavailable helper changed outcome')
            manifest['runs'].append(row)
            save()


if __name__ == '__main__':
    main()
