#!/usr/bin/env python3
"""Adversarial stream/producer checks and separate sampled memory profiles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import time

from check_ecdsa_parallel import rss_tree
from ecdsa_economics_bench import EXPECTED
from ecdsa_parallel_bench import frames as legacy_frames, produce
from ecdsa_replay_bench import digest

MAGIC = b'AVHINT04'
EXPECTED['rare'] = hashlib.sha256(hashlib.sha256(bytes([1, 1])).digest()).hexdigest()


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def body(hints):
    counts = compact(len(hints)) + b''.join(compact(len(h)) for h in hints)
    values = [h for tx in hints for h in tx]
    packed = bytearray((len(values) + 3) // 4)
    escapes = bytearray()
    for i, h in enumerate(values):
        symbol = h if h < 2 else 2 if h == 255 else 3
        if symbol == 3:
            assert h in (2, 3)
            escapes.append(h)
        packed[i // 4] |= symbol << (2 * (i % 4))
    return counts + packed + escapes


def decode(data):
    offset = 0

    def count():
        nonlocal offset
        tag = data[offset]
        offset += 1
        if tag < 253:
            return tag
        size = {253: 2, 254: 4, 255: 8}[tag]
        value = int.from_bytes(data[offset:offset + size], 'little')
        offset += size
        return value

    counts = [count() for _ in range(count())]
    packed = data[offset:offset + (sum(counts) + 3) // 4]
    offset += len(packed)
    hints, i = [], 0
    for n in counts:
        tx = []
        for _ in range(n):
            symbol = (packed[i // 4] >> (2 * (i % 4))) & 3
            i += 1
            if symbol < 2:
                tx.append(symbol)
            elif symbol == 2:
                tx.append(255)
            else:
                tx.append(data[offset])
                offset += 1
        hints.append(tx)
    assert offset == len(data)
    assert body(hints) == data
    return hints


def frames(data):
    assert data[:8] == MAGIC
    offset = 8
    result = []
    while offset < len(data):
        key, size = data[offset:offset + 32], struct.unpack_from('<I', data, offset + 32)[0]
        offset += 36
        value = data[offset:offset + size]
        assert len(value) == size
        result.append((key, value))
        offset += size
    return result


def encode(items):
    return MAGIC + b''.join(k + struct.pack('<I', len(v)) + v for k, v in items)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build-dir', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--checked-worker', type=Path)
    ap.add_argument('--only', nargs='+', choices=['cases', 'mainnet', 'extras', 'memory', 'schedule'])
    ap.add_argument('--producer-mode', choices=['produce', 'produce-batch'], default='produce')
    ap.add_argument('--rare-cases', action='store_true')
    ap.add_argument('--historical-corpus', type=Path, default=Path('target/ecdsa-replay/corpus-linked-24/corpus.bin'))
    args = ap.parse_args()
    built, out = args.build_dir.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = {'sources': {'checker': digest(Path(__file__))}, 'runs': [],
               'binary_sha256': digest(built / 'replay'), 'worker_sha256': digest(built / 'worker')}
    if args.checked_worker:
        results['checked_worker_sha256'] = digest(args.checked_worker)

    def save():
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')

    def run(label, name='cases', mode='stream', sidecar=None, worker=None, batch=8192, minimum=None,
            sample=False, storage='ram', group_jobs=512):
        print(label, flush=True)
        kind, corpus = (name, Path('/dev/null')) if name in ('cases', 'rare') else (
            ('scripts', args.historical_corpus.resolve()) if name == 'mainnet' else
            ('chain', Path(__file__).resolve().parents[1] / 'fixtures/mainnet-blocks-000000-000500.dat') if name == 'early' else
            ('rollback' if name == 'rollback' else 'chain', Path('/tmp/spend-fixture.dat')))
        if minimum is None:
            minimum = 0 if name in ('cases', 'rare', 'rollback') else 64
        sidecar = sidecar or built / f'{name}.hints'
        argv = list(map(str, [built / 'replay', kind, corpus, mode, sidecar, worker or built / 'worker',
                             batch, minimum, group_jobs, storage]))
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1',
                   AVILA_COINS_ENGINE='redb')
        peak = processes = samples = 0
        start = time.perf_counter()
        with (out / f'{label}.stdout').open('w') as stdout, (out / f'{label}.stderr').open('w') as stderr:
            p = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env)
            while p.poll() is None:
                if sample:
                    rss, count = rss_tree(p.pid)
                    peak, processes, samples = max(peak, rss), max(processes, count), samples + 1
                if time.perf_counter() - start > 300:
                    p.kill()
                    p.wait()
                    raise ValueError(f'{label}: timeout')
                time.sleep(0.02)
        if p.returncode:
            raise ValueError((out / f'{label}.stderr').read_text())
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = json.loads((out / f'{label}.stdout').read_text().strip().splitlines()[-1])
        row.update(label=label, name=name, argv=argv, group_jobs=group_jobs, load_average=list(os.getloadavg()),
                   tree_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                   sampled_sum_rss_bytes=peak, max_processes=processes, samples=samples)
        if mode != 'pack' and row['result_hash'] != EXPECTED[name]:
            raise ValueError(f'{label}: wrong outcome')
        if row['max_retry_jobs'] > 512 or row['max_pending'] > 8192:
            raise ValueError(f'{label}: recovery bounds exceeded')
        results['runs'].append(row)
        save()
        return row

    for name in ['cases', 'mainnet']:
        if args.only and name not in args.only:
            continue
        original = (built / f'{name}.hints').read_bytes()
        items = frames(original)
        decoded = [(k, decode(v)) for k, v in items]
        assert encode([(k, body(h)) for k, h in decoded]) == original
        variants = {}
        for attack in ['bad-parity', 'false-claim', 'forged-true', 'all-bad']:
            modified = [(k, [list(tx) for tx in hints]) for k, hints in decoded]
            done = False
            for _, hints in modified:
                for tx in hints:
                    for i, h in enumerate(tx):
                        if (h == 255 if attack == 'forged-true' else h < 4):
                            tx[i] = 0 if attack == 'forged-true' else 255 if attack == 'false-claim' else h ^ 1
                            done = True
                            if attack != 'all-bad':
                                break
                    if done and attack != 'all-bad':
                        break
                if done and attack != 'all-bad':
                    break
            if done:
                variants[attack] = encode([(k, body(h)) for k, h in modified])
        variants.update(truncated=original[:-1], missing_prefix=encode(items[len(items) // 2 or 1:]),
                        missing_tail=encode(items[:len(items) // 2]), reordered=encode(list(reversed(items))),
                        wrong_hash=encode([(bytes([99]) * 32, items[0][1]), *items[1:]]),
                        oversized=MAGIC + items[0][0] + struct.pack('<I', (1 << 20) + 1),
                        bad_count=encode([(items[0][0], b'\xff' * 9), *items[1:]]),
                        noncanonical=encode([(items[0][0], b'\xfd\x00\x00'), *items[1:]]),
                        bad_magic=b'WRONG000' + original[8:],
                        trailing_body=encode([(items[0][0], items[0][1] + b'\x00'), *items[1:]]),
                        empty=MAGIC)
        if name == 'cases':
            # Exactly one valid frame: padding and escape errors cannot hide behind hash mismatches.
            malformed = bytearray(items[0][1])
            malformed[-1] |= 0xf0
            variants['padding'] = encode([(items[0][0], bytes(malformed))])
            variants['escape'] = encode([(items[0][0], body([[2], *decoded[0][1][1:]])[:-1] + b'\x04')])
            for n in range(1, 36):
                variants[f'header-truncation-{n}'] = MAGIC + items[0][0][:min(n, 32)] + b'\x00' * max(0, n - 32)
        for attack, payload in variants.items():
            path = out / f'{name}-{attack}.hints'
            path.write_bytes(payload)
            row = run(f'{name}-{attack}', name=name, sidecar=path)
            if attack in ('bad-parity', 'all-bad', 'forged-true') and not row['retry_groups']:
                raise ValueError(f'{attack}: expected verified rejection and fallback')
            if attack == 'false-claim' and row['retry_groups']:
                raise ValueError('a claimed false must be checked normally without speculative failure')

    if not args.only or 'extras' in args.only:
        run('missing-stream', sidecar=out / 'missing.hints')
        row = run('worker-exit', worker=Path('/bin/false'))
        if not row['retry_groups'] or not row['worker_errors']:
            raise ValueError('worker failure did not recover')
        run('missing-worker', worker=out / 'absent-worker')
        row = run('one-record-batches', batch=1)
        if row['retry_groups']:
            raise ValueError('healthy callback flush')
        if not run('one-record-failure', batch=1, sidecar=out / 'cases-bad-parity.hints')['retry_groups']:
            raise ValueError('callback failure did not retry')
        tiny = run('tiny-bypass', minimum=64)
        if tiny['hinted'] or tiny['workers'] or tiny['ordinary'] != 10:
            raise ValueError('small-group bypass')
        malformed = out / 'malformed-worker'
        malformed.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdin.buffer.read(135)\nsys.stdout.buffer.write(bytes([4])+bytes(8))\nsys.stdout.buffer.flush()\n')
        malformed.chmod(0o700)
        run('malformed-batch-verdict', worker=malformed, batch=1)
        for label, worker in [('exits', Path('/bin/false')), ('missing', out / 'absent-worker'), ('malformed', malformed)]:
            output = out / f'producer-{label}.advice'
            row = run(f'producer-{label}', mode=args.producer_mode, sidecar=output, worker=worker)
            if not row['worker_errors'] or row['produced'] or row['ordinary'] != 10 or row['retry_groups']:
                raise ValueError('producer failure must use ordinary verification exactly once')
            if any(h != 255 for _, hints in legacy_frames(output.read_bytes(), b'AVADVC03', 1) for h in hints):
                raise ValueError('failed producer emitted a claimed true')
            packed = out / f'producer-{label}.hints'
            run(f'producer-{label}-pack', mode='pack', sidecar=output, storage=packed)
            run(f'producer-{label}-recipient', sidecar=packed)
        if args.checked_worker:
            run('asan-stream', worker=args.checked_worker.resolve(), batch=1)
            run('asan-produce', mode=args.producer_mode, sidecar=out / 'asan-produce.advice', worker=args.checked_worker.resolve())
        run('producer-one-record-batches', mode=args.producer_mode, sidecar=out / 'producer-one.advice', batch=1)
        if not run('stream-invalid-spend-rollback', name='rollback', sidecar=built / 'regtest.hints')['retry_groups']:
            raise ValueError('invalid hinted spend must reject and restore the prefix')
        run('producer-invalid-spend-rollback', name='rollback', mode=args.producer_mode, sidecar=out / 'producer-rollback.advice')
        for name in ['early', 'regtest']:
            source = (built / f'{name}.hints').read_bytes()
            start = time.perf_counter()
            before = time.process_time()
            # No reader change is needed: absent frames already select ordinary checks.
            sparse = encode([(k, v) for k, v in frames(source) if any(decode(v))])
            elapsed, cpu_seconds = time.perf_counter() - start, time.process_time() - before
            path = out / f'{name}-sparse.hints'
            path.write_bytes(sparse)
            row = run(f'{name}-sparse', name=name, sidecar=path)
            row.update(dense_bytes=len(source), sparse_bytes=len(sparse), sparsify_wall_seconds=elapsed,
                       sparsify_cpu_seconds=cpu_seconds, sparse_sha256=digest(path))
            if row['retry_groups'] or row['stream_rejected']:
                raise ValueError('omitting hintless frames must preserve ordinary fallback')
        if args.rare_cases:
            trace, reference = out / 'rare.trace', out / 'rare.advice'
            run('rare-capture', name='rare', mode='capture', sidecar=trace)
            results['rare_preparation'] = produce(trace, reference, built / 'worker')
            exact = dict(legacy_frames(reference.read_bytes(), b'AVADVC03', 1))
            if sorted(h for hints in exact.values() for h in hints) != [2, 3]:
                raise ValueError('rare fixtures did not exercise both x >= n parities')
            packed = out / 'rare.hints'
            run('rare-pack', name='rare', mode='pack', sidecar=reference, storage=packed)
            run('rare-stream', name='rare', sidecar=packed, batch=1)
            generated = out / 'rare-produce.advice'
            run('rare-produce', name='rare', mode=args.producer_mode, sidecar=generated)
            if dict(legacy_frames(generated.read_bytes(), b'AVADVC03', 1)) != exact:
                raise ValueError('rare fused producer changed the hint')
            items = frames(packed.read_bytes())
            hints = decode(items[0][1])
            hints[0][0] ^= 1
            attack = out / 'rare-parity.hints'
            attack.write_bytes(encode([(items[0][0], body(hints))]))
            if not run('rare-wrong-parity', name='rare', sidecar=attack, batch=1)['retry_groups']:
                raise ValueError('rare false parity escaped verification')
            truncated = out / 'rare-truncated-escape.hints'
            truncated.write_bytes(encode([(items[0][0], items[0][1][:-1])]))
            if not run('rare-truncated-escape', name='rare', sidecar=truncated)['stream_rejected']:
                raise ValueError('truncated rare escape must fall back')
            if args.checked_worker:
                run('asan-rare-stream', name='rare', sidecar=packed, worker=args.checked_worker.resolve(), batch=1)
                run('asan-rare-produce', name='rare', mode=args.producer_mode,
                    sidecar=out / 'asan-rare.advice', worker=args.checked_worker.resolve())
    for mode in ['baseline', 'candidate', 'stream', args.producer_mode]:
        if args.only and 'memory' not in args.only:
            continue
        path = out / 'memory-produce.advice' if mode == args.producer_mode else built / (
            'mainnet.hints' if mode == 'stream' else 'mainnet.advice')
        run(f'memory-{mode}', name='mainnet', mode=mode, sidecar=path, sample=True)
    if args.only and 'schedule' in args.only:
        expected = dict(legacy_frames((built / 'mainnet.advice').read_bytes(), b'AVADVC03', 1))
        for rep in range(3):
            sizes = [512, 128, 64]
            for size in sizes[rep:] + sizes[:rep]:
                path = out / f'schedule-{size}-{rep}.advice'
                row = run(f'producer-schedule-{size}-{rep}', name='mainnet', mode=args.producer_mode,
                          sidecar=path, group_jobs=size)
                row['rep'] = rep
                actual = list(legacy_frames(path.read_bytes(), b'AVADVC03', 1))
                if len(dict(actual)) != len(actual) or dict(actual) != expected:
                    raise ValueError('scheduling changed producer output')
                row['exact_hints_match'] = True
                save()
    save()


if __name__ == '__main__':
    main()
