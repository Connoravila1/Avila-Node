#!/usr/bin/env python3
"""Additional boundary checks and separate sampled process-tree RSS profiles."""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import time

from ecdsa_parallel_bench import encode_frames, frames


def rss_tree(pid):
    """Sum RSS, including shared pages once per process; NOT private memory."""
    seen, todo = set(), [pid]
    rss = 0
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        base = Path('/proc') / str(current)
        try:
            for line in (base / 'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    rss += int(line.split()[1]) * 1024
            # Worker children may belong to a non-main Rust thread.
            for task in (base / 'task').iterdir():
                todo.extend(map(int, (task / 'children').read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return rss, len(seen)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--worker', type=Path, required=True)
    ap.add_argument('--checked-worker', type=Path)
    ap.add_argument('--advice-dir', type=Path, required=True)
    ap.add_argument('--historical-corpus', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    reference = '26c99b5f964b84b96f818f43cab06fd2cfe4d024128a6313df36747a5f46d557'

    def run(label, kind='cases', corpus=Path('/dev/null'), mode='candidate', sidecar=None,
            worker=None, batch=8192, minimum=0, sample=False):
        print(label, flush=True)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        argv = list(map(str, [args.binary.resolve(), kind, corpus, mode,
                             sidecar or args.advice_dir.resolve() / 'cases.advice',
                             worker or args.worker.resolve(), batch, minimum, 512, 'ram']))
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        peak = processes = samples = 0
        start = time.perf_counter()
        with (out / f'{label}.stdout').open('w') as stdout, (out / f'{label}.stderr').open('w') as stderr:
            p = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env)
            while p.poll() is None:
                if sample:
                    rss, count = rss_tree(p.pid)
                    peak, processes, samples = max(peak, rss), max(processes, count), samples + 1
                if time.perf_counter() - start > 180:
                    p.kill()
                    p.wait()
                    raise ValueError(f'{label}: timed out')
                time.sleep(0.02)
            if p.returncode:
                raise ValueError((out / f'{label}.stderr').read_text())
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = json.loads((out / f'{label}.stdout').read_text().strip().splitlines()[-1])
        row.update(label=label, argv=argv, tree_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                   sampled_sum_rss_bytes=peak, max_processes=processes, samples=samples)
        expected = reference if kind == 'cases' else '63d23d5bae36386939c31d955fcc686266ae569d56ab3e9104dc23fe285aac92'
        if row['result_hash'] != expected:
            raise ValueError('outcome mismatch')
        rows.append(row)
        (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        return row

    # Both successful and failing flushes INSIDE an ECDSA callback, not just
    # the more common end-of-group drain.
    if run('one-record-batches', batch=1)['retry_groups']:
        raise ValueError('valid one-record batches')
    attacked = args.advice_dir.resolve() / 'cases-bad-parity.advice'
    if not run('one-record-failure', sidecar=attacked, batch=1)['retry_groups']:
        raise ValueError('wrong parity must retry')
    all_true = out / 'all-false-forged-true.advice'
    original = (args.advice_dir.resolve() / 'cases.advice').read_bytes()
    all_true.write_bytes(encode_frames([(key, bytes(0 if h == 255 else h for h in value))
                                       for key, value in frames(original, b'AVADVC03', 1)]))
    if not run('all-false-forged-true', sidecar=all_true, batch=1)['retry_groups']:
        raise ValueError('false checks disguised as true must recover')
    row = run('tiny-work-bypass', minimum=64)
    if row['hinted'] or row['workers'] or row['ordinary'] != 10:
        raise ValueError('small groups must bypass speculation and workers')
    row = run('missing-executable', worker=out / 'absent-executable')
    if not row['worker_errors'] or not row['retry_groups']:
        raise ValueError('missing executable did not recover')
    malformed = out / 'bad-verdict-worker'
    malformed.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdin.buffer.read(135)\nsys.stdout.buffer.write(bytes([2])+bytes(8))\nsys.stdout.buffer.flush()\n')
    malformed.chmod(0o700)
    row = run('malformed-worker-verdict', worker=malformed)
    if not row['worker_errors'] or not row['retry_groups']:
        raise ValueError('malformed verdict did not recover')
    oversized = out / 'oversized.advice'
    with oversized.open('wb') as f:
        f.truncate((32 << 20) + 1)
    if not run('oversized-sidecar', sidecar=oversized)['sidecar_rejected']:
        raise ValueError('oversized sidecar not rejected')
    if args.checked_worker:
        if run('asan-boundary', worker=args.checked_worker.resolve(), batch=1)['retry_groups']:
            raise ValueError('sanitized worker unexpectedly failed')
    for mode in ['baseline', 'candidate']:
        run(f'memory-{mode}', kind='scripts', corpus=args.historical_corpus.resolve(), mode=mode,
            sidecar=args.advice_dir.resolve() / 'mainnet.advice', minimum=64, sample=True)


if __name__ == '__main__':
    main()
