#!/usr/bin/env python3
"""Bounded protocol/correctness checks for the local arithmetic worker.

Pass the ASan/UBSan/VERIFY worker and a public replay trace. This checks real
tuples, fresh batch acceptance, modified inputs, and rejected protocol framing.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--worker', type=Path, required=True)
    ap.add_argument('--trace', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    with args.trace.open('rb') as reader:
        records = reader.read(130*256)
    if len(records) % 130 or not records:
        raise ValueError('trace framing')
    count = len(records)//130
    rows = []
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')

    def call(label, packet, expected_exit=0):
        p = subprocess.run([str(args.worker.resolve())], input=packet, capture_output=True, env=env)
        if p.returncode != expected_exit:
            raise AssertionError(f'{label}: exit {p.returncode}, stderr {p.stderr[-2000:]!r}')
        if b'AddressSanitizer' in p.stderr or b'runtime error:' in p.stderr:
            raise AssertionError(f'{label}: sanitizer finding')
        rows.append({'case': label, 'returncode': p.returncode, 'stdout_bytes': len(p.stdout)})
        return p.stdout

    reply = call('ordinary_matches_Rust', b'V'+struct.pack('<I',count)+records)
    assert len(reply) == count+8 and reply[:count] == records[129::130]
    advice = call('producer_matches_Rust', b'P'+struct.pack('<I',count)+records)
    assert len(advice) == count+8
    assert bytes(int(v<4) for v in advice[:count]) == records[129::130]
    valid = bytearray()
    for i,hint in enumerate(advice[:count]):
        if hint < 4:
            valid.extend(records[130*i:130*i+129]+bytes([hint]))
    if not valid:
        raise ValueError('trace has no valid checks')
    prefix = b'B'+struct.pack('<I',len(valid)//130)
    reply = call('batch_accepts_valid',prefix+valid)
    assert len(reply)==9 and reply[0]==1
    changed = bytearray(valid); changed[0] ^= 1
    reply = call('batch_rejects_changed_digest',prefix+changed)
    assert len(reply)==9 and reply[0]==0
    changed = bytearray(valid); changed[129] ^= 1
    reply = call('batch_rejects_wrong_nonce_sign',prefix+changed)
    assert len(reply)==9 and reply[0]==0
    for label,packet in [('unknown_command',b'Z'),('zero_count',b'B'+struct.pack('<I',0)),
                         ('oversized_count',b'B'+struct.pack('<I',8193)),
                         ('truncated_record',b'B'+struct.pack('<I',1)+valid[:70])]:
        call(label,packet,1)
    args.output.write_text(json.dumps({'status':'pass','records':count,'cases':rows},indent=2)+'\n')
    print(json.dumps({'status':'pass','records':count,'cases':len(rows)}))


if __name__=='__main__':main()
