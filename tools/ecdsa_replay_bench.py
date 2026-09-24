#!/usr/bin/env python3
"""Stage and measure an isolated nonce-advice replay prototype.

The production sources stay unchanged. A copied workspace gets a signature hook
and single-thread script scheduling on BOTH baseline and candidate. The native
worker is a trusted local arithmetic process, not the untrusted hint producer.
No new dependencies, unsafe Rust, node configuration changes, or live state.
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


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise ValueError(f"staging patch no longer applies uniquely to {path.name}")
    path.write_text(text.replace(old, new))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--historical-corpus", type=Path, required=True)
    ap.add_argument("--chain-corpus", type=Path, default=Path('/tmp/spend-fixture.dat'))
    ap.add_argument("--repetitions", type=int, default=3)
    ap.add_argument("--build-only", action="store_true")
    ap.add_argument("--reuse-build", action="store_true")
    ap.add_argument("--cargo-target", type=Path)
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10:
        ap.error("repetitions 1..10")
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=args.reuse_build)
    stage = out / "workspace"
    target = args.cargo_target.resolve() if args.cargo_target else out / "cargo-target"
    vendor = list((Path(os.environ.get('CARGO_HOME', Path.home()/'.cargo'))/'registry/src').glob('*/secp256k1-sys-0.10.1/depend/secp256k1'))
    if len(vendor) != 1: raise ValueError("identify pinned libsecp source")
    secp = vendor[0]
    native = out/'worker'
    checked = out/'worker-checked'
    manifest = {"scope":"single-thread isolated replay; historical scripts use supplied undo; complete test-chain replay derives state",
                "git_head":subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
                "platform":platform.platform(), "compiler":subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                "cpu_model":next(line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
                "commands":[],"runs":[],"preparation":[],"sources":{},"corpora":{}}
    for name in ['ecdsa_advice.c','ecdsa_advice_worker.c','ecdsa_replay_hook.rs','ecdsa_replay.rs','ecdsa_replay_cases.rs']:
        manifest['sources'][name]=digest(root/'experiments/code'/name)
    manifest['sources']['runner']=digest(Path(__file__))
    manifest['sources']['Cargo.lock']=digest(root/'Cargo.lock')
    if args.reuse_build:
        built=json.loads((out/'build-manifest.json').read_text())
        if built['sources'] != manifest['sources']:
            raise ValueError('sources changed since build; use a fresh output directory')
        manifest['build']=built

    def save():
        (out/'results.json').write_text(json.dumps(manifest,indent=2)+'\n')

    def execute(label, argv, env=None, cwd=root):
        print(label,flush=True)
        before=resource.getrusage(resource.RUSAGE_CHILDREN)
        start=time.perf_counter()
        r=subprocess.run(list(map(str,argv)),cwd=cwd,env=env,capture_output=True,text=True)
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        entry={"label":label,"argv":list(map(str,argv)),"wall_seconds":time.perf_counter()-start,
               "tree_cpu_seconds":(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),"returncode":r.returncode}
        (out/f'{label}.stdout').write_text(r.stdout)
        (out/f'{label}.stderr').write_text(r.stderr)
        manifest['commands'].append(entry);save()
        if r.returncode: print(r.stderr[-12000:],flush=True)
        r.check_returncode()
        return r,entry

    if not args.reuse_build:
        stage.mkdir()
        for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']:
            shutil.copy2(root/name,stage/name)
        shutil.copytree(root/'crates',stage/'crates')
        shutil.copytree(root/'fixtures',stage/'fixtures')
        crate=stage/'crates/avila-consensus'
        shutil.copy2(root/'experiments/code/ecdsa_replay_hook.rs',crate/'src/experimental_advice.rs')
        shutil.copy2(root/'experiments/code/ecdsa_replay.rs',crate/'examples/ecdsa_replay.rs')
        (crate/'examples/ecdsa_replay_cases').mkdir()
        shutil.copy2(root/'experiments/code/ecdsa_replay_cases.rs',crate/'examples/ecdsa_replay_cases/mod.rs')
        with (crate/'src/lib.rs').open('a') as f:f.write('\n// Isolated experiment only.\npub mod experimental_advice;\n')
        declaration='    fn verify_ecdsa_signature(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {'
        replacement=declaration+'''\n        crate::experimental_advice::verify(sig, pubkey, sighash, || {\n            Self::verify_ecdsa_signature_untraced(sig, pubkey, sighash)\n        })\n    }\n\n    fn verify_ecdsa_signature_untraced(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {'''
        replace_once(crate/'src/sigchecker.rs',declaration,replacement)
        scheduling='''    let workers = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .min(jobs.len());'''
        replace_once(crate/'src/connect.rs',scheduling,'    let workers = 1usize; // BOTH experiment arms use one script thread.')
        common=['cc','-std=c99','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',
                '-D_POSIX_C_SOURCE=200809L','-include','stdio.h','-DECMULT_WINDOW_SIZE=15','-DECMULT_GEN_PREC_BITS=4',
                f'-I{secp}',f'-I{secp/"src"}',f'-I{secp/"include"}',root/'experiments/code/ecdsa_advice_worker.c',
                secp/'src/precomputed_ecmult.c',secp/'src/precomputed_ecmult_gen.c']
        execute('build-worker',[*common,'-O3','-o',native])
        execute('build-worker-checked',[*common,'-O1','-g','-DVERIFY','-fsanitize=address,undefined','-fno-omit-frame-pointer','-o',checked])
        execute('checked-selftest',[checked,'--selftest'],env=dict(os.environ,ADVICE_SELFTEST_ONLY='1',ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
        execute('build-replay',['cargo','build','--release','--locked','--offline','-p','avila-consensus','--example','ecdsa_replay'],
                cwd=stage,env=dict(os.environ,CARGO_TARGET_DIR=str(target)))
    binary=target/'release/examples/ecdsa_replay'
    manifest['binary_sha256']=digest(binary)
    manifest['worker_sha256']=digest(native)
    if not args.reuse_build:
        manifest['staged_sources']={str(p.relative_to(stage)):digest(p) for p in sorted((stage/'crates/avila-consensus/src').rglob('*.rs'))}
        (out/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    save()
    if args.build_only:return

    for name,kind,corpus in [('script-cases','cases',Path('/dev/null')),('mainnet','scripts',args.historical_corpus.resolve()),('regtest','chain',args.chain_corpus.resolve()),
                            ('early-mainnet','chain',root/'fixtures/mainnet-blocks-000000-000500.dat')]:
        manifest['corpora'][name]={'sha256':digest(corpus),'bytes':corpus.stat().st_size}
        trace=out/f'{name}.trace';hints=out/f'{name}.hints'
        def replay(label,mode,hintpath,bs=8192):
            process,entry=execute(label,[binary,kind,corpus,mode,hintpath,native,bs])
            row=json.loads(process.stdout.strip().splitlines()[-1]);row.update(name=name,label=label,tree_cpu_seconds=entry['tree_cpu_seconds'])
            return row
        captured=replay(f'{name}-capture','capture',trace)
        if name=='script-cases':
            expected=hashlib.sha256(hashlib.sha256(bytes([1,1,0,1,1,1,1,1,1])).digest()).hexdigest()
            if captured['result_hash']!=expected:raise ValueError('ordinary script-case expectations failed')
        manifest['preparation'].append(captured);save()
        data=trace.read_bytes()
        if len(data)%130:raise ValueError('trace framing')
        start=time.perf_counter();producer_cpu=0
        proc=subprocess.Popen([native],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        payload=bytearray()
        for off in range(0,len(data),130*8192):
            chunk=data[off:off+130*8192];count=len(chunk)//130
            proc.stdin.write(b'P'+struct.pack('<I',count)+chunk);proc.stdin.flush()
            result=proc.stdout.read(count)
            if len(result)!=count:raise ValueError('producer framing')
            for j,hint in enumerate(result):
                if (hint<4)!=bool(chunk[130*j+129]):raise ValueError('producer disagrees with Rust verifier')
            payload.extend(result);producer_cpu+=struct.unpack('<Q',proc.stdout.read(8))[0]
        proc.stdin.close();proc.wait()
        if proc.returncode:raise ValueError('producer failed')
        hints.write_bytes(payload)
        manifest['preparation'].append({'name':name,'mode':'produce_hints','count':len(payload),'wall_seconds':time.perf_counter()-start,
                                         'worker_cpu_seconds':producer_cpu/1e9,'hint_bytes':len(payload),'trace_sha256':digest(trace),'hints_sha256':digest(hints)})
        reference=None
        for rep in range(args.repetitions):
            modes=['baseline','candidate'] if rep%2==0 else ['candidate','baseline']
            for mode in modes:
                row=replay(f'{name}-{mode}-{rep}',mode,hints);row['rep']=rep
                if reference is None:reference=row['result_hash']
                if row['result_hash']!=reference or row['result_hash']!=captured['result_hash']:raise ValueError('replay result mismatch')
                if row['fallback']:raise ValueError('good hints unexpectedly failed')
                if row['checks']!=captured['checks']:raise ValueError('script execution trace changed')
                if mode=='candidate' and row['hinted']!=sum(h<4 for h in payload):raise ValueError('candidate did not verify every hinted check')
                manifest['runs'].append(row);save()
        # A plausible wrong R sign, a false-result claim, a missing tail, and
        # one forged true claim for a genuinely false check (when available).
        variants={}
        if any(h<4 for h in payload):
            first=next(i for i,h in enumerate(payload) if h<4)
            bad=bytearray(payload);bad[first]^=1;variants['bad-parity']=bad
            false=bytearray(payload);false[first]=255;variants['false-claim']=false
        variants['missing-tail']=payload[:len(payload)//2]
        if 255 in payload:
            bad=bytearray(payload);bad[bad.index(255)]=0;variants['forged-true']=bad
            variants['forged-all-true']=bytes(0 if h==255 else h for h in payload)
        for variant,content in variants.items():
            path=out/f'{name}-{variant}.hints';path.write_bytes(content)
            row=replay(f'{name}-{variant}','candidate',path)
            if row['result_hash']!=reference:raise ValueError('hostile/missing hints changed replay result')
            if variant=='bad-parity' and not row['fallback']:raise ValueError('wrong nonce point failed to trigger fallback')
            manifest['runs'].append(row);save()
    print(f'Results: {out/"results.json"}',flush=True)


if __name__=='__main__':main()
