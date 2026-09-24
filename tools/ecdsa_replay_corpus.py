#!/usr/bin/env python3
"""Copy a bounded public block/undo sample from a local Core data directory.

Reads only blkNNNNN.dat, revNNNNN.dat and their public XOR obfuscation key.
Never opens chainstate, credentials, wallets, or the node's writable databases.
The undo checksum binds a record to a parent hash, but is not a consensus
commitment: this is a script-replay corpus, not independently derived prestate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def decode_file(path, key):
    if path.stat().st_size > 256 << 20:
        raise ValueError("file exceeds bounded 256 MiB reader")
    raw = path.read_bytes()
    data = bytearray(raw)
    for i, k in enumerate(key):
        data[i::8] = data[i::8].translate(bytes(v ^ k for v in range(256)))
    return bytes(data), hashlib.sha256(raw).hexdigest()


def records(data, undo=False):
    offset = 0
    while offset + 8 <= len(data):
        if data[offset:offset+4] == b"\0" * 4:
            break
        if data[offset:offset+4] != bytes.fromhex("f9beb4d9"):
            raise ValueError(f"bad mainnet record magic at {offset}")
        size = struct.unpack_from("<I", data, offset+4)[0]
        if not 1 <= size <= 16 << 20:
            raise ValueError("record size outside bound")
        end = offset + 8 + size
        if end + (32 if undo else 0) > len(data):
            raise ValueError("truncated record")
        yield offset, data[offset+8:end], data[end:end+32] if undo else b""
        offset = end + (32 if undo else 0)


def compact(data, off):
    first = data[off]
    if first < 253:
        return first, off+1
    size = {253: 2, 254: 4, 255: 8}[first]
    return int.from_bytes(data[off+1:off+1+size], "little"), off+1+size


def height(block):
    _, off = compact(block, 80)
    off += 4  # transaction version
    if block[off:off+2] == b"\0\1":
        off += 2
    count, off = compact(block, off)
    if count != 1:
        raise ValueError("coinbase input count")
    off += 36
    size, off = compact(block, off)
    push = block[off]
    if not 1 <= push <= 5 or size < 1+push:
        raise ValueError("sample requires BIP34 height")
    return int.from_bytes(block[off+1:off+1+push], "little")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blocks-dir", type=Path, required=True)
    parser.add_argument("--file-number", type=int, required=True)
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.count <= 128 or not 0 <= args.file_number <= 99999:
        parser.error("count 1..128, file number 0..99999")
    args.output.mkdir(parents=True, exist_ok=False)
    key_path = args.blocks_dir / "xor.dat"
    key = key_path.read_bytes() if key_path.exists() else bytes(8)
    if len(key) != 8:
        raise ValueError("invalid XOR key size")
    blocks, block_hash = decode_file(args.blocks_dir / f"blk{args.file_number:05}.dat", key)
    undo, undo_hash = decode_file(args.blocks_dir / f"rev{args.file_number:05}.dat", key)
    candidates = sorted([(height(b), off, b) for off, b, _ in records(blocks)])
    # Physical block files can contain gaps and out-of-order downloads. Select
    # the first sufficiently long linked run; file order is not chain order.
    runs, run = [], []
    for item in candidates:
        if run and item[2][4:36] != sha256d(run[-1][2][:80]):
            runs.append(run)
            run = []
        run.append(item)
    if run:
        runs.append(run)
    candidates = next((r for r in runs if len(r) >= args.count), None)
    if candidates is None:
        raise ValueError(f"no linked run of {args.count} blocks; lengths {[len(r) for r in runs]}")
    undos = list(records(undo, True))
    entries = []
    previous = None
    output = args.output / "corpus.bin"
    with output.open("xb") as writer:
        writer.write(b"AVREPLAY")
        for h, block_off, block in candidates:
            if len(entries) == args.count:
                break
            if previous is not None and block[4:36] != previous:
                raise ValueError("sample blocks are not contiguous")
            matches = [(off, u, checksum) for off, u, checksum in undos
                       if sha256d(block[4:36] + u) == checksum]
            if len(matches) != 1:
                raise ValueError(f"undo match count {len(matches)} at height {h}")
            undo_off, payload, checksum = matches[0]
            writer.write(struct.pack("<III", h, len(block), len(payload)))
            writer.write(block)
            writer.write(payload)
            previous = sha256d(block[:80])
            entries.append({"height": h, "block_hash": previous[::-1].hex(),
                            "block_offset": block_off, "undo_offset": undo_off,
                            "block_bytes": len(block), "undo_bytes": len(payload),
                            "block_sha256": hashlib.sha256(block).hexdigest(),
                            "undo_sha256": hashlib.sha256(payload).hexdigest(),
                            "undo_checksum": checksum.hex()})
    if len(entries) != args.count:
        raise ValueError("not enough complete block/undo pairs")
    manifest = {"scope": "actual mainnet blocks with locally supplied undo/prestate; not genesis replay",
                "file_number": args.file_number, "source_block_sha256": block_hash,
                "source_undo_sha256": undo_hash, "entries": entries,
                "corpus_bytes": output.stat().st_size,
                "corpus_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    print(json.dumps({"blocks": len(entries), "first_height": entries[0]['height'],
                      "last_height": entries[-1]['height'], "bytes": output.stat().st_size}))


if __name__ == "__main__":
    main()
