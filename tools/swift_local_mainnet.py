#!/usr/bin/env python3
"""Self-hosted CLI check for Swift IBD over the committed mainnet h0..500 slice.

This deliberately small local provider derives BIP456 survivor hints and BIP455
spent-coin replies from the fixture itself. The claims remain untrusted: the
installed Avila CLI runs its normal full-check Swift path, audits/promotes to a
fresh directory, and is compared with a separate strict ordinary sync. Nothing
in this tool reads, starts, or writes the operator's normal datadir.

Because the pinned 500-block mainnet prefix is below today's anti-DoS minimum
chain-work threshold, the harness first submits only those headers to a fresh
private node through ordinary localhost `submitheader` RPC. It then cleanly
stops and clones that header-only state; Swift and ordinary body validation
still use the installed production parameters.

Run under tools/guard_run.sh. The fixture reader is capped at its exact known
length and block count; the P2P peer binds only to loopback; each CLI run has a
deadline; and every datadir/workspace is inside a newly-created private temp
directory. The default installed CLI is checked against its adjacent
validated.json receipt; candidate binaries require --allow-other-binary.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO


REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "fixtures/mainnet-blocks-000000-000500.dat"
FIXTURE_BYTES = 114_278
FIXTURE_SHA256 = "ef9cb1e45eaaafa55d23016d7dfce3e8f64f56609573e18b9a8940b8b1ac3d73"
MAGIC = bytes.fromhex("f9beb4d9")
TARGET_HEIGHT = 500
MAX_FIXTURE_BYTES = 114_278
MAX_BLOCKS = 501
MAX_HEADER_SEED_SECONDS = 45
MAX_BLOCK_BYTES = 4_000_000
MAX_TXS = 10_000
MAX_INPUTS_PER_BLOCK = 100_000
MAX_TOTAL_CLAIMS = 100_000
MAX_HELPER_COINS = 1_000_000
MAX_FRAME_BYTES = 4_000_000
MAX_PROVIDER_BYTES = 16 * 1024 * 1024
MAX_P2P_CONNECTIONS = 8
MAX_P2P_REQUESTS = 10_000
MAX_RPC_WAIT_SECONDS = 60
MAX_SYNC_SECONDS = 180
MAX_BAD_HINT_SECONDS = 25
MAX_RPC_BODY = 1_000_000
PROTOCOL_VERSION = 70017
NODE_NETWORK_WITNESS = 9


class FixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class TxOut:
    value: int
    script: bytes


@dataclass(frozen=True)
class Coin:
    output: TxOut
    height: int
    coinbase: bool


@dataclass(frozen=True)
class Tx:
    txid: bytes  # Bitcoin's serialized/internal byte order.
    inputs: tuple[bytes, ...]  # Serialized 36-byte outpoints.
    outputs: tuple[TxOut, ...]
    coinbase: bool


@dataclass(frozen=True)
class Block:
    raw: bytes
    header: bytes
    block_hash: bytes  # Serialized/internal byte order.
    txs: tuple[Tx, ...]


@dataclass(frozen=True)
class SpentRecord:
    input_index: int
    coin: Coin


def dsha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_compact(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset >= len(data):
        raise FixtureError("truncated CompactSize")
    tag = data[offset]
    offset += 1
    if tag < 0xfd:
        value = tag
    else:
        width = {0xfd: 2, 0xfe: 4, 0xff: 8}[tag]
        if offset + width > len(data):
            raise FixtureError("truncated CompactSize payload")
        value = int.from_bytes(data[offset:offset + width], "little")
        offset += width
        if (tag == 0xfd and value < 0xfd) or (tag == 0xfe and value <= 0xffff) or (
            tag == 0xff and value <= 0xffffffff
        ):
            raise FixtureError("noncanonical CompactSize")
    if value > limit:
        raise FixtureError(f"CompactSize {value} exceeds local limit {limit}")
    return value, offset


def take(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end < offset or end > len(data):
        raise FixtureError("truncated block serialization")
    return data[offset:end], end


def read_varbytes(data: bytes, offset: int, limit: int) -> tuple[bytes, int]:
    size, offset = read_compact(data, offset, limit)
    return take(data, offset, size)


def parse_tx(data: bytes, offset: int) -> tuple[Tx, int]:
    start = offset
    version, offset = take(data, offset, 4)
    witness = False
    if offset + 2 <= len(data) and data[offset] == 0 and data[offset + 1] != 0:
        flag = data[offset + 1]
        if flag != 1:
            raise FixtureError("fixture uses unsupported transaction optional flags")
        witness = True
        offset += 2
    vin_start = offset
    input_count, offset = read_compact(data, offset, MAX_INPUTS_PER_BLOCK)
    inputs: list[bytes] = []
    for _ in range(input_count):
        outpoint, offset = take(data, offset, 36)
        inputs.append(outpoint)
        _, offset = read_varbytes(data, offset, 10_000)
        _, offset = take(data, offset, 4)
    vin_end = offset
    output_start = offset
    output_count, offset = read_compact(data, offset, MAX_INPUTS_PER_BLOCK)
    outputs: list[TxOut] = []
    for _ in range(output_count):
        amount, offset = take(data, offset, 8)
        script, offset = read_varbytes(data, offset, 10_000)
        value = struct.unpack("<q", amount)[0]
        if value < 0 or value > 21_000_000 * 100_000_000:
            raise FixtureError("fixture output amount outside MoneyRange")
        outputs.append(TxOut(value, script))
    outputs_end = offset
    if witness:
        for _ in range(input_count):
            count, offset = read_compact(data, offset, 100_000)
            for _ in range(count):
                _, offset = read_varbytes(data, offset, 4_000_000)
    locktime, offset = take(data, offset, 4)
    stripped = version + data[vin_start:vin_end] + data[output_start:outputs_end] + locktime
    is_coinbase = (
        input_count == 1
        and inputs[0][:32] == bytes(32)
        and inputs[0][32:] == b"\xff\xff\xff\xff"
    )
    if offset <= start:
        raise FixtureError("transaction parser made no progress")
    return Tx(dsha(stripped), tuple(inputs), tuple(outputs), is_coinbase), offset


def load_blocks(path: Path) -> list[Block]:
    if path.resolve() != FIXTURE.resolve():
        raise FixtureError("only the pinned local 0..500 fixture is accepted")
    stat = path.stat()
    if stat.st_size != FIXTURE_BYTES or stat.st_size > MAX_FIXTURE_BYTES:
        raise FixtureError(f"fixture length is {stat.st_size}, expected {FIXTURE_BYTES}")
    with path.open("rb") as f:
        raw_file = f.read(MAX_FIXTURE_BYTES + 1)
    if len(raw_file) != FIXTURE_BYTES or hashlib.sha256(raw_file).hexdigest() != FIXTURE_SHA256:
        raise FixtureError("fixture length or SHA256 mismatch")
    blocks: list[Block] = []
    offset = 0
    while offset < len(raw_file):
        if len(blocks) >= MAX_BLOCKS or offset + 8 > len(raw_file):
            raise FixtureError("truncated framing or too many blocks")
        if raw_file[offset:offset + 4] != MAGIC:
            raise FixtureError("wrong mainnet message magic")
        length = struct.unpack_from("<I", raw_file, offset + 4)[0]
        start = offset + 8
        end = start + length
        if not length or length > MAX_BLOCK_BYTES or end > len(raw_file):
            raise FixtureError("block length outside fixture bound")
        raw = raw_file[start:end]
        if len(raw) < 81:
            raise FixtureError("short block")
        count, pos = read_compact(raw, 80, MAX_TXS)
        txs = []
        for _ in range(count):
            tx, pos = parse_tx(raw, pos)
            txs.append(tx)
        if pos != len(raw) or not txs or not txs[0].coinbase or any(t.coinbase for t in txs[1:]):
            raise FixtureError("invalid fixture transaction framing/order")
        header = raw[:80]
        blocks.append(Block(raw, header, dsha(header), tuple(txs)))
        offset = end
    if len(blocks) != MAX_BLOCKS or offset != len(raw_file):
        raise FixtureError("fixture must contain exactly heights 0..=500")
    if blocks[0].block_hash[::-1].hex() != (
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    ):
        raise FixtureError("fixture genesis is not Bitcoin mainnet")
    for previous, current in zip(blocks, blocks[1:]):
        if current.header[4:36] != previous.block_hash:
            raise FixtureError("fixture header linkage mismatch")
    return blocks


def outpoint(txid: bytes, vout: int) -> bytes:
    return txid + struct.pack("<I", vout)


def spendable(output: TxOut) -> bool:
    return len(output.script) == 0 or output.script[0] != 0x6a


def helper_dataset(blocks: list[Block]) -> tuple[dict[bytes, list[SpentRecord]], list[list[int]], int, int]:
    # The helper is independent of Chainstate: it only walks the checked raw
    # fixture in transaction order and maintains a strict local live map.
    live: dict[bytes, Coin] = {}
    responses: dict[bytes, list[SpentRecord]] = {}
    outputs_at_height: list[list[bytes]] = [[] for _ in range(MAX_BLOCKS)]
    total_txs = 0
    total_claims = 0
    for height, block in enumerate(blocks[1:], start=1):
        total_txs += len(block.txs)
        local = set()
        records: list[SpentRecord] = []
        ordinal = 0
        input_index = 0
        for tx in block.txs:
            if not tx.coinbase:
                for previous in tx.inputs:
                    if input_index >= MAX_INPUTS_PER_BLOCK:
                        raise FixtureError("per-block input cap exceeded")
                    if previous in local:
                        local.remove(previous)
                        live.pop(previous, None)
                    else:
                        coin = live.pop(previous, None)
                        if coin is None or coin.height >= height:
                            raise FixtureError("missing, duplicate, or future helper input")
                        records.append(SpentRecord(input_index, coin))
                        total_claims += 1
                        if total_claims > MAX_TOTAL_CLAIMS:
                            raise FixtureError("total helper claim cap exceeded")
                    input_index += 1
            for vout, output in enumerate(tx.outputs):
                if not spendable(output):
                    continue
                op = outpoint(tx.txid, vout)
                if op in live:
                    raise FixtureError("fixture repeats a live output outpoint")
                coin = Coin(output, height, tx.coinbase)
                live[op] = coin
                local.add(op)
                outputs_at_height[height].append(op)
                ordinal += 1
                if len(live) > MAX_HELPER_COINS:
                    raise FixtureError("helper live-set cap exceeded")
        if records:
            responses[block.block_hash] = records
    hints: list[list[int]] = [[] for _ in range(MAX_BLOCKS)]
    for height in range(1, MAX_BLOCKS):
        hints[height] = [i for i, op in enumerate(outputs_at_height[height]) if op in live]
    return responses, hints, total_txs, total_claims


def set_bit(buf: bytearray, pos: int) -> None:
    buf[pos // 8] |= 1 << (pos % 8)


def encode_ef(indices: list[int]) -> bytes:
    if not indices:
        return compact_size(0)
    if indices != sorted(set(indices)) or indices[0] < 0 or indices[-1] > 0xffffffff:
        raise FixtureError("survivor indices must be sorted unique u32")
    n = len(indices)
    maximum = indices[-1]
    if n > maximum + 1:
        raise FixtureError("Elias-Fano set cardinality exceeds its universe")
    quotient = (maximum + 1) // n
    low_bits = quotient.bit_length() - 1
    low_count = n * low_bits
    high_count = n + (maximum >> low_bits)
    low = bytearray((low_count + 7) // 8)
    high = bytearray((high_count + 7) // 8)
    for ordinal, value in enumerate(indices):
        for bit in range(low_bits):
            if (value >> bit) & 1:
                set_bit(low, ordinal * low_bits + bit)
        set_bit(high, (value >> low_bits) + ordinal)
    return (
        compact_size(n)
        + compact_size(maximum)
        + bytes(low)
        + bytes(high)
    )


def hints_file(records: list[list[int]]) -> bytes:
    if len(records) != MAX_BLOCKS:
        raise FixtureError("wrong number of BIP456 records")
    encoded = bytearray(b"UTXO\x00" + struct.pack("<I", TARGET_HEIGHT))
    for row in records:
        encoded.extend(encode_ef(row))
        if len(encoded) > 16 * 1024 * 1024:
            raise FixtureError("generated hints exceed the local byte limit")
    return bytes(encoded)


def make_bad_hints(records: list[list[int]]) -> bytes:
    rows = [list(row) for row in records]
    # Omit one true checkpoint survivor. This remains a valid sorted EF row,
    # but the independently accumulated final coin set must reject the lie.
    mutated = False
    for height in range(MAX_BLOCKS - 1, 0, -1):
        if rows[height]:
            rows[height].pop()
            mutated = True
            break
    if not mutated:
        raise FixtureError("fixture has no survivor to omit in the negative control")
    return hints_file(rows)


def compress_amount(amount: int) -> int:
    if amount == 0:
        return 0
    exponent = 0
    while amount % 10 == 0 and exponent < 9:
        amount //= 10
        exponent += 1
    if exponent < 9:
        digit = amount % 10
        amount //= 10
        return 1 + (amount * 9 + digit - 1) * 10 + exponent
    return 1 + (amount - 1) * 10 + 9


def encode_script(script: bytes) -> bytes:
    if len(script) == 25 and script[:3] == bytes.fromhex("76a914") and script[-2:] == bytes.fromhex("88ac"):
        return compact_size(1) + script[3:23]
    if len(script) == 35 and script[0] == 33 and script[1] in (2, 3) and script[-1] == 0xac:
        return compact_size(script[1]) + script[2:34]
    if len(script) == 67 and script[:2] == bytes.fromhex("4104") and script[-1] == 0xac:
        return compact_size(4) + script[2:66]
    if len(script) == 23 and script[:2] == bytes.fromhex("a914") and script[-1] == 0x87:
        return compact_size(5) + script[2:22]
    if len(script) == 34 and script[:2] == bytes.fromhex("0020"):
        return compact_size(6) + script[2:]
    if len(script) == 22 and script[:2] == bytes.fromhex("0014"):
        return compact_size(7) + script[2:]
    if len(script) == 34 and script[:2] == bytes.fromhex("5120"):
        return compact_size(8) + script[2:]
    if len(script) > 10_000:
        raise FixtureError("spent script exceeds protocol/local cap")
    return compact_size(0) + compact_size(len(script)) + script


def encode_spent(block_hash: bytes, records: list[SpentRecord]) -> bytes:
    if len(records) > MAX_INPUTS_PER_BLOCK:
        raise FixtureError("spent claims exceed response cap")
    out = bytearray(block_hash + compact_size(len(records)))
    prior = -1
    for record in records:
        if record.input_index <= prior or record.coin.height >= TARGET_HEIGHT + 1:
            raise FixtureError("invalid response input index or coin height")
        prior = record.input_index
        coin = record.coin
        code = coin.height * 2 + int(coin.coinbase)
        out.extend(struct.pack("<II", record.input_index, code))
        out.extend(compact_size(compress_amount(coin.output.value)))
        out.extend(encode_script(coin.output.script))
        if len(out) > MAX_FRAME_BYTES:
            raise FixtureError("spent response exceeds frame cap")
    return bytes(out)


def frame(command: str, payload: bytes) -> bytes:
    name = command.encode("ascii")
    if not 1 <= len(name) <= 12 or len(payload) > MAX_FRAME_BYTES:
        raise FixtureError("outgoing P2P frame outside bounds")
    return (
        MAGIC + name.ljust(12, b"\x00") + struct.pack("<I", len(payload))
        + dsha(payload)[:4] + payload
    )


def read_exact(stream: socket.socket, length: int) -> bytes:
    if length < 0 or length > MAX_FRAME_BYTES + 24:
        raise FixtureError("read length outside frame cap")
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError
        result.extend(chunk)
    return bytes(result)


def read_frame(stream: socket.socket) -> tuple[str, bytes]:
    head = read_exact(stream, 24)
    if head[:4] != MAGIC:
        raise FixtureError("peer sent wrong network magic")
    command = head[4:16].split(b"\x00", 1)[0].decode("ascii", "strict")
    length = struct.unpack_from("<I", head, 16)[0]
    if length > MAX_FRAME_BYTES:
        raise FixtureError("incoming P2P frame exceeds 4 MiB")
    payload = read_exact(stream, length)
    if dsha(payload)[:4] != head[20:24]:
        raise FixtureError("P2P checksum mismatch")
    return command, payload


def net_addr() -> bytes:
    # services + IPv4-mapped 0.0.0.0 + port 8333 in network byte order.
    return struct.pack("<Q", NODE_NETWORK_WITNESS) + bytes(10) + b"\xff\xff" + bytes(4) + struct.pack(">H", 8333)


def version_payload() -> bytes:
    user_agent = b"/avila-swift-local-fixture:1.0/"
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, NODE_NETWORK_WITNESS, int(time.time()))
        + net_addr() + net_addr() + struct.pack("<Q", 0x4156494c41535746)
        + compact_size(len(user_agent)) + user_agent + struct.pack("<iB", TARGET_HEIGHT, 0)
    )


def feature_payload() -> bytes:
    name = b"blockspentcoinsv1"
    return compact_size(len(name)) + name + compact_size(1) + b"\x00"


def parse_getheaders(payload: bytes) -> tuple[list[bytes], bytes]:
    if len(payload) < 4:
        raise FixtureError("truncated getheaders protocol version")
    _version = struct.unpack_from("<I", payload, 0)[0]
    count, pos = read_compact(payload, 4, 101)
    if pos + count * 32 + 32 != len(payload):
        raise FixtureError("malformed getheaders payload")
    locators = [payload[pos + i * 32:pos + (i + 1) * 32] for i in range(count)]
    pos += count * 32
    return locators, payload[pos:]


def encode_headers(headers: list[bytes]) -> bytes:
    if len(headers) > 2_000:
        raise FixtureError("headers response exceeds protocol count")
    return compact_size(len(headers)) + b"".join(header + b"\x00" for header in headers)


def parse_getdata(payload: bytes) -> list[tuple[int, bytes]]:
    count, pos = read_compact(payload, 0, 50_000)
    if pos + count * 36 != len(payload):
        raise FixtureError("malformed getdata payload")
    vectors = []
    for _ in range(count):
        inv_type = struct.unpack_from("<I", payload, pos)[0]
        vectors.append((inv_type, payload[pos + 4:pos + 36]))
        pos += 36
    return vectors


class LocalProvider:
    def __init__(self, blocks: list[Block], replies: dict[bytes, list[SpentRecord]], *, feature: bool, once: bool):
        self.blocks = {block.block_hash: block for block in blocks[1:]}
        self.heights = {block.block_hash: height for height, block in enumerate(blocks[1:], start=1)}
        self.headers = [block.header for block in blocks[1:]]
        self.replies = replies
        self.feature = feature
        self.once = once
        self.served: set[bytes] = set()
        self.claim_count = 0
        self.spent_request_count = 0
        self.outgoing_bytes = 0
        self.request_count = 0
        self.connection_count = 0
        self.errors: list[str] = []
        self.stop_event = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(MAX_P2P_CONNECTIONS)
        self.listener.settimeout(0.2)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("local provider did not stop within its bound")
        if self.errors:
            raise RuntimeError("local provider failed: " + "; ".join(self.errors))

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if address[0] != "127.0.0.1":
                client.close()
                self.errors.append("refused non-loopback connection")
                continue
            self.connection_count += 1
            if self.connection_count > MAX_P2P_CONNECTIONS:
                client.close()
                self.errors.append("connection cap exceeded")
                continue
            client.settimeout(0.5)
            try:
                self._serve_client(client)
            except (EOFError, ConnectionError, OSError):
                pass
            except Exception as error:  # report into parent without wedging sync
                self.errors.append(str(error))
            finally:
                client.close()

    def _send(self, client: socket.socket, command: str, payload: bytes = b"") -> None:
        self.outgoing_bytes += len(payload) + 24
        if self.outgoing_bytes > MAX_PROVIDER_BYTES:
            raise FixtureError("provider outgoing-byte cap exceeded")
        client.sendall(frame(command, payload))

    def _serve_client(self, client: socket.socket) -> None:
        sent_version = False
        while not self.stop_event.is_set():
            try:
                command, payload = read_frame(client)
            except socket.timeout:
                continue
            if command == "version" and not sent_version:
                sent_version = True
                self._send(client, "version", version_payload())
                if self.feature:
                    self._send(client, "feature", feature_payload())
                self._send(client, "verack")
            elif command == "ping":
                self._send(client, "pong", payload)
            elif command == "getheaders":
                locators, stop_hash = parse_getheaders(payload)
                # self.headers[0] is h1; locator positions are heights.
                positions = {header_hash(header): index + 1 for index, header in enumerate(self.headers)}
                positions[header_hash(GENESIS_HEADER)] = 0
                matched = max((positions[item] for item in locators if item in positions), default=0)
                start = min(matched, len(self.headers))
                selected = self.headers[start:]
                if stop_hash != bytes(32):
                    for idx, header in enumerate(selected):
                        if header_hash(header) == stop_hash:
                            selected = selected[:idx + 1]
                            break
                self._send(client, "headers", encode_headers(selected))
            elif command == "getdata":
                self.request_count += 1
                if self.request_count > MAX_P2P_REQUESTS:
                    raise FixtureError("P2P request-count cap exceeded")
                for inv_type, block_hash in parse_getdata(payload):
                    if inv_type not in (2, 0x40000002):
                        continue
                    block = self.blocks.get(block_hash)
                    if block is None or (self.once and block_hash in self.served):
                        continue
                    if len(self.served) >= MAX_BLOCKS - 1 and block_hash not in self.served:
                        raise FixtureError("provider body-count cap exceeded")
                    self.served.add(block_hash)
                    self._send(client, "block", block.raw)
            elif command == "getbspent":
                self.request_count += 1
                if self.request_count > MAX_P2P_REQUESTS:
                    raise FixtureError("P2P request-count cap exceeded")
                if len(payload) != 36:
                    raise FixtureError("bad getbspent request size")
                block_hash = payload[:32]
                cutoff = struct.unpack_from("<I", payload, 32)[0]
                expected_height = self.heights.get(block_hash)
                if expected_height is None or cutoff != expected_height:
                    raise FixtureError("getbspent does not match fixture block/cutoff")
                records = self.replies.get(block_hash, [])
                if any(record.coin.height >= cutoff for record in records):
                    raise FixtureError("helper would violate request cutoff")
                self.claim_count += len(records)
                self.spent_request_count += 1
                if self.spent_request_count > MAX_BLOCKS:
                    raise FixtureError("spent-request count cap exceeded")
                self._send(client, "bspent", encode_spent(block_hash, records))
            # Other standard handshake and sync messages are safely ignored.


def header_hash(header: bytes) -> bytes:
    return dsha(header)


GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c"
)


def write_config(path: Path, datadir: Path) -> None:
    # Tiny defaulted config: no seeds, no inbound listener, v1 localhost only.
    content = (
        "schema_version = 1\nnetwork = \"mainnet\"\n"
        f"data_dir = {json.dumps(str(datadir))}\n\n"
        "[net]\ndns_seeds = false\nv2transport = false\n"
        "[peers]\nmax_connections = 1\n"
        "[storage]\ndbcache_mb = 32\n"
    )
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def run_sync(binary: Path, config: Path, provider: LocalProvider, *, swift: bool, hints: Path | None, work: Path, data_dir: Path | None = None, bad: bool = False) -> tuple[int, str]:
    address = f"{provider.address[0]}:{provider.address[1]}"
    argv = [
        str(binary), "--config", str(config), "sync", "--blocks", str(TARGET_HEIGHT),
        "--timeout-secs", str(MAX_BAD_HINT_SECONDS if bad else MAX_SYNC_SECONDS),
        "--max-peers", "1", "--connect", address, "--v2transport=false",
    ]
    if swift:
        assert hints is not None
        argv.extend([
            "--swift-checkpoint-height", str(TARGET_HEIGHT),
            "--swift-checkpoint-hash", work.joinpath("checkpoint.hash").read_text().strip(),
            "--swift-hints", str(hints),
            "--swift-workspace", str(work / ("bad-workspace" if bad else "swift-workspace")),
            "--swift-data-dir", str(data_dir or work / ("bad-promoted" if bad else "swift-promoted")),
        ])
    log = work / ("sync-bad.log" if bad else ("sync-swift.log" if swift else "sync-ordinary.log"))
    with log.open("wb") as output:
        result = subprocess.run(
            argv,
            cwd=REPO,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=(MAX_BAD_HINT_SECONDS + 20 if bad else MAX_SYNC_SECONDS + 30),
            check=False,
        )
    text = log.read_text(encoding="utf-8", errors="replace")
    if not bad and result.returncode != 0:
        raise RuntimeError(f"CLI sync failed ({result.returncode}); see {log}\n{text[-4000:]}")
    if not bad and f"Done: connected {TARGET_HEIGHT} blocks" not in text:
        raise RuntimeError(f"CLI sync did not reach h{TARGET_HEIGHT}; see {log}\n{text[-4000:]}")
    if bad and f"Done: connected {TARGET_HEIGHT} blocks" in text:
        raise RuntimeError(f"mutated survivor hints unexpectedly reached target; see {log}")
    if bad and "full-coin audit or stump did not match" not in text:
        raise RuntimeError(f"bad survivor control did not report an audit mismatch; see {log}\n{text[-4000:]}")
    return result.returncode, text


def rpc_call(binary: Path, config: Path, rpc_addr: str, method: str, params: list | None = None) -> object:
    config_data_dir = read_data_dir(config)
    cookie_path = config_data_dir / "mainnet" / ".cookie"
    cookie = cookie_path.read_text(encoding="ascii").strip()
    auth = base64.b64encode(cookie.encode()).decode("ascii")
    host, port = rpc_addr.rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=2)
    try:
        return rpc_request(connection, auth, method, params or [])
    finally:
        connection.close()


def rpc_request(connection: http.client.HTTPConnection, auth: str, method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "1.0", "id": "swift-local", "method": method, "params": params}).encode()
    connection.request("POST", "/", body, {"Authorization": f"Basic {auth}", "Content-Type": "application/json"})
    response = connection.getresponse()
    payload = response.read(MAX_RPC_BODY + 1)
    if response.status != 200 or len(payload) > MAX_RPC_BODY:
        raise RuntimeError(f"RPC {method} failed with HTTP {response.status}")
    decoded = json.loads(payload)
    if decoded.get("error") is not None:
        raise RuntimeError(f"RPC {method} error: {decoded['error']}")
    return decoded.get("result")


def read_data_dir(config: Path) -> Path:
    for line in config.read_text(encoding="utf-8").splitlines():
        if line.startswith("data_dir = "):
            return Path(json.loads(line.split("=", 1)[1].strip()))
    raise RuntimeError("generated config has no datadir")


def parse_state_file(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) < 45 or len(raw) > 16 * 1024 * 1024:
        raise RuntimeError(f"state file length outside 45 B..16 MiB: {path}")
    version = struct.unpack_from("<I", raw, 4)[0]
    if raw[:4] != MAGIC or version not in (4, 5) or hashlib.sha256(hashlib.sha256(raw[40:]).digest()).digest() != raw[8:40]:
        raise RuntimeError(f"state file version/checksum invalid: {path}")
    payload = raw[40:]
    offset = 0

    def take_state(size: int) -> bytes:
        nonlocal offset
        end = offset + size
        if size < 0 or end > len(payload):
            raise RuntimeError("truncated state payload")
        data = payload[offset:end]
        offset = end
        return data

    def compact(limit: int) -> int:
        nonlocal offset
        value, offset = read_compact(payload, offset, limit)
        return value

    tip = take_state(32)
    height = struct.unpack("<I", take_state(4))[0]
    header_count = compact(MAX_BLOCKS + 10_000)
    take_state(header_count * 80)
    best_header = take_state(32)
    chain_count = compact(MAX_BLOCKS + 10_000)
    take_state(chain_count * 32)
    undo_count = compact(MAX_BLOCKS + 10_000)
    for _ in range(undo_count):
        undo_len = compact(16 * 1024 * 1024)
        take_state(undo_len)
    utxo_count = compact(MAX_HELPER_COINS)
    if utxo_count:
        raise RuntimeError("promoted external state unexpectedly embeds inline UTXOs")
    failed_count = compact(MAX_BLOCKS + 10_000)
    take_state(failed_count * 32)
    tx_meta_count = compact(MAX_BLOCKS + 10_000)
    take_state(tx_meta_count * 44)
    snapshot_base = struct.unpack("<I", take_state(4))[0]
    flags = take_state(1)[0]
    floor = struct.unpack("<I", take_state(4))[0] if version >= 5 else 0
    if offset != len(payload):
        raise RuntimeError("state payload has trailing bytes")
    return {
        "version": version,
        "tip": tip,
        "height": height,
        "best_header": best_header,
        "headers": header_count,
        "chain": chain_count,
        "snapshot_base": snapshot_base,
        "flags": flags,
        "floor": floor,
    }


def contains_block(dir_path: Path, block: Block) -> bool:
    found = False
    for path in dir_path.glob("blk*.dat"):
        if path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError(f"fixture block file exceeds local scan cap: {path}")
        if block.raw in path.read_bytes():
            found = True
            break
    return found


def clone_bounded_header_seed(source: Path, destination: Path) -> None:
    total_bytes = 0
    file_count = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("header seed unexpectedly contains a symlink")
        if path.is_file():
            file_count += 1
            total_bytes += path.stat().st_size
            if file_count > 100 or total_bytes > 32 * 1024 * 1024:
                raise RuntimeError("header-only source exceeds clone bounds")
    shutil.copytree(source, destination)


def start_rpc_node(binary: Path, config: Path, provider: LocalProvider | None, port: int, work: Path, label: str) -> tuple[subprocess.Popen, BinaryIO, Path]:
    rpc_address = f"127.0.0.1:{port}"
    log_path = work / f"run-{label}.log"
    log = log_path.open("wb")
    argv = [str(binary), "--config", str(config), "run", "--maxconnections", "1", "--v2transport=false", "--assumevalid", "0", "--rpc", rpc_address]
    if provider is not None:
        argv.extend(["--connect", f"127.0.0.1:{provider.address[1]}"])
    process = subprocess.Popen(argv, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
    return process, log, log_path


def seed_header_datadir(binary: Path, config: Path, blocks: list[Block], work: Path) -> Path:
    """Validate fixture headers through the ordinary RPC path, without blocks."""
    port = reserve_port()
    process, log, log_path = start_rpc_node(binary, config, None, port, work, "header-seed")
    try:
        wait_for_rpc(binary, config, port, process)
        config_data_dir = read_data_dir(config)
        cookie = (config_data_dir / "mainnet" / ".cookie").read_text(encoding="ascii").strip()
        auth = base64.b64encode(cookie.encode()).decode("ascii")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        deadline = time.monotonic() + MAX_HEADER_SEED_SECONDS
        try:
            for height, block in enumerate(blocks[1:], start=1):
                if time.monotonic() >= deadline:
                    raise TimeoutError("header seeding exceeded its 45-second bound")
                if height > MAX_BLOCKS - 1:
                    raise FixtureError("header seed exceeded the fixture height bound")
                result = rpc_request(connection, auth, "submitheader", [block.header.hex()])
                if result is not None:
                    raise RuntimeError(f"submitheader h{height} returned unexpected result {result!r}")
        finally:
            connection.close()
    finally:
        stop_rpc_node(process, log, log_path)
    seeded = config_data_dir / "mainnet"
    state = seeded / "state.dat"
    if not state.is_file() or state.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError("header-only source did not persist a bounded state.dat")
    return seeded


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_rpc(binary: Path, config: Path, port: int, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + MAX_RPC_WAIT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"node exited before RPC was ready ({process.returncode})")
        try:
            rpc_call(binary, config, f"127.0.0.1:{port}", "getvalidationreport")
            return
        except (OSError, RuntimeError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(0.2)
    raise TimeoutError(f"RPC did not become ready within {MAX_RPC_WAIT_SECONDS}s: {last_error}")


def poll_full_report(binary: Path, config: Path, port: int, process: subprocess.Popen) -> dict:
    deadline = time.monotonic() + MAX_RPC_WAIT_SECONDS
    last = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"node exited while syncing ({process.returncode})")
        last = rpc_call(binary, config, f"127.0.0.1:{port}", "getvalidationreport")
        if last.get("connected_height") == TARGET_HEIGHT:
            policy = last.get("validation_policy", {})
            if policy.get("assume_valid_checkpoint") is not None or not policy.get("historical_scripts_required"):
                raise RuntimeError(f"node did not report strict historical script policy: {last}")
            return last
        time.sleep(0.2)
    raise TimeoutError(f"node did not fully connect h{TARGET_HEIGHT}; last report={last}")


def stop_rpc_node(process: subprocess.Popen, log: BinaryIO, log_path: Path) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            raise RuntimeError(f"node ignored SIGINT; see {log_path}")
    log.close()
    if process.returncode not in (0, -signal.SIGINT, 130):
        raise RuntimeError(f"node shutdown exited {process.returncode}; see {log_path}")


def rpc_snapshot(binary: Path, config: Path, work: Path, label: str, provider: LocalProvider) -> dict:
    port = reserve_port()
    process, log, log_path = start_rpc_node(binary, config, provider, port, work, label)
    try:
        wait_for_rpc(binary, config, port, process)
        report = poll_full_report(binary, config, port, process)
        stats = rpc_call(binary, config, f"127.0.0.1:{port}", "gettxoutsetinfo", ["muhash"])
        if not isinstance(stats, dict) or not isinstance(report, dict):
            raise RuntimeError("RPC state report did not return objects")
        if stats.get("height") != TARGET_HEIGHT:
            raise RuntimeError(f"UTXO stats are at wrong height: {stats}")
        if stats.get("bestblock") != work.joinpath("checkpoint.hash").read_text().strip():
            raise RuntimeError(f"UTXO stats have wrong best block: {stats}")
        if not isinstance(stats.get("txouts"), int) or not isinstance(stats.get("muhash"), str):
            raise RuntimeError(f"UTXO stats lack count/MuHash: {stats}")
        return {"height": stats["height"], "bestblock": stats["bestblock"], "txouts": stats["txouts"], "muhash": stats["muhash"], "validation_policy": report["validation_policy"], "coverage": report["coverage"]["state"]}
    finally:
        stop_rpc_node(process, log, log_path)


def run_harness(binary: Path, work: Path) -> dict:
    blocks = load_blocks(FIXTURE)
    replies, survivor_rows, total_txs, total_claims = helper_dataset(blocks)
    checkpoint_hash = blocks[-1].block_hash[::-1].hex()
    (work / "checkpoint.hash").write_text(checkpoint_hash + "\n", encoding="ascii")
    os.chmod(work / "checkpoint.hash", 0o600)
    valid_hints = work / "mainnet-500.hints"
    valid_hints.write_bytes(hints_file(survivor_rows))
    os.chmod(valid_hints, 0o600)
    bad_hints = work / "mainnet-500-bad-survivor.hints"
    bad_hints.write_bytes(make_bad_hints(survivor_rows))
    os.chmod(bad_hints, 0o600)

    dirs = {}
    for name in ("header-seed", "swift", "oracle", "bad"):
        root = work / name
        root.mkdir(mode=0o700)
        config = work / f"{name}.toml"
        write_config(config, root)
        dirs[name] = (root, config)

    # The first 500 mainnet headers are below today's minimum-chain-work
    # anti-DoS threshold. Submit them through the ordinary, strict header RPC
    # before Swift sync; this validates PoW/context without changing Params.
    seed_dir = seed_header_datadir(binary, dirs["header-seed"][1], blocks, work)
    seed_state = parse_state_file(seed_dir / "state.dat")
    if (seed_state["version"] != 4 or seed_state["height"] != 0 or seed_state["floor"] != 0
            or seed_state["chain"] != 1
            or seed_state["headers"] < TARGET_HEIGHT
            or seed_state["best_header"] != blocks[-1].block_hash):
        raise RuntimeError(f"header-only seed did not persist the expected header tip: {seed_state}")

    # Clone only this harness-owned header-only source. The CLI Swift caller
    # uses workspace/header-source; the ordinary oracle opens its own clone.
    swift_workspace = work / "swift-workspace"
    swift_workspace.mkdir(mode=0o700)
    clone_bounded_header_seed(seed_dir, swift_workspace / "header-source")
    oracle_datadir = dirs["oracle"][0] / "mainnet"
    clone_bounded_header_seed(seed_dir, oracle_datadir)
    bad_workspace = work / "bad-workspace"
    bad_workspace.mkdir(mode=0o700)
    clone_bounded_header_seed(seed_dir, bad_workspace / "header-source")
    swift_datadir = dirs["swift"][0] / "mainnet"
    swift_datadir.mkdir(mode=0o700)
    bad_datadir = dirs["bad"][0] / "mainnet"
    bad_datadir.mkdir(mode=0o700)

    # First: real CLI Swift path with self-derived, untrusted hints/claims.
    provider = LocalProvider(blocks, replies, feature=True, once=False)
    provider.start()
    try:
        run_sync(binary, dirs["swift"][1], provider, swift=True, hints=valid_hints, work=work, data_dir=swift_datadir)
        if provider.claim_count != total_claims or provider.claim_count != 10:
            raise RuntimeError(f"provider sent {provider.claim_count} coins, expected 10 fixture spends")
        positive_claims = provider.claim_count
    finally:
        provider.close()

    swift_state = parse_state_file(swift_datadir / "state.dat")
    if (swift_state["version"] != 5 or swift_state["height"] != TARGET_HEIGHT
            or swift_state["floor"] != TARGET_HEIGHT - 288 or swift_state["snapshot_base"] != 0
            or not (swift_state["flags"] & 1) or (swift_state["flags"] & 2)):
        raise RuntimeError(f"Swift sync did not publish fully checked pruned-history state: {swift_state}")
    workspace_path = swift_workspace / "swift-live.redb"
    if not workspace_path.is_file():
        raise RuntimeError("Swift audit workspace is missing its durable live index")
    if contains_block(swift_datadir, blocks[1]):
        raise RuntimeError("Swift promotion unexpectedly retained pre-floor h1 body")
    swift_log = (work / "sync-swift.log").read_text(encoding="utf-8", errors="replace")
    if "swift-ibd: provisional full-check enabled" not in swift_log or "falling back to ordinary full validation" in swift_log:
        raise RuntimeError("positive sync did not prove an active, non-fallback Swift attempt")

    # Second: independent ordinary genesis-to-h500 validation, with the
    # assumevalid shortcut explicitly disabled and RPC stats read after sync.
    provider = LocalProvider(blocks, replies, feature=False, once=False)
    provider.start()
    try:
        oracle = rpc_snapshot(binary, dirs["oracle"][1], work, "oracle", provider)
    finally:
        provider.close()
    if not contains_block(oracle_datadir, blocks[1]):
        raise RuntimeError("ordinary full-validation oracle did not retain its h1 body")

    # Reopen the atomically promoted Swift datadir under the same strict policy.
    provider = LocalProvider(blocks, replies, feature=False, once=False)
    provider.start()
    try:
        swift = rpc_snapshot(binary, dirs["swift"][1], work, "swift-promoted", provider)
    finally:
        provider.close()
    comparable = ("height", "bestblock", "txouts", "muhash")
    if any(swift[key] != oracle[key] for key in comparable):
        raise RuntimeError(f"Swift promoted state differs from ordinary oracle: {swift} != {oracle}")
    for label, result in (("swift", swift), ("oracle", oracle)):
        policy = result["validation_policy"]
        if policy.get("assume_valid_checkpoint") is not None or policy.get("historical_scripts_required") is not True:
            raise RuntimeError(f"{label} did not report full historical script validation: {policy}")

    # Negative control: a validly encoded but false survivor hint must fail the
    # checkpoint audit. Each raw block is served once, so fallback cannot
    # silently finish by replaying ordinary genesis sync in this control.
    provider = LocalProvider(blocks, replies, feature=True, once=True)
    provider.start()
    try:
        negative_exit, negative_log = run_sync(binary, dirs["bad"][1], provider, swift=True, hints=bad_hints, work=work, data_dir=bad_datadir, bad=True)
        negative_claims = provider.claim_count
    finally:
        provider.close()
    if negative_claims != total_claims:
        raise RuntimeError(f"negative-control provider sent {negative_claims} claims, expected {total_claims}")
    bad_state_path = bad_datadir / "state.dat"
    if bad_state_path.exists():
        bad_state = parse_state_file(bad_state_path)
        if bad_state["version"] == 5 and bad_state["height"] == TARGET_HEIGHT and bad_state["floor"] == TARGET_HEIGHT - 288:
            raise RuntimeError("bad survivor hints created a promoted Swift checkpoint")

    return {
        "experiment": "self_hosted_mainnet_swift_cli",
        "binary_sha256": file_sha256(binary),
        "fixture": str(FIXTURE.relative_to(REPO)),
        "fixture_bytes": FIXTURE_BYTES,
        "fixture_sha256": FIXTURE_SHA256,
        "blocks": len(blocks),
        "transactions_after_genesis": total_txs,
        "historical_spent_claims": total_claims,
        "provider_spent_coin_records": positive_claims,
        "checkpoint_height": TARGET_HEIGHT,
        "checkpoint_hash": checkpoint_hash,
        "header_seed": "500 production-mainnet headers accepted with ordinary submitheader RPC before sync",
        "swift_and_ordinary_match": True,
        "swift": swift,
        "ordinary_full_validation_oracle": oracle,
        "swift_promotion_evidence": {
            "state_version": swift_state["version"],
            "fully_validated_pruned_through": swift_state["floor"],
            "snapshot_base": swift_state["snapshot_base"],
            "externalized_coins": bool(swift_state["flags"] & 1),
            "durable_workspace_live_index": workspace_path.is_file(),
            "provider_claim_records": positive_claims,
            "pre_floor_h1_body_absent": True,
            "ordinary_oracle_h1_body_present": True,
            "fallback_log_absent": True,
        },
        "negative_control": {
            "mutated_survivor_hint_promoted": False,
            "audit_mismatch_reported": "full-coin audit or stump did not match" in negative_log,
            "exit_code": negative_exit,
            "spent_coin_claim_records": negative_claims,
            "swift_checkpoint_published": False,
        },
        "provider": "loopback v1 / BIP434 feature / Draft BIP455 claims",
        "operator_datadir_touched": False,
        "workdir": str(work),
        "workdir_retained": True,
        "limitation": "historical mainnet h0..500 only; no modern witness coverage, public helper availability, or IBD speed result",
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def installed_receipt_hash(binary: Path) -> str | None:
    receipt = binary.parent / "validated.json"
    if not receipt.is_file():
        return None
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read installed CLI validation receipt {receipt}: {error}")
    value = data.get("binary_sha256")
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise SystemExit(f"installed CLI receipt has no valid binary_sha256: {receipt}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path.home() / ".local/opt/avila-node/avila-node")
    parser.add_argument("--workdir", type=Path, help="new or empty private directory for isolated datadirs and logs")
    parser.add_argument(
        "--allow-other-binary",
        action="store_true",
        help="explicitly allow a candidate without a matching adjacent validated.json receipt",
    )
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"CLI binary is not executable: {binary}")
    actual_cli_hash = file_sha256(binary)
    expected_cli_hash = installed_receipt_hash(binary)
    if not args.allow_other_binary and (
        expected_cli_hash is None or actual_cli_hash != expected_cli_hash
    ):
        expected = expected_cli_hash or "no adjacent validated.json receipt"
        raise SystemExit(
            f"CLI is not the validated installed artifact: got {actual_cli_hash}; "
            f"expected {expected} (or pass --allow-other-binary for a candidate)"
        )
    if args.workdir:
        work = args.workdir.expanduser().resolve()
        if work.exists() and any(work.iterdir()):
            raise SystemExit(f"workdir must be absent or empty: {work}")
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(work, 0o700)
    else:
        work = Path(tempfile.mkdtemp(prefix="avila-swift-mainnet-"))
        os.chmod(work, 0o700)
    try:
        result = run_harness(binary, work)
        result_path = work / "result.json"
        result["result_file"] = str(result_path)
        result_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(result_path, 0o600)
        print(json.dumps(result, sort_keys=True, indent=2))
    except Exception as error:
        print(f"swift local mainnet harness failed: {error}; artifacts: {work}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
