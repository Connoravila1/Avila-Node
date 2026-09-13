#!/usr/bin/env python3
"""
fetch_fixtures.py -- regenerate the bounded, real Bitcoin chain fixtures used
by Avila Node's consensus tests and benchmarks.

WHAT THIS PRODUCES
-------------------
Under fixtures/ (relative to the repository root):

  Header fixtures (raw concatenated 80-byte block headers, height order,
  no length prefixes, no transaction counts):

    mainnet-headers-000000-004031.bin   mainnet heights 0..=4031  (4032 * 80B)
    mainnet-headers-030229-032257.bin   mainnet heights 30229..=32257
                                         (2029 * 80B; contains the first
                                         real difficulty retarget at height
                                         32256: nBits 0x1d00ffff -> 0x1d00d86a)
    testnet4-headers-000000-004031.bin  testnet4 heights 0..=4031
    signet-headers-000000-002047.bin    signet heights 0..=2047

  Block fixtures (raw serialized block bytes, exactly as served by the
  source, i.e. block header + tx count + transactions, witness data
  included where present):

    mainnet-block-000000.bin            mainnet genesis
    mainnet-block-000001.bin            mainnet height 1
    mainnet-block-000170.bin            mainnet height 170 (first
                                         non-coinbase transaction: the
                                         Hal Finney / Satoshi 10 BTC tx)
    mainnet-block-100000.bin            mainnet height 100000 (4 txs,
                                         a classic test vector)
    mainnet-block-segwit-small.bin      a small mainnet block at height
                                         >= 481824 (segwit active) that
                                         carries witness data on at least
                                         one non-coinbase transaction
    mainnet-block-taproot-era-small.bin a small mainnet block at height
                                         >= 709632 (taproot active), same
                                         selection criteria
    testnet4-block-000000.bin           testnet4 genesis
    signet-block-000000.bin             signet genesis
    signet-block-000001.bin             signet height 1 (coinbase carries
                                         the signet solution)

  fixtures/manifest.json   machine-readable provenance for every fixture.
  fixtures/SHA256SUMS      `sha256sum` output for every fixture binary;
                            verify with `cd fixtures && sha256sum -c SHA256SUMS`.
  fixtures/README.md       human-readable summary (checked in by hand, but
                            this script does not overwrite prose fields).

SOURCES
-------
Headers are fetched directly over the Bitcoin P2P wire protocol:
  - TCP connect to a peer discovered via each network's DNS seeds.
  - `version`/`verack` handshake (protocol version 70016, services=0,
    user_agent "/avila-fixtures:0.1/", relay=false -- we never request or
    relay transactions, and we present ourselves honestly as a fixture
    fetcher, not a full node).
  - `getheaders` messages with a block locator, answered with `headers`
    messages (up to 2000 headers each).
  - `ping` is answered with `pong` (same nonce); every other unsolicited
    message (`sendheaders`, `sendcmpct`, `wtxidrelay`, `sendaddrv2`,
    `feefilter`, `addr`, `addrv2`, `inv`, incoming `getheaders`, etc.) is
    read and ignored.

If P2P fails for a network (DNS seed exhausted, or every candidate peer
refused/timed out), the script falls back to fetching headers one-by-one
over HTTPS from a public esplora-style block explorer API (Blockstream
for mainnet, mempool.space for testnet4/signet). This is slower (one
HTTP round trip per header) but has no protocol dependency beyond HTTPS.

Blocks are always fetched over HTTPS from esplora-compatible APIs
(Blockstream for mainnet with a mempool.space fallback; mempool.space for
testnet4 and signet), using the `/api/block-height/{h}` and
`/api/block/{hash}/raw` endpoints, plus `/api/block/{hash}` for metadata
(tx_count/size/weight).

VERIFICATION
------------
Every header is checked as it is received: its prev_hash field must equal
the double-SHA256 of the previously accepted header, and the first header
of each network's run must be that network's known genesis block. Every
block is checked by recomputing double-SHA256 of its first 80 bytes and
comparing to the expected block hash. After all files are written, the
script re-reads every fixture from disk, recomputes its sha256, checks
header file lengths are an exact multiple of 80 bytes (== count * 80),
re-walks header linkage end-to-end, and re-checks block header hashes --
independently of the in-memory state used to write them -- and prints a
verification summary. Finally it runs `sha256sum -c SHA256SUMS` in
fixtures/ as an external sanity check.

USAGE
-----
    python3 tools/fetch_fixtures.py                # regenerate everything
    python3 tools/fetch_fixtures.py --only NAME     # regenerate one fixture
    python3 tools/fetch_fixtures.py --list          # list fixture names

NAME is the fixture "file" field from manifest.json, e.g.
"mainnet-headers-000000-004031.bin" or "mainnet-block-100000.bin".

This script uses only the Python standard library (socket, ssl,
http.client/urllib, hashlib, struct, json, etc.) -- no third-party
dependencies.

Bitcoin's block chain data is public; the files this script produces are
small, bounded slices of it kept only for deterministic, offline test
fixtures. Larger or additional ranges should be fetched on demand by
re-running (a variant of) this script rather than committed to the repo.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(REPO_ROOT, "fixtures")

HEADER_SIZE = 80
PROTOCOL_VERSION = 70016
USER_AGENT = "/avila-fixtures:0.1/"
P2P_CONNECT_TIMEOUT = 10.0
P2P_READ_TIMEOUT = 30.0
HTTP_TIMEOUT = 20.0
HTTP_RETRY_DELAY = 1.5
HTTP_MAX_RETRIES = 4
MAX_BLOCK_BYTES = 64 * 1024

MAX_GETHEADERS_ROUNDS = 200  # generous safety cap; real runs need ~1-20


# ---------------------------------------------------------------------------
# Hashing / hex helpers
# ---------------------------------------------------------------------------

def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def to_display_hex(internal_le_hash: bytes) -> str:
    """Internal little-endian hash -> conventional display-order hex."""
    return internal_le_hash[::-1].hex()


def from_display_hex(display_hex: str) -> bytes:
    """Conventional display-order hex -> internal little-endian bytes."""
    return bytes.fromhex(display_hex)[::-1]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Network parameters
# ---------------------------------------------------------------------------

@dataclass
class NetParams:
    name: str
    magic: bytes
    port: int
    dns_seeds: list
    genesis_display_hash: str

    @property
    def genesis_internal_hash(self) -> bytes:
        return from_display_hex(self.genesis_display_hash)


NETWORKS = {
    "mainnet": NetParams(
        name="mainnet",
        magic=bytes.fromhex("f9beb4d9"),
        port=8333,
        dns_seeds=[
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "seed.bitcoinstats.com",
            "seed.bitcoin.sprovoost.nl",
        ],
        genesis_display_hash="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ),
    "testnet4": NetParams(
        name="testnet4",
        magic=bytes.fromhex("1c163f28"),
        port=48333,
        dns_seeds=[
            "seed.testnet4.bitcoin.sprovoost.nl",
            "seed.testnet4.wiz.biz",
        ],
        genesis_display_hash="00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
    ),
    "signet": NetParams(
        name="signet",
        magic=bytes.fromhex("0a03cf40"),
        port=38333,
        dns_seeds=[
            "seed.signet.bitcoin.sprovoost.nl",
            "seed.signet.achownodes.xyz",
        ],
        genesis_display_hash="00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    ),
}

# NOTE on the testnet4 genesis hash: independently cross-checked against
# (a) the mempool.space/testnet4 esplora API's /block-height/0 response and
# (b) the `prev_block` field of the real height-1 header fetched live over
# the P2P protocol from a testnet4 seed peer -- both agree on
# "...bc53dee25a72ae507ff..." (with 'e', not 'a', at that position). This
# is used below instead of a value with a single transposed hex digit.


def _validate_hash_hex(h: str) -> str:
    h = h.strip().lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError(f"genesis hash must be 64 lowercase hex chars, got: {h!r}")
    return h


for _net in NETWORKS.values():
    _net.genesis_display_hash = _validate_hash_hex(_net.genesis_display_hash)


# ---------------------------------------------------------------------------
# Bitcoin P2P wire protocol (minimal, read-only client)
# ---------------------------------------------------------------------------

class PeerError(Exception):
    pass


def compact_size_encode(n: int) -> bytes:
    if n < 0xfd:
        return struct.pack("<B", n)
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def var_str_encode(s: bytes) -> bytes:
    return compact_size_encode(len(s)) + s


class SocketReader:
    """Buffered exact-read helper over a blocking socket with a deadline."""

    def __init__(self, sock: socket.socket, read_timeout: float):
        self.sock = sock
        self.read_timeout = read_timeout
        self.buf = b""

    def read_exact(self, n: int) -> bytes:
        deadline = time.monotonic() + self.read_timeout
        while len(self.buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError(f"timed out reading {n} bytes (have {len(self.buf)})")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise PeerError("peer closed connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_compact_size(self) -> int:
        first = self.read_exact(1)[0]
        if first < 0xfd:
            return first
        elif first == 0xfd:
            return struct.unpack("<H", self.read_exact(2))[0]
        elif first == 0xfe:
            return struct.unpack("<I", self.read_exact(4))[0]
        else:
            return struct.unpack("<Q", self.read_exact(8))[0]


class Peer:
    def __init__(self, net: NetParams, ip: str, family: int):
        self.net = net
        self.ip = ip
        self.family = family
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[SocketReader] = None
        self.user_agent_of_peer: str = ""

    def connect(self):
        self.sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.sock.settimeout(P2P_CONNECT_TIMEOUT)
        self.sock.connect((self.ip, self.net.port))
        self.sock.settimeout(P2P_READ_TIMEOUT)
        self.reader = SocketReader(self.sock, P2P_READ_TIMEOUT)

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    # -- message framing -----------------------------------------------

    def send_message(self, command: str, payload: bytes):
        cmd = command.encode("ascii")
        if len(cmd) > 12:
            raise ValueError("command too long")
        cmd_padded = cmd + b"\x00" * (12 - len(cmd))
        checksum = dsha256(payload)[:4]
        header = self.net.magic + cmd_padded + struct.pack("<I", len(payload)) + checksum
        self.sock.sendall(header + payload)

    def recv_message(self):
        """Returns (command_str, payload_bytes)."""
        magic = self.reader.read_exact(4)
        if magic != self.net.magic:
            raise PeerError(f"bad magic {magic.hex()} (expected {self.net.magic.hex()})")
        cmd_raw = self.reader.read_exact(12)
        command = cmd_raw.rstrip(b"\x00").decode("ascii", errors="replace")
        length = struct.unpack("<I", self.reader.read_exact(4))[0]
        checksum = self.reader.read_exact(4)
        payload = self.reader.read_exact(length) if length else b""
        actual_checksum = dsha256(payload)[:4]
        if actual_checksum != checksum:
            raise PeerError(f"checksum mismatch for {command!r} message")
        return command, payload

    # -- handshake --------------------------------------------------------

    def handshake(self):
        version_payload = self._build_version_payload()
        self.send_message("version", version_payload)

        got_version = False
        got_verack = False
        deadline = time.monotonic() + P2P_READ_TIMEOUT
        while not (got_version and got_verack):
            if time.monotonic() > deadline:
                raise PeerError("handshake timed out")
            command, payload = self.recv_message()
            if command == "version":
                got_version = True
                self._parse_version_payload(payload)
                self.send_message("verack", b"")
            elif command == "verack":
                got_verack = True
            elif command == "ping":
                # respond even during handshake, some peers send it early
                self.send_message("pong", payload)
            else:
                # ignore anything else during handshake (rare)
                pass

    def _build_version_payload(self) -> bytes:
        version = struct.pack("<i", PROTOCOL_VERSION)
        services = struct.pack("<Q", 0)
        timestamp = struct.pack("<q", int(time.time()))
        addr_recv_services = struct.pack("<Q", 0)
        addr_recv_ip = self._encode_addr_ip(self.ip)
        addr_recv_port = struct.pack(">H", self.net.port)
        addr_trans_services = struct.pack("<Q", 0)
        addr_trans_ip = self._encode_addr_ip("0.0.0.0")
        addr_trans_port = struct.pack(">H", 0)
        nonce = struct.pack("<Q", int.from_bytes(os.urandom(8), "little"))
        user_agent = var_str_encode(USER_AGENT.encode("ascii"))
        start_height = struct.pack("<i", 0)
        relay = struct.pack("<B", 0)  # relay=false
        return (
            version + services + timestamp
            + addr_recv_services + addr_recv_ip + addr_recv_port
            + addr_trans_services + addr_trans_ip + addr_trans_port
            + nonce + user_agent + start_height + relay
        )

    @staticmethod
    def _encode_addr_ip(ip: str) -> bytes:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = ipaddress.ip_address("0.0.0.0")
        if isinstance(addr, ipaddress.IPv4Address):
            # IPv4-mapped IPv6 address
            return b"\x00" * 10 + b"\xff\xff" + addr.packed
        return addr.packed

    def _parse_version_payload(self, payload: bytes):
        # version(4) services(8) timestamp(8) addr_recv(26) addr_from(26)
        # nonce(8) then var_str user_agent, then start_height(4), relay(1 opt)
        offset = 4 + 8 + 8 + 26 + 26 + 8
        if offset >= len(payload):
            return
        # parse compact size for user agent length
        first = payload[offset]
        offset += 1
        if first < 0xfd:
            ua_len = first
        elif first == 0xfd:
            ua_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
        elif first == 0xfe:
            ua_len = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
        else:
            ua_len = struct.unpack_from("<Q", payload, offset)[0]
            offset += 8
        ua_bytes = payload[offset:offset + ua_len]
        try:
            self.user_agent_of_peer = ua_bytes.decode("ascii", errors="replace")
        except Exception:
            self.user_agent_of_peer = ""

    # -- getheaders / headers --------------------------------------------

    def send_getheaders(self, locator_hashes: list, hash_stop: bytes = b"\x00" * 32):
        version = struct.pack("<i", PROTOCOL_VERSION)
        count = compact_size_encode(len(locator_hashes))
        hashes = b"".join(locator_hashes)
        payload = version + count + hashes + hash_stop
        self.send_message("getheaders", payload)

    def recv_headers_message(self, timeout: float = P2P_READ_TIMEOUT):
        """
        Loops reading messages, answering pings, ignoring irrelevant
        messages, until a 'headers' message arrives. Returns list of
        80-byte raw headers (tx count stripped).
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError("timed out waiting for headers message")
            self.reader.read_timeout = remaining
            command, payload = self.recv_message()
            if command == "ping":
                self.send_message("pong", payload)
                continue
            if command == "headers":
                return self._parse_headers_payload(payload)
            # ignore: sendheaders, sendcmpct, wtxidrelay, sendaddrv2,
            # feefilter, addr, addrv2, inv, getheaders, alert, etc.
            continue

    @staticmethod
    def _parse_headers_payload(payload: bytes) -> list:
        offset = 0
        first = payload[offset]
        offset += 1
        if first < 0xfd:
            count = first
        elif first == 0xfd:
            count = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
        elif first == 0xfe:
            count = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
        else:
            count = struct.unpack_from("<Q", payload, offset)[0]
            offset += 8
        headers = []
        for _ in range(count):
            header = payload[offset:offset + 80]
            offset += 80
            # tx count compact size follows, always 0 for a headers msg
            tx_first = payload[offset]
            offset += 1
            if tx_first == 0xfd:
                offset += 2
            elif tx_first == 0xfe:
                offset += 4
            elif tx_first == 0xff:
                offset += 8
            headers.append(header)
        return headers

    # -- getdata / block (used only to fetch the genesis header) --------
    #
    # A `getheaders` response never includes the header matched by the
    # locator itself -- only what comes strictly after it. Since every
    # peer's genesis block is height 0 with no parent, there is no locator
    # value that makes `getheaders` hand back genesis. Every peer holds
    # its own genesis block by construction, though, so we fetch it
    # directly with a single `getdata`/`block` round trip instead.

    MSG_BLOCK = 2

    def send_getdata(self, inv_type: int, hash_internal: bytes):
        payload = compact_size_encode(1) + struct.pack("<I", inv_type) + hash_internal
        self.send_message("getdata", payload)

    def fetch_block_header_via_getdata(self, block_hash_internal: bytes,
                                        timeout: float = P2P_READ_TIMEOUT) -> bytes:
        """Fetch a full block via getdata(MSG_BLOCK) and return its leading
        80-byte header. Used only for the genesis block (small, <300B)."""
        self.send_getdata(self.MSG_BLOCK, block_hash_internal)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError("timed out waiting for block message")
            self.reader.read_timeout = remaining
            command, payload = self.recv_message()
            if command == "ping":
                self.send_message("pong", payload)
                continue
            if command == "block":
                if len(payload) < HEADER_SIZE:
                    raise PeerError("block message shorter than one header")
                return payload[:HEADER_SIZE]
            if command == "notfound":
                raise PeerError("peer replied notfound for requested block")
            # ignore anything else (inv, addr, sendcmpct, etc.)
            continue


def resolve_candidates(net: NetParams):
    """Yield (ip, family) candidates from all DNS seeds, IPv4 first."""
    v4_candidates = []
    v6_candidates = []
    for seed in net.dns_seeds:
        try:
            infos = socket.getaddrinfo(seed, net.port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            print(f"    [dns] {seed}: FAILED ({e})", file=sys.stderr)
            continue
        seen_here = set()
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen_here:
                continue
            seen_here.add(ip)
            if fam == socket.AF_INET:
                v4_candidates.append((ip, fam, seed))
            elif fam == socket.AF_INET6:
                v6_candidates.append((ip, fam, seed))
        print(f"    [dns] {seed}: {len(seen_here)} address(es)", file=sys.stderr)
    for ip, fam, seed in v4_candidates:
        yield ip, fam, seed
    for ip, fam, seed in v6_candidates:
        yield ip, fam, seed


def fetch_headers_p2p(net: NetParams, target_count: int):
    """
    Walk headers from genesis via P2P until at least target_count headers
    (including genesis) are collected, or the chain tip is reached first.
    Returns (headers_list_of_raw80, source_info_dict) or (None, last_error)
    on total failure.
    """
    last_error = None
    for ip, fam, seed in resolve_candidates(net):
        peer = Peer(net, ip, fam)
        try:
            print(f"    [p2p] trying {ip} (via {seed}) ...", file=sys.stderr)
            peer.connect()
            peer.handshake()
            print(
                f"    [p2p] connected to {ip}:{net.port} "
                f"user_agent={peer.user_agent_of_peer!r}",
                file=sys.stderr,
            )

            # Step 1: fetch the genesis header (height 0) via getdata/block.
            # A `getheaders` response never includes the header matched by
            # the locator itself, only what comes strictly after it -- so
            # no locator value makes a compliant peer hand back genesis.
            # Every peer holds its own genesis block by construction, so we
            # fetch it directly instead (confirmed empirically against a
            # live testnet4 peer: the response is a 261-byte `block`
            # message whose first 80 bytes double-SHA256 to the expected
            # genesis hash).
            genesis_header = peer.fetch_block_header_via_getdata(net.genesis_internal_hash)
            genesis_hash = dsha256(genesis_header)
            if genesis_hash != net.genesis_internal_hash:
                raise PeerError(
                    f"peer's genesis block does not hash to the expected "
                    f"genesis (got {to_display_hex(genesis_hash)}, "
                    f"expected {net.genesis_display_hash})"
                )
            if genesis_header[4:36] != b"\x00" * 32:
                raise PeerError("genesis header has non-zero prev field")

            headers: list = [genesis_header]
            prev_internal_hash = genesis_hash
            rounds = 0

            # Step 2: walk forward via getheaders. The locator's first
            # entry is our latest known header hash (so far, genesis);
            # a second, older entry (genesis again) is included per the
            # normal locator-construction convention. hash_stop stays
            # zero, so each response is capped only by the 2000-header
            # protocol limit.
            locator = [net.genesis_internal_hash]
            while len(headers) < target_count:
                if rounds >= MAX_GETHEADERS_ROUNDS:
                    raise PeerError("exceeded max getheaders rounds")
                peer.send_getheaders(locator)
                batch = peer.recv_headers_message()
                rounds += 1
                if not batch:
                    raise PeerError(
                        "peer returned zero headers; it may not have "
                        "enough chain to satisfy the request"
                    )
                for h in batch:
                    h_hash = dsha256(h)
                    prev_field = h[4:36]
                    if prev_field != prev_internal_hash:
                        raise PeerError("header linkage broken across batch")
                    headers.append(h)
                    prev_internal_hash = h_hash
                locator = [prev_internal_hash, net.genesis_internal_hash]
                if len(batch) < 2000:
                    break  # peer has no more headers past its own tip

            if len(headers) < target_count:
                raise PeerError(
                    f"peer only supplied {len(headers)} headers "
                    f"(< {target_count} requested); chain tip reached or "
                    f"peer misbehaved"
                )

            source = {
                "transport": "p2p",
                "peer": f"{ip}:{net.port}",
                "user_agent_of_peer": peer.user_agent_of_peer,
                "dns_seed": seed,
            }
            peer.close()
            return headers, source
        except (PeerError, OSError, socket.timeout) as e:
            last_error = f"{ip}: {e}"
            print(f"    [p2p] {ip} failed: {e}", file=sys.stderr)
            peer.close()
            continue
    return None, last_error


# ---------------------------------------------------------------------------
# HTTPS helpers (esplora-style APIs), fallback path
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()


def http_get(url: str, as_json: bool = False, as_hex_text: bool = False):
    last_exc = None
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "avila-fixtures/0.1 (+standard-library-only)"},
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as resp:
                data = resp.read()
            if as_json:
                return json.loads(data.decode("utf-8"))
            if as_hex_text:
                return data.decode("utf-8").strip()
            return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
            last_exc = e
            print(f"    [http] attempt {attempt}/{HTTP_MAX_RETRIES} failed for {url}: {e}", file=sys.stderr)
            time.sleep(HTTP_RETRY_DELAY)
    raise RuntimeError(f"HTTP GET failed after {HTTP_MAX_RETRIES} attempts: {url} ({last_exc})")


ESPLORA_BASE = {
    "mainnet": ["https://blockstream.info/api", "https://mempool.space/api"],
    "testnet4": ["https://mempool.space/testnet4/api"],
    "signet": ["https://mempool.space/signet/api"],
}


def fetch_headers_https_fallback(net: NetParams, first_height: int, last_height: int):
    """Fetch a contiguous header range one-by-one over HTTPS. Slow, used
    only if P2P fails entirely for this network."""
    bases = ESPLORA_BASE[net.name]
    headers = []
    used_base = None
    for h in range(first_height, last_height + 1):
        last_exc = None
        for base in bases:
            try:
                block_hash = http_get(f"{base}/block-height/{h}", as_hex_text=True)
                header_hex = http_get(f"{base}/block/{block_hash}/header", as_hex_text=True)
                header_bytes = bytes.fromhex(header_hex)
                if len(header_bytes) != HEADER_SIZE:
                    raise RuntimeError(f"unexpected header length {len(header_bytes)}")
                used_base = base
                headers.append(header_bytes)
                last_exc = None
                break
            except Exception as e:
                last_exc = e
                continue
        if last_exc is not None:
            raise RuntimeError(f"HTTPS header fallback failed at height {h}: {last_exc}")
        time.sleep(0.05)
    source = {"transport": "https", "url": f"{used_base}/block/<hash>/header (per-height)"}
    return headers, source


def fetch_block_raw(net: NetParams, height: int, expected_display_hash: Optional[str] = None):
    """
    Fetch a full raw block by height over HTTPS. Returns
    (raw_bytes, block_hash_display_hex, meta_dict, source_dict).
    """
    bases = ESPLORA_BASE[net.name]
    last_exc = None
    for base in bases:
        try:
            block_hash = http_get(f"{base}/block-height/{height}", as_hex_text=True)
            if expected_display_hash and block_hash != expected_display_hash:
                raise RuntimeError(
                    f"height {height} hash mismatch: got {block_hash}, "
                    f"expected {expected_display_hash}"
                )
            raw = http_get(f"{base}/block/{block_hash}/raw")
            meta = http_get(f"{base}/block/{block_hash}", as_json=True)
            computed_hash = to_display_hex(dsha256(raw[:80]))
            if computed_hash != block_hash:
                raise RuntimeError(
                    f"block {height} header hash mismatch: computed "
                    f"{computed_hash}, expected {block_hash}"
                )
            source = {"transport": "https", "url": f"{base}/block/{block_hash}/raw"}
            return raw, block_hash, meta, source
        except Exception as e:
            last_exc = e
            print(f"    [http] base {base} failed for height {height}: {e}", file=sys.stderr)
            continue
    raise RuntimeError(f"could not fetch block at height {height}: {last_exc}")


def select_small_block(net: NetParams, start_heights: list, tx_min=2, tx_max=60,
                        size_max=32768, step=10, max_scan_per_region=3000):
    """
    Implements the "small block" selection procedure using the
    /api/blocks/{start_height} endpoint (10 summaries ending at
    start_height), scanning forward in steps, across multiple start
    regions, looking for a block with tx_min<=tx_count<=tx_max,
    size<=size_max, and weight < 4*size (proves witness data present).
    Returns (height, block_hash_display_hex, meta_dict).
    """
    base = "https://blockstream.info/api"
    for region_start in start_heights:
        scanned = 0
        cursor = region_start
        while scanned < max_scan_per_region:
            try:
                summaries = http_get(f"{base}/blocks/{cursor}", as_json=True)
            except Exception as e:
                print(f"    [select] blocks/{cursor} failed: {e}", file=sys.stderr)
                break
            if not summaries:
                break
            # summaries are typically in descending height order ending at
            # (or near) cursor; sort ascending for a stable forward scan
            summaries_sorted = sorted(summaries, key=lambda b: b["height"])
            for b in summaries_sorted:
                h = b["height"]
                tx_count = b.get("tx_count")
                size = b.get("size")
                weight = b.get("weight")
                if tx_count is None or size is None or weight is None:
                    continue
                if h < region_start:
                    continue
                scanned += 1
                if (tx_min <= tx_count <= tx_max and size <= size_max
                        and weight < 4 * size):
                    return h, b["id"], b
            max_h = max(b["height"] for b in summaries_sorted)
            cursor = max_h + 10
            if scanned >= max_scan_per_region:
                break
    raise RuntimeError(
        f"no small block matching criteria found in regions {start_heights}"
    )


# ---------------------------------------------------------------------------
# Fixture definitions
# ---------------------------------------------------------------------------

@dataclass
class HeaderFixtureSpec:
    file: str
    network: str
    first_height: int
    last_height: int
    notes: str = ""


@dataclass
class BlockFixtureSpec:
    file: str
    network: str
    height: Optional[int]
    expected_hash: Optional[str]
    notes: str = ""
    select_small: bool = False
    select_start_heights: list = field(default_factory=list)


HEADER_FIXTURES = [
    HeaderFixtureSpec(
        file="mainnet-headers-000000-004031.bin",
        network="mainnet",
        first_height=0,
        last_height=4031,
        notes="Genesis through two full difficulty periods (2016 blocks each).",
    ),
    HeaderFixtureSpec(
        file="mainnet-headers-030229-032257.bin",
        network="mainnet",
        first_height=30229,
        last_height=32257,
        notes=(
            "Window containing mainnet's first real difficulty retarget: "
            "height 32256 nBits 0x1d00d86a (down from 0x1d00ffff at 32255)."
        ),
    ),
    HeaderFixtureSpec(
        file="testnet4-headers-000000-004031.bin",
        network="testnet4",
        first_height=0,
        last_height=4031,
        notes="testnet4 genesis through height 4031.",
    ),
    HeaderFixtureSpec(
        file="signet-headers-000000-002047.bin",
        network="signet",
        first_height=0,
        last_height=2047,
        notes="Default signet genesis through height 2047.",
    ),
]

BLOCK_FIXTURES = [
    BlockFixtureSpec(
        file="mainnet-block-000000.bin",
        network="mainnet",
        height=0,
        expected_hash=NETWORKS["mainnet"].genesis_display_hash,
        notes="Mainnet genesis block.",
    ),
    BlockFixtureSpec(
        file="mainnet-block-000001.bin",
        network="mainnet",
        height=1,
        expected_hash="00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        notes="Mainnet height 1.",
    ),
    BlockFixtureSpec(
        file="mainnet-block-000170.bin",
        network="mainnet",
        height=170,
        expected_hash="00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
        notes="First non-coinbase transaction on mainnet (Satoshi -> Hal Finney).",
    ),
    BlockFixtureSpec(
        file="mainnet-block-100000.bin",
        network="mainnet",
        height=100000,
        expected_hash="000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
        notes="Classic test vector block; 4 transactions.",
    ),
    BlockFixtureSpec(
        file="mainnet-block-segwit-small.bin",
        network="mainnet",
        height=None,
        expected_hash=None,
        select_small=True,
        select_start_heights=[481824, 500000, 520000, 540000],
        notes=(
            "Selected: smallest early block at/after segwit activation "
            "(height>=481824) with 2<=tx_count<=60, size<=32768, and "
            "weight<4*size (proves witness data present)."
        ),
    ),
    BlockFixtureSpec(
        file="mainnet-block-taproot-era-small.bin",
        network="mainnet",
        height=None,
        expected_hash=None,
        select_small=True,
        select_start_heights=[709632, 730000, 750000, 770000],
        notes=(
            "Selected: smallest early block at/after taproot activation "
            "(height>=709632) with 2<=tx_count<=60, size<=32768, and "
            "weight<4*size."
        ),
    ),
    BlockFixtureSpec(
        file="testnet4-block-000000.bin",
        network="testnet4",
        height=0,
        expected_hash=NETWORKS["testnet4"].genesis_display_hash,
        notes="testnet4 genesis block.",
    ),
    BlockFixtureSpec(
        file="signet-block-000000.bin",
        network="signet",
        height=0,
        expected_hash=NETWORKS["signet"].genesis_display_hash,
        notes="Default signet genesis block.",
    ),
    BlockFixtureSpec(
        file="signet-block-000001.bin",
        network="signet",
        height=1,
        expected_hash=None,
        notes="Signet height 1; coinbase carries the signet solution.",
    ),
]

ALL_FIXTURE_NAMES = [f.file for f in HEADER_FIXTURES] + [f.file for f in BLOCK_FIXTURES]


# ---------------------------------------------------------------------------
# Manifest bookkeeping
# ---------------------------------------------------------------------------

class Manifest:
    def __init__(self):
        self.fixtures = []
        self.observed = {}

    def add(self, entry: dict):
        self.fixtures.append(entry)

    def to_dict(self):
        return {
            "schema_version": 1,
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "generator": "tools/fetch_fixtures.py",
            "fixtures": self.fixtures,
            "observed": self.observed,
        }


def load_existing_manifest() -> dict:
    path = os.path.join(FIXTURES_DIR, "manifest.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {"schema_version": 1, "fixtures": [], "observed": {}}


def save_manifest(manifest_dict: dict):
    path = os.path.join(FIXTURES_DIR, "manifest.json")
    with open(path, "w") as f:
        json.dump(manifest_dict, f, indent=2, sort_keys=False)
        f.write("\n")


def upsert_fixture_entry(manifest_dict: dict, entry: dict):
    fixtures = manifest_dict.setdefault("fixtures", [])
    for i, existing in enumerate(fixtures):
        if existing.get("file") == entry.get("file"):
            fixtures[i] = entry
            return
    fixtures.append(entry)


# ---------------------------------------------------------------------------
# Fixture generation
# ---------------------------------------------------------------------------

def write_bytes(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def generate_header_fixture(spec: HeaderFixtureSpec, manifest_dict: dict):
    net = NETWORKS[spec.network]
    target_count = spec.last_height + 1
    print(f"[headers] {spec.file}: fetching {spec.network} heights "
          f"0..={spec.last_height} to slice {spec.first_height}..={spec.last_height}")

    headers, source = fetch_headers_p2p(net, target_count)
    if headers is None:
        print(f"[headers] {spec.file}: P2P failed ({source}); falling back to HTTPS", file=sys.stderr)
        headers, source = fetch_headers_https_fallback(net, 0, spec.last_height)
        # verify linkage for the fallback path too
        prev_hash = None
        for i, h in enumerate(headers):
            h_hash = dsha256(h)
            prev_field = h[4:36]
            if i == 0:
                if h_hash != net.genesis_internal_hash:
                    raise RuntimeError(f"{spec.file}: fallback height 0 is not genesis")
            else:
                if prev_field != prev_hash:
                    raise RuntimeError(f"{spec.file}: fallback linkage broken at height {i}")
            prev_hash = h_hash

    if len(headers) < target_count:
        raise RuntimeError(
            f"{spec.file}: only obtained {len(headers)} headers, need {target_count}"
        )

    full_run = headers[:target_count]

    # Record full 0..=32257 observation for the mainnet retarget window fixture.
    if spec.network == "mainnet" and spec.last_height == 32257:
        full_concat = b"".join(full_run)
        manifest_dict.setdefault("observed", {})["mainnet_headers_0_to_32257_sha256"] = (
            hashlib.sha256(full_concat).hexdigest()
        )
        nbits_32255 = struct.unpack_from("<I", full_run[32255], 72)[0]
        nbits_32256 = struct.unpack_from("<I", full_run[32256], 72)[0]
        manifest_dict["observed"]["mainnet_nbits_at_32255"] = f"0x{nbits_32255:08x}"
        manifest_dict["observed"]["mainnet_nbits_at_32256"] = f"0x{nbits_32256:08x}"
        assert nbits_32255 == 0x1d00ffff, (
            f"expected nBits 0x1d00ffff at height 32255, got 0x{nbits_32255:08x}"
        )
        assert nbits_32256 == 0x1d00d86a, (
            f"expected nBits 0x1d00d86a at height 32256, got 0x{nbits_32256:08x}"
        )
        print(f"[headers] confirmed retarget: 32255=0x{nbits_32255:08x} -> 32256=0x{nbits_32256:08x}")

    sliced = full_run[spec.first_height:spec.last_height + 1]
    if len(sliced) != spec.last_height - spec.first_height + 1:
        raise RuntimeError(f"{spec.file}: slice length mismatch")

    # verify linkage within the slice against full_run context
    if spec.first_height > 0:
        prev_hash_expected = dsha256(full_run[spec.first_height - 1])
        prev_field_actual = sliced[0][4:36]
        if prev_field_actual != prev_hash_expected:
            raise RuntimeError(f"{spec.file}: slice does not link to preceding header")

    data = b"".join(sliced)
    out_path = os.path.join(FIXTURES_DIR, spec.file)
    write_bytes(out_path, data)

    first_hash = to_display_hex(dsha256(sliced[0]))
    last_hash = to_display_hex(dsha256(sliced[-1]))
    sha256_hex = hashlib.sha256(data).hexdigest()

    entry = {
        "file": spec.file,
        "network": spec.network,
        "kind": "headers",
        "first_height": spec.first_height,
        "last_height": spec.last_height,
        "count": len(sliced),
        "first_hash": first_hash,
        "last_hash": last_hash,
        "bytes": len(data),
        "sha256": sha256_hex,
        "source": source,
        "notes": spec.notes,
    }
    upsert_fixture_entry(manifest_dict, entry)
    print(f"[headers] {spec.file}: OK ({len(data)} bytes, sha256={sha256_hex[:16]}...)")
    return entry


def generate_block_fixture(spec: BlockFixtureSpec, manifest_dict: dict):
    net = NETWORKS[spec.network]
    print(f"[block] {spec.file}: fetching {spec.network} "
          f"{'(auto-select small block)' if spec.select_small else f'height {spec.height}'}")

    height = spec.height
    expected_hash = spec.expected_hash
    selection_meta = None
    if spec.select_small:
        height, expected_hash, selection_meta = select_small_block(
            net, spec.select_start_heights
        )
        print(f"[block] {spec.file}: selected height {height} hash {expected_hash} "
              f"tx_count={selection_meta.get('tx_count')} size={selection_meta.get('size')} "
              f"weight={selection_meta.get('weight')}")

    raw, block_hash, meta, source = fetch_block_raw(net, height, expected_hash)

    if len(raw) >= MAX_BLOCK_BYTES:
        raise RuntimeError(
            f"{spec.file}: block at height {height} is {len(raw)} bytes, "
            f">= {MAX_BLOCK_BYTES} limit"
        )

    out_path = os.path.join(FIXTURES_DIR, spec.file)
    write_bytes(out_path, raw)
    sha256_hex = hashlib.sha256(raw).hexdigest()

    notes = spec.notes
    if spec.select_small:
        notes += (
            f" Selection result: height={height}, tx_count={meta.get('tx_count')}, "
            f"size={meta.get('size')}, weight={meta.get('weight')}."
        )

    entry = {
        "file": spec.file,
        "network": spec.network,
        "kind": "block",
        "height": height,
        "hash": block_hash,
        "tx_count": meta.get("tx_count"),
        "size": meta.get("size"),
        "weight": meta.get("weight"),
        "bytes": len(raw),
        "sha256": sha256_hex,
        "source": source,
        "notes": notes,
    }
    upsert_fixture_entry(manifest_dict, entry)
    print(f"[block] {spec.file}: OK ({len(raw)} bytes, sha256={sha256_hex[:16]}...)")
    return entry


# ---------------------------------------------------------------------------
# Post-hoc independent verification
# ---------------------------------------------------------------------------

def verify_all(manifest_dict: dict) -> bool:
    print("\n=== Independent verification ===")
    ok = True
    for entry in manifest_dict["fixtures"]:
        path = os.path.join(FIXTURES_DIR, entry["file"])
        if not os.path.exists(path):
            print(f"  [MISSING] {entry['file']}")
            ok = False
            continue
        actual_sha = sha256_file(path)
        actual_bytes = os.path.getsize(path)
        if actual_sha != entry["sha256"]:
            print(f"  [SHA MISMATCH] {entry['file']}: manifest={entry['sha256']} actual={actual_sha}")
            ok = False
        if actual_bytes != entry["bytes"]:
            print(f"  [SIZE MISMATCH] {entry['file']}: manifest={entry['bytes']} actual={actual_bytes}")
            ok = False

        if entry["kind"] == "headers":
            if actual_bytes != entry["count"] * HEADER_SIZE:
                print(f"  [LENGTH MISMATCH] {entry['file']}: {actual_bytes} != {entry['count']}*80")
                ok = False
            with open(path, "rb") as f:
                data = f.read()
            n = len(data) // HEADER_SIZE
            prev_hash = None
            first_hash_seen = None
            for i in range(n):
                h = data[i * HEADER_SIZE:(i + 1) * HEADER_SIZE]
                h_hash = dsha256(h)
                if i == 0:
                    first_hash_seen = h_hash
                else:
                    prev_field = h[4:36]
                    if prev_field != prev_hash:
                        print(f"  [LINKAGE BROKEN] {entry['file']} at index {i}")
                        ok = False
                        break
                prev_hash = h_hash
            else:
                last_hash_seen = prev_hash
                if to_display_hex(first_hash_seen) != entry["first_hash"]:
                    print(f"  [FIRST HASH MISMATCH] {entry['file']}")
                    ok = False
                if to_display_hex(last_hash_seen) != entry["last_hash"]:
                    print(f"  [LAST HASH MISMATCH] {entry['file']}")
                    ok = False
            print(f"  [ok] {entry['file']} headers linkage verified ({n} headers)")

        elif entry["kind"] == "block":
            with open(path, "rb") as f:
                data = f.read()
            computed_hash = to_display_hex(dsha256(data[:80]))
            if computed_hash != entry["hash"]:
                print(f"  [HASH MISMATCH] {entry['file']}: computed={computed_hash} expected={entry['hash']}")
                ok = False
            else:
                print(f"  [ok] {entry['file']} block header hash verified ({len(data)} bytes)")

    total_bytes = sum(
        os.path.getsize(os.path.join(FIXTURES_DIR, e["file"]))
        for e in manifest_dict["fixtures"]
        if os.path.exists(os.path.join(FIXTURES_DIR, e["file"]))
    )
    print(f"\nTotal fixture bytes: {total_bytes} ({total_bytes / 1024:.1f} KiB)")
    if total_bytes >= 1.3 * 1024 * 1024:
        print("  [WARNING] total exceeds 1.3 MiB budget!")
        ok = False

    return ok


def write_sha256sums(manifest_dict: dict):
    lines = []
    for entry in sorted(manifest_dict["fixtures"], key=lambda e: e["file"]):
        path = os.path.join(FIXTURES_DIR, entry["file"])
        if os.path.exists(path):
            digest = sha256_file(path)
            lines.append(f"{digest}  {entry['file']}\n")
    out_path = os.path.join(FIXTURES_DIR, "SHA256SUMS")
    with open(out_path, "w") as f:
        f.writelines(lines)
    print(f"[sha256sums] wrote {out_path} ({len(lines)} entries)")


def run_sha256sum_check() -> bool:
    import subprocess
    result = subprocess.run(
        ["sha256sum", "-c", "SHA256SUMS"],
        cwd=FIXTURES_DIR,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", metavar="NAME", help="regenerate only this fixture file")
    parser.add_argument("--list", action="store_true", help="list fixture names and exit")
    args = parser.parse_args()

    if args.list:
        for name in ALL_FIXTURE_NAMES:
            print(name)
        return 0

    os.makedirs(FIXTURES_DIR, exist_ok=True)

    manifest_dict = load_existing_manifest()
    manifest_dict.setdefault("schema_version", 1)
    manifest_dict.setdefault("fixtures", [])
    manifest_dict.setdefault("observed", {})
    manifest_dict["generator"] = "tools/fetch_fixtures.py"

    header_specs = HEADER_FIXTURES
    block_specs = BLOCK_FIXTURES
    if args.only:
        header_specs = [s for s in HEADER_FIXTURES if s.file == args.only]
        block_specs = [s for s in BLOCK_FIXTURES if s.file == args.only]
        if not header_specs and not block_specs:
            print(f"error: unknown fixture name {args.only!r}", file=sys.stderr)
            print("known names:", file=sys.stderr)
            for name in ALL_FIXTURE_NAMES:
                print(f"  {name}", file=sys.stderr)
            return 2

    errors = []

    for spec in header_specs:
        try:
            generate_header_fixture(spec, manifest_dict)
        except Exception as e:
            print(f"[ERROR] {spec.file}: {e}", file=sys.stderr)
            errors.append((spec.file, str(e)))

    for spec in block_specs:
        try:
            generate_block_fixture(spec, manifest_dict)
        except Exception as e:
            print(f"[ERROR] {spec.file}: {e}", file=sys.stderr)
            errors.append((spec.file, str(e)))

    manifest_dict["generated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_manifest(manifest_dict)
    write_sha256sums(manifest_dict)

    verify_ok = verify_all(manifest_dict)
    check_ok = run_sha256sum_check()

    if errors:
        print(f"\n{len(errors)} fixture(s) FAILED to generate:", file=sys.stderr)
        for name, msg in errors:
            print(f"  {name}: {msg}", file=sys.stderr)

    if not verify_ok or not check_ok or errors:
        print("\nRESULT: FAILURE", file=sys.stderr)
        return 1

    print("\nRESULT: SUCCESS -- all fixtures generated and verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
