#!/usr/bin/env python3
"""Bounded passive sampler for full-validation mainnet IBD block receipts.

The tool only calls read-only JSON-RPC through the configured Avila CLI. It
never starts/stops the node, changes configuration, or retries/continues a
partial receipt file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from typing import Any, Callable

MAX_WINDOW = 128
RECEIPT_RING = 2016
MAX_CLI_OUTPUT = 4 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_CLI_BINARY_BYTES = 512 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 60
MAX_WAIT_SECONDS = 7 * 24 * 60 * 60
MAX_HEIGHT = 100_000_000
HEX64 = set("0123456789abcdef")


class MeasurementError(Exception):
    """A bounded, user-actionable measurement refusal/failure."""


class RpcCallError(MeasurementError):
    """A CLI invocation or RPC response failed."""


@dataclass(frozen=True)
class NodeState:
    connected_height: int
    header_height: int
    bestblockhash: str
    chain: str
    ibd: bool
    uptime: int
    policy_checkpoint: str | None
    historical_scripts_required: bool
    observed_at: str
    monotonic_at: float
    info_blocks: int


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    exe_dev: int
    exe_ino: int
    exe_sha256: str
    config_resolved: str
    clock_ticks_per_second: int
    page_size: int


@dataclass(frozen=True)
class ProcessCounters:
    cpu_seconds: float
    rss_bytes: int
    read_bytes: int
    write_bytes: int
    cancelled_write_bytes: int


class AvilaCli:
    def __init__(
        self,
        cli: Path,
        config: Path,
        rpc_addr: str,
        timeout: float,
        output_limit: int = MAX_CLI_OUTPUT,
    ) -> None:
        self.cli = cli
        self.config = config
        self.rpc_addr = rpc_addr
        self.timeout = timeout
        self.output_limit = output_limit

    def call(self, method: str, *params: Any) -> Any:
        argv = [
            str(self.cli),
            "--config",
            str(self.config),
            "rpc",
            method,
            *(json.dumps(param, separators=(",", ":")) for param in params),
            "--rpc-addr",
            self.rpc_addr,
        ]
        stdout, stderr, returncode = bounded_subprocess(argv, self.timeout, self.output_limit)
        if returncode != 0:
            # Do not surface CLI stderr: deployments may include sensitive
            # endpoint or authentication diagnostics in an error string.
            raise RpcCallError(f"CLI RPC {method} failed (exit {returncode})")
        try:
            return json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if method == "getblockhash":
                try:
                    raw_hash = stdout.decode("ascii").strip()
                    return require_hash(raw_hash, "getblockhash result")
                except (UnicodeDecodeError, MeasurementError) as raw_exc:
                    raise RpcCallError("CLI RPC getblockhash returned invalid hash text") from raw_exc
            raise RpcCallError(f"CLI RPC {method} returned invalid JSON") from exc


def bounded_subprocess(argv: list[str], timeout: float, output_limit: int) -> tuple[bytes, bytes, int]:
    """Run one CLI request with a hard combined stdout/stderr byte bound."""
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except OSError as exc:
        raise RpcCallError(f"cannot execute CLI: {exc.strerror or type(exc).__name__}") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise RpcCallError("could not capture bounded CLI output")
    out = bytearray()
    err = bytearray()
    selector = selectors.DefaultSelector()
    for stream, target in ((process.stdout, out), (process.stderr, err)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, target)
    deadline = time.monotonic() + timeout
    failed: str | None = None
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failed = "timed out"
            break
        for key, _ in selector.select(min(remaining, 0.25)):
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            key.data.extend(chunk)
            if len(out) + len(err) > output_limit:
                failed = f"output exceeded {output_limit} bytes"
                break
        if failed:
            break
    if failed:
        process.kill()
        process.wait()
        for stream in (process.stdout, process.stderr):
            stream.close()
        selector.close()
        raise RpcCallError(f"CLI RPC {argv[4] if len(argv) > 4 else 'request'} {failed}")
    selector.close()
    try:
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
        raise RpcCallError("CLI process timed out after closing its output") from exc
    return bytes(out), bytes(err), returncode


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def require_int(obj: dict[str, Any], key: str, minimum: int = 0) -> int:
    value = obj.get(key)
    if not is_int(value) or value < minimum:
        raise MeasurementError(f"RPC field {key} is missing or outside its allowed range")
    return value


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value.lower()) <= HEX64:
        raise MeasurementError(f"{label} is not a 64-character hexadecimal hash")
    return value.lower()


def validate_observation(info: Any, report: Any, uptime: Any, observed_at: str | None = None, mono: float | None = None) -> NodeState:
    if not isinstance(info, dict) or not isinstance(report, dict):
        raise MeasurementError("getblockchaininfo/getvalidationreport returned the wrong JSON type")
    if info.get("chain") != "main":
        raise MeasurementError("measurement requires the mainnet chain")
    connected = require_int(report, "connected_height")
    header_height = require_int(report, "header_height")
    info_blocks = require_int(info, "blocks")
    require_int(info, "headers")
    tip_hash = require_hash(info.get("bestblockhash"), "bestblockhash")
    if header_height < connected or info_blocks > require_int(info, "headers"):
        raise MeasurementError("reported connected/header heights are inconsistent")
    if not isinstance(info.get("initialblockdownload"), bool):
        raise MeasurementError("initialblockdownload is missing or not boolean")
    if info["initialblockdownload"] is not True:
        raise MeasurementError("node is not reporting initial block download")
    policy = report.get("validation_policy")
    if not isinstance(policy, dict):
        raise MeasurementError("getvalidationreport lacks validation_policy metadata")
    if "assume_valid_checkpoint" not in policy:
        raise MeasurementError("validation_policy does not explicitly report assume_valid_checkpoint")
    if policy["assume_valid_checkpoint"] is not None:
        raise MeasurementError("AssumeValid is configured; refusing a full-validation measurement")
    if policy.get("historical_scripts_required") is not True:
        raise MeasurementError("historical script validation is not required by the configured policy")
    if not is_int(uptime) or uptime < 0:
        raise MeasurementError("uptime RPC returned an invalid value")
    return NodeState(
        connected_height=connected,
        header_height=header_height,
        bestblockhash=tip_hash,
        chain="main",
        ibd=True,
        uptime=uptime,
        policy_checkpoint=None,
        historical_scripts_required=True,
        observed_at=observed_at or utc_now(),
        monotonic_at=mono if mono is not None else time.monotonic(),
        info_blocks=info_blocks,
    )


def validate_receipt(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise MeasurementError("receipt entry is not an object")
    height = require_int(row, "height")
    digest = require_hash(row.get("hash"), f"receipt[{height}].hash")
    delta = require_hash(row.get("delta_commitment"), f"receipt[{height}].delta_commitment")
    if row.get("checks_enabled") is not True:
        raise MeasurementError(f"receipt at height {height} says script checks were disabled")
    normalized = dict(row)
    normalized["height"] = height
    normalized["hash"] = digest
    normalized["delta_commitment"] = delta
    for key in ("script_flags", "txs", "sigops", "script_checks", "verified_hits", "spent_coins", "created_coins", "wall_ns"):
        normalized[key] = require_int(row, key)
    fees = row.get("fees")
    try:
        finite_fees = isinstance(fees, (int, float)) and not isinstance(fees, bool) and math.isfinite(fees)
    except OverflowError:
        finite_fees = False
    if not finite_fees or fees < 0 or fees > 21_000_000:
        raise MeasurementError(f"receipt at height {height} has invalid fees")
    normalized["fees"] = fees
    return normalized


def validate_receipt_window(
    rows: Any,
    start_height: int,
    count: int,
    active_hash_for: Callable[[int], Any],
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) > RECEIPT_RING:
        raise MeasurementError("getblockreceipts returned a non-array or exceeded the 2016-entry bound")
    end_height = start_height + count - 1
    by_height: dict[int, dict[str, Any]] = {}
    for raw in rows:
        row = validate_receipt(raw)
        height = row["height"]
        if start_height <= height <= end_height:
            if height in by_height:
                raise MeasurementError(f"duplicate receipt at height {height}; possible reorg event")
            by_height[height] = row
    expected_heights = list(range(start_height, end_height + 1))
    missing = [height for height in expected_heights if height not in by_height]
    if missing:
        raise MeasurementError(f"receipt ring missing target heights (first missing: {missing[0]})")
    result = [by_height[height] for height in expected_heights]
    for row in result:
        height = row["height"]
        active = require_hash(active_hash_for(height), f"getblockhash({height})")
        if row["hash"] != active:
            raise MeasurementError(f"receipt at height {height} does not match the active chain")
    return result


def percentiles(values: list[int]) -> dict[str, int | float]:
    if not values:
        raise MeasurementError("cannot summarize an empty timing series")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        median: int | float = ordered[middle]
    else:
        median = (ordered[middle - 1] + ordered[middle]) / 2
    p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    return {"median": median, "p95": p95, "min": ordered[0], "max": ordered[-1]}


def build_external_sample(
    start: NodeState | None,
    end: NodeState,
    target_start: int,
    target_end: int,
    poll_seconds: float,
    rpc_timeout: float,
) -> dict[str, Any]:
    if start is None:
        return {
            "available": False,
            "reason": "sampler first observed the checked tip at or above the target start height",
            "target_heights": [target_start, target_end],
        }
    if start.connected_height >= target_start:
        raise MeasurementError("external sample start must be strictly before the target window")
    if end.connected_height < target_end:
        raise MeasurementError("external sample ended before the target window completed")
    if end.monotonic_at < start.monotonic_at:
        raise MeasurementError("monotonic sample clock moved backwards")
    elapsed = end.monotonic_at - start.monotonic_at
    if elapsed <= 0:
        raise MeasurementError("sampled status interval must have positive elapsed time")
    advanced = end.connected_height - start.connected_height
    prefix = target_start - start.connected_height - 1
    target_count = target_end - target_start + 1
    suffix = end.connected_height - target_end
    return {
        "available": True,
        "target_heights": [target_start, target_end],
        "observed_connected_height_start": start.connected_height,
        "observed_connected_height_end": end.connected_height,
        "observed_advanced_checked_blocks": advanced,
        "prefix_blocks_before_target": prefix,
        "target_blocks": target_count,
        "suffix_blocks_after_target": suffix,
        "interval_encloses_target_window": True,
        "exact_target_height_endpoints": prefix == 0 and suffix == 0,
        "start_observed_at_utc": start.observed_at,
        "end_observed_at_utc": end.observed_at,
        "sampled_elapsed_seconds": elapsed,
        "observed_checked_blocks_per_second": advanced / elapsed,
        "endpoint_overshoot_blocks": end.connected_height - target_end,
        "exact_target_endpoint_observed": end.connected_height == target_end,
        "status_observation_uncertainty_allowance_seconds": 2.0 * (poll_seconds + 5.0 * rpc_timeout),
        "boundary_note": "elapsed time is between RPC status observations, not exact block-connection timestamps; checked-blocks-per-second uses the actual observed height delta; the status-observation allowance assumes one poll interval and up to five sequential status/continuity-hash CLI call timeouts at each endpoint, and does not bound target-only timing when prefix or suffix blocks are included",
    }


def update_pre_window_observation(
    state: NodeState,
    target_start: int,
    previous: NodeState | None,
    late_attach: bool,
) -> tuple[NodeState | None, bool, bool]:
    """Keep the latest below-window status until the first crossing is seen."""
    if late_attach:
        return previous, True, False
    if state.connected_height < target_start:
        return state, False, True
    if previous is None:
        return None, True, False
    return previous, False, False


def sha256_file(path: Path, max_bytes: int, label: str) -> str:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise MeasurementError(f"{label} exceeds the {max_bytes}-byte provenance hashing bound")
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise MeasurementError(f"{label} grew beyond the provenance hashing bound")
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise MeasurementError(f"cannot read {label} for provenance: {exc.strerror or type(exc).__name__}") from exc


def process_identity(pid: int, cli_sha256: str, config: Path) -> ProcessIdentity:
    proc = Path("/proc") / str(pid)
    try:
        raw_stat = (proc / "stat").read_text(encoding="ascii")
        close = raw_stat.rfind(")")
        fields = raw_stat[close + 2 :].split()
        # `fields[0]` is stat field 3; starttime is field 22.
        start_ticks = int(fields[19])
        exe_stat = (proc / "exe").stat()
        exe_sha = sha256_file(proc / "exe", MAX_CLI_BINARY_BYTES, "node executable")
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        argv = [part.decode("utf-8", "surrogateescape") for part in argv if part]
    except (OSError, ValueError, IndexError) as exc:
        raise MeasurementError(f"cannot verify node PID {pid}: {type(exc).__name__}") from exc
    if exe_sha != cli_sha256:
        raise MeasurementError("provided PID executable does not match the selected CLI binary")
    if "run" not in argv:
        raise MeasurementError("provided PID is not running the Avila run command")
    config_resolved = str(config.resolve())
    configured_path: str | None = None
    for index, token in enumerate(argv):
        if token == "--config" and index + 1 < len(argv):
            configured_path = argv[index + 1]
            break
        if token.startswith("--config="):
            configured_path = token.split("=", 1)[1]
            break
    if configured_path is None or str(Path(configured_path).resolve()) != config_resolved:
        raise MeasurementError("provided PID is not using the selected config file")
    return ProcessIdentity(
        pid=pid,
        start_ticks=start_ticks,
        exe_dev=exe_stat.st_dev,
        exe_ino=exe_stat.st_ino,
        exe_sha256=exe_sha,
        config_resolved=config_resolved,
        clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
        page_size=os.sysconf("SC_PAGE_SIZE"),
    )


def verify_process_identity(identity: ProcessIdentity) -> None:
    proc = Path("/proc") / str(identity.pid)
    try:
        raw_stat = (proc / "stat").read_text(encoding="ascii")
        close = raw_stat.rfind(")")
        fields = raw_stat[close + 2 :].split()
        start_ticks = int(fields[19])
        exe_stat = (proc / "exe").stat()
    except (OSError, ValueError, IndexError) as exc:
        raise MeasurementError(f"node PID {identity.pid} exited or could not be revalidated") from exc
    if (
        start_ticks != identity.start_ticks
        or exe_stat.st_dev != identity.exe_dev
        or exe_stat.st_ino != identity.exe_ino
    ):
        raise MeasurementError(f"node PID {identity.pid} changed identity during the sample")


def read_process_counters(identity: ProcessIdentity) -> ProcessCounters:
    verify_process_identity(identity)
    proc = Path("/proc") / str(identity.pid)
    try:
        raw_stat = (proc / "stat").read_text(encoding="ascii")
        fields = raw_stat[raw_stat.rfind(")") + 2 :].split()
        utime = int(fields[11])
        stime = int(fields[12])
        statm = (proc / "statm").read_text(encoding="ascii").split()
        rss_bytes = int(statm[1]) * identity.page_size
        io_values: dict[str, int] = {}
        for line in (proc / "io").read_text(encoding="ascii").splitlines():
            key, value = line.split(":", 1)
            io_values[key] = int(value.strip())
    except (OSError, ValueError, IndexError) as exc:
        raise MeasurementError(f"could not read bounded counters for PID {identity.pid}") from exc
    return ProcessCounters(
        cpu_seconds=(utime + stime) / identity.clock_ticks_per_second,
        rss_bytes=rss_bytes,
        read_bytes=io_values.get("read_bytes", 0),
        write_bytes=io_values.get("write_bytes", 0),
        cancelled_write_bytes=io_values.get("cancelled_write_bytes", 0),
    )


def process_delta(start: ProcessCounters, end: ProcessCounters) -> dict[str, Any]:
    if end.cpu_seconds < start.cpu_seconds or end.read_bytes < start.read_bytes or end.write_bytes < start.write_bytes:
        raise MeasurementError("node process counters moved backwards")
    return {
        "cpu_seconds_delta": end.cpu_seconds - start.cpu_seconds,
        "rss_bytes_start": start.rss_bytes,
        "rss_bytes_end": end.rss_bytes,
        "read_bytes_delta": end.read_bytes - start.read_bytes,
        "write_bytes_delta": end.write_bytes - start.write_bytes,
        "cancelled_write_bytes_delta": end.cancelled_write_bytes - start.cancelled_write_bytes,
        "scope": "node PID only; RSS values are endpoint samples, not peak memory; /proc io byte counters are process-accounted I/O, not device bytes",
    }


def write_atomic_new(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_RESULT_BYTES:
        raise MeasurementError(f"result exceeds {MAX_RESULT_BYTES} bytes")
    parent = path.parent
    if not parent.is_dir():
        raise MeasurementError("output parent directory must already exist")
    if path.exists():
        raise MeasurementError("output already exists; refusing overwrite or implicit resume")
    temp_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=parent)
        temp_path = Path(temp_name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link publishes atomically and fails if another
        # process created the destination after the preflight check.
        os.link(temp_path, path)
        temp_path.unlink()
        temp_path = None
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except FileExistsError as exc:
        raise MeasurementError("output already exists; refusing overwrite or implicit resume") from exc
    except OSError as exc:
        raise MeasurementError(f"could not atomically publish output: {exc.strerror or type(exc).__name__}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path, help="avila-node CLI executable")
    parser.add_argument("--config", required=True, type=Path, help="same TOML config used by the running daemon")
    parser.add_argument("--output", required=True, type=Path, help="new JSON output path; existing files are never overwritten")
    parser.add_argument("--rpc-addr", default="127.0.0.1:18443", help="daemon RPC address")
    parser.add_argument("--start-height", type=int, default=600_000, help="first block receipt height (default: 600000)")
    parser.add_argument("--count", type=int, default=128, help=f"bounded window size, 1..{MAX_WINDOW} (default: 128)")
    parser.add_argument("--wait-seconds", type=int, default=86_400, help="maximum wait for the checked window (default: 24h)")
    parser.add_argument("--poll-seconds", type=float, default=5.0, help="status polling interval (default: 5s)")
    parser.add_argument("--rpc-timeout", type=float, default=15.0, help="per-CLI-call timeout (default: 15s, max: 60s)")
    parser.add_argument("--node-pid", type=int, help="optional Avila run PID for bounded /proc CPU/RSS/I/O deltas")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not 1 <= args.count <= MAX_WINDOW:
        raise MeasurementError(f"--count must be between 1 and {MAX_WINDOW}")
    if not 1 <= args.start_height <= MAX_HEIGHT:
        raise MeasurementError("--start-height must be in 1..100000000")
    if args.start_height + args.count - 1 > MAX_HEIGHT:
        raise MeasurementError("requested end height exceeds the supported bound")
    if not 0 <= args.wait_seconds <= MAX_WAIT_SECONDS:
        raise MeasurementError("--wait-seconds must be in 0..604800")
    if not 0.25 <= args.poll_seconds <= 60:
        raise MeasurementError("--poll-seconds must be in 0.25..60")
    if not 0.5 <= args.rpc_timeout <= MAX_TIMEOUT_SECONDS:
        raise MeasurementError("--rpc-timeout must be in 0.5..60")
    validate_rpc_addr(args.rpc_addr)
    if args.node_pid is not None and args.node_pid <= 1:
        raise MeasurementError("--node-pid must be a positive non-system PID")
    if not args.cli.is_file() or not os.access(args.cli, os.X_OK):
        raise MeasurementError("--cli must name an executable file")
    if not args.config.is_file():
        raise MeasurementError("--config must name an existing file")
    if args.output.exists():
        raise MeasurementError("output already exists; refusing overwrite or implicit resume")
    if not args.output.parent.is_dir():
        raise MeasurementError("output parent directory must already exist")


def validate_rpc_addr(value: str) -> None:
    """Keep this observer local: no DNS lookup or remote RPC endpoint."""
    if not isinstance(value, str) or len(value) > 64:
        raise MeasurementError("--rpc-addr must be a numeric loopback address and port")
    if value.startswith("["):
        host, separator, port_text = value[1:].partition("]:")
    else:
        host, separator, port_text = value.rpartition(":")
    if not separator or not port_text.isdecimal():
        raise MeasurementError("--rpc-addr must be a numeric loopback address and port")
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as exc:
        raise MeasurementError("--rpc-addr must be a numeric loopback address and port") from exc
    if not address.is_loopback or not 1 <= port <= 65535:
        raise MeasurementError("--rpc-addr must use a loopback address and valid port")


def read_state(client: AvilaCli) -> NodeState:
    info = client.call("getblockchaininfo")
    report = client.call("getvalidationreport")
    uptime = client.call("uptime")
    state = validate_observation(info, report, uptime)
    if state.info_blocks != state.connected_height:
        # These RPCs are separate snapshots. Resolve the exact checked tip when
        # they straddle a successful connect instead of pairing the wrong hash.
        tip_hash = require_hash(client.call("getblockhash", state.connected_height), "checked tip hash")
        state = replace(state, bestblockhash=tip_hash)
    return state


def collect_window(client: AvilaCli, start_height: int, count: int, connected_height: int) -> list[dict[str, Any]]:
    if connected_height < start_height + count - 1:
        raise MeasurementError("checked connected height is below the requested window end")
    if connected_height - start_height + 1 > RECEIPT_RING:
        raise MeasurementError("requested start is older than the 2016-entry receipt ring")
    rows = client.call("getblockreceipts", RECEIPT_RING)
    return validate_receipt_window(
        rows,
        start_height,
        count,
        lambda height: client.call("getblockhash", height),
    )


def recheck_receipt_hashes(client: AvilaCli, receipts: list[dict[str, Any]]) -> None:
    """Recheck the active chain after receipt collection to catch intervening reorgs."""
    for row in receipts:
        active = require_hash(client.call("getblockhash", row["height"]), f"getblockhash({row['height']})")
        if row["hash"] != active:
            raise MeasurementError(f"active hash changed during receipt collection at height {row['height']}")


def summarize(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    fields = ("txs", "sigops", "script_checks", "verified_hits", "spent_coins", "created_coins", "wall_ns")
    totals = {field: sum(row[field] for row in receipts) for field in fields}
    walls = [row["wall_ns"] for row in receipts]
    return {
        "blocks": len(receipts),
        "totals": totals,
        "serial_connect_wall_ns_per_block": percentiles(walls),
        "serial_connect_wall_semantics": "wall_ns is the serial connect pass; if script workers are configured it excludes deferred script-check wait",
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    validate_args(args)
    cli_sha = sha256_file(args.cli, MAX_CLI_BINARY_BYTES, "CLI binary")
    config_sha = sha256_file(args.config, MAX_CONFIG_BYTES, "config file")
    client = AvilaCli(args.cli, args.config, args.rpc_addr, args.rpc_timeout)
    end_height = args.start_height + args.count - 1
    deadline = time.monotonic() + args.wait_seconds
    external_start: NodeState | None = None
    end_state: NodeState | None = None
    last_height: int | None = None
    last_tip_hash: str | None = None
    last_uptime: int | None = None
    late_attach = False
    pid_identity = process_identity(args.node_pid, cli_sha, args.config) if args.node_pid else None
    proc_start: ProcessCounters | None = None
    proc_end: ProcessCounters | None = None
    first_observation: NodeState | None = None

    while True:
        if pid_identity:
            verify_process_identity(pid_identity)
        try:
            state = read_state(client)
            # These checks need only the new observation and must run before
            # a retryable RPC, so a transient hash failure cannot mask a
            # restart or reorg already evident in the status fields.
            if last_height is not None and state.connected_height < last_height:
                raise MeasurementError("checked connected height decreased during sample; possible reorg/restart")
            if last_height is not None and state.connected_height == last_height and state.bestblockhash != last_tip_hash:
                raise MeasurementError("checked tip hash changed without height progress; possible reorg")
            if last_uptime is not None and state.uptime < last_uptime:
                raise MeasurementError("node uptime decreased during sample; node restarted")
            # Keep the observation and its continuity check together. A
            # transient CLI/RPC failure must not discard the last successful
            # baseline or terminate a long pre-window wait. MeasurementError
            # (including a real active-chain mismatch) remains fail-closed.
            if last_height is not None and state.connected_height > last_height:
                prior_active_hash = require_hash(
                    client.call("getblockhash", last_height), f"getblockhash({last_height})"
                )
                if prior_active_hash != last_tip_hash:
                    raise MeasurementError("active chain changed below the observed checked tip")
        except RpcCallError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(args.poll_seconds)
            continue
        if first_observation is None:
            first_observation = state
        last_height = state.connected_height
        last_tip_hash = state.bestblockhash
        last_uptime = state.uptime

        external_start, late_attach, refreshed_pre_window = update_pre_window_observation(
            state, args.start_height, external_start, late_attach
        )
        if refreshed_pre_window and pid_identity:
            # Pair the process counter baseline with the latest checked status
            # strictly before the target starts, just as for the time baseline.
            proc_start = read_process_counters(pid_identity)

        if state.connected_height >= end_height:
            end_state = state
            if external_start and pid_identity:
                proc_end = read_process_counters(pid_identity)
            break
        if time.monotonic() >= deadline:
            raise MeasurementError(
                f"timed out waiting for checked height {end_height}; last checked height {state.connected_height}"
            )
        time.sleep(args.poll_seconds)

    if end_state is None:
        raise MeasurementError("internal error: no endpoint observation")
    receipts = collect_window(client, args.start_height, args.count, end_state.connected_height)
    # Re-read checked tip and policy after the receipt/hash scan: this rejects
    # a policy change, restart, or state discontinuity during collection.
    final_state = read_state(client)
    if final_state.uptime < end_state.uptime:
        raise MeasurementError("node restarted while collecting the receipt window")
    if final_state.connected_height < end_height:
        raise MeasurementError("checked connected height fell below the window during collection")
    if final_state.connected_height < end_state.connected_height:
        raise MeasurementError("checked connected height moved backwards during collection")
    if final_state.uptime == end_state.uptime and final_state.connected_height == end_state.connected_height:
        if final_state.bestblockhash != end_state.bestblockhash:
            raise MeasurementError("checked tip hash changed during receipt collection")
    recheck_receipt_hashes(client, receipts)
    post_hash_state = read_state(client)
    if post_hash_state.uptime < end_state.uptime or post_hash_state.connected_height < end_height:
        raise MeasurementError("node restarted or checked height regressed during final active-hash recheck")
    if require_hash(client.call("getblockhash", end_height), f"getblockhash({end_height})") != receipts[-1]["hash"]:
        raise MeasurementError("active chain changed within the target window during final hash recheck")
    final_state = post_hash_state
    if pid_identity:
        verify_process_identity(pid_identity)

    if sha256_file(args.cli, MAX_CLI_BINARY_BYTES, "CLI binary") != cli_sha:
        raise MeasurementError("CLI binary changed during the measurement")
    if sha256_file(args.config, MAX_CONFIG_BYTES, "config file") != config_sha:
        raise MeasurementError("config file changed during the measurement")

    external = build_external_sample(
        external_start,
        end_state,
        args.start_height,
        end_height,
        args.poll_seconds,
        args.rpc_timeout,
    )
    if external_start and external_start.uptime > end_state.uptime:
        raise MeasurementError("node uptime decreased across the external sample")

    process_report = None
    if pid_identity and proc_start and proc_end:
        process_report = process_delta(proc_start, proc_end)
        process_report["pid"] = pid_identity.pid
        process_report["executable_sha256"] = pid_identity.exe_sha256

    payload = {
        "schema": "avila-live-ibd-receipts-v1",
        "experiment": "passive_full_validation_mainnet_receipt_window",
        "scope": {
            "start_height": args.start_height,
            "end_height": end_height,
            "count": args.count,
            "chain": "main",
            "assume_valid_checkpoint": None,
            "historical_scripts_required": True,
            "initialblockdownload": True,
            "consensus_or_connect_behavior_changed": False,
        },
        "provenance": {
            "cli_name": args.cli.name,
            "cli_sha256": cli_sha,
            "config_name": args.config.name,
            "config_sha256": config_sha,
            "rpc_addr": args.rpc_addr,
            "sampler": Path(__file__).name,
            "sampler_sha256": sha256_file(Path(__file__), MAX_CONFIG_BYTES, "sampler source"),
        },
        "observations": {
            "first_status": state_dict(first_observation),
            "window_end_status": state_dict(end_state),
            "post_collection_status": state_dict(final_state),
            "attached_late": late_attach,
        },
        "external_sample": external,
        "process_counters": process_report,
        "receipt_summary": summarize(receipts),
        "receipt_semantics": {
            "wall_ns": "serial connect-pass time; does not include deferred script-worker wait when enabled",
            "script_checks": "checks queued/performed; may still be in flight with a script worker pool",
            "verified_hits": "transactions skipped by the verified-script cache, not per-input script count",
            "delta_commitment": "commitment to the connected UTXO delta, not a UTXO-set hash or membership proof",
        },
        "receipts": receipts,
        "limitations": [
            "passive observation of ordinary node validation; no speedup comparison",
            "receipt times are not whole-chain IBD time or exact block-arrival timestamps",
            "the sample does not prove SwiftSync/Utreexo membership, temporal ordering, BIP30, or script validity beyond the node checks recorded",
            "process counters are emitted only when a matching node PID was supplied and verified",
            "without a node PID, RPC uptime detects observed decreases but cannot prove that a brief restart between polls did not occur",
        ],
    }
    return payload


def state_dict(state: NodeState | None) -> dict[str, Any] | None:
    if state is None:
        return None
    return {
        "connected_height": state.connected_height,
        "header_height": state.header_height,
        "bestblockhash": state.bestblockhash,
        "initialblockdownload": state.ibd,
        "uptime_seconds": state.uptime,
        "observed_at_utc": state.observed_at,
        "info_blocks": state.info_blocks,
        "historical_scripts_required": state.historical_scripts_required,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
        payload = json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode("utf-8") + b"\n"
        write_atomic_new(args.output, payload)
        summary = result["receipt_summary"]
        print(
            f"sampled {summary['blocks']} checked blocks "
            f"{result['scope']['start_height']}..{result['scope']['end_height']}; "
            f"AssumeValid disabled; output published atomically",
            file=sys.stderr,
        )
        return 0
    except MeasurementError as exc:
        print(f"measure_live_ibd: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
