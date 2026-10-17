"""Unit tests for the bounded passive IBD receipt sampler."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.measure_live_ibd import (
    MAX_WINDOW,
    AvilaCli,
    MeasurementError,
    NodeState,
    RpcCallError,
    build_external_sample,
    build_parser,
    collect_window,
    percentiles,
    run,
    validate_observation,
    validate_rpc_addr,
    validate_receipt_window,
    update_pre_window_observation,
    write_atomic_new,
)


def fake_state(height: int, *, mono: float = 10.0, uptime: int = 600) -> NodeState:
    return NodeState(
        connected_height=height,
        header_height=height,
        bestblockhash="a" * 64,
        chain="main",
        ibd=True,
        uptime=uptime,
        policy_checkpoint=None,
        historical_scripts_required=True,
        observed_at="2026-10-17T12:00:00.000Z",
        monotonic_at=mono,
        info_blocks=height,
    )


def receipt(height: int, digest: str | None = None) -> dict[str, object]:
    return {
        "height": height,
        "hash": digest or f"{height:064x}",
        "delta_commitment": "f" * 64,
        "checks_enabled": True,
        "script_flags": 0,
        "txs": 2,
        "sigops": 3,
        "script_checks": 4,
        "verified_hits": 0,
        "spent_coins": 5,
        "created_coins": 6,
        "wall_ns": height * 10,
        "fees": 7,
    }


class ValidateObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.info = {
            "chain": "main",
            "blocks": 10,
            "headers": 20,
            "bestblockhash": "a" * 64,
            "initialblockdownload": True,
        }
        self.report = {
            "connected_height": 10,
            "header_height": 20,
            "validation_policy": {
                "assume_valid_checkpoint": None,
                "historical_scripts_required": True,
            },
        }

    def test_full_validation_policy_is_required(self) -> None:
        state = validate_observation(self.info, self.report, 100)
        self.assertEqual(state.connected_height, 10)
        self.assertTrue(state.historical_scripts_required)

    def test_rejects_wrong_network_assumevalid_or_disabled_scripts(self) -> None:
        for mutate in (
            lambda info, report: info.update(chain="test"),
            lambda info, report: report["validation_policy"].update(assume_valid_checkpoint="00"),
            lambda info, report: report["validation_policy"].update(historical_scripts_required=False),
            lambda info, report: info.update(initialblockdownload=False),
            lambda info, report: report["validation_policy"].pop("assume_valid_checkpoint"),
        ):
            info = dict(self.info)
            report = {**self.report, "validation_policy": dict(self.report["validation_policy"])}
            mutate(info, report)
            with self.assertRaises(MeasurementError):
                validate_observation(info, report, 100)


class ReceiptWindowTests(unittest.TestCase):
    def test_orders_receipts_and_matches_active_hashes(self) -> None:
        rows = [receipt(12), receipt(10), receipt(11)]
        active = lambda height: f"{height:064x}"
        result = validate_receipt_window(rows, 10, 3, active)
        self.assertEqual([row["height"] for row in result], [10, 11, 12])

    def test_rejects_missing_duplicate_wrong_hash_and_disabled_checks(self) -> None:
        active = lambda height: f"{height:064x}"
        with self.assertRaisesRegex(MeasurementError, "missing"):
            validate_receipt_window([receipt(10)], 10, 2, active)
        with self.assertRaisesRegex(MeasurementError, "duplicate"):
            validate_receipt_window([receipt(10), receipt(10), receipt(11)], 10, 2, active)
        with self.assertRaisesRegex(MeasurementError, "active chain"):
            validate_receipt_window([receipt(10, "b" * 64)], 10, 1, active)
        disabled = receipt(10)
        disabled["checks_enabled"] = False
        with self.assertRaisesRegex(MeasurementError, "disabled"):
            validate_receipt_window([disabled], 10, 1, active)

    def test_collection_uses_one_ring_snapshot_and_fails_if_evicted(self) -> None:
        class FakeClient:
            def __init__(self, rows: list[dict[str, object]]) -> None:
                self.rows = rows
                self.calls: list[tuple[str, object]] = []

            def call(self, method: str, *params: object) -> object:
                self.calls.append((method, params[0] if params else None))
                if method == "getblockreceipts":
                    return self.rows
                if method == "getblockhash":
                    return f"{int(params[0]):064x}"
                raise AssertionError(f"unexpected RPC method {method}")

        client = FakeClient([receipt(11), receipt(10)])
        result = collect_window(client, 10, 2, 11)  # type: ignore[arg-type]
        self.assertEqual([row["height"] for row in result], [10, 11])
        self.assertEqual(client.calls[0], ("getblockreceipts", 2016))
        self.assertEqual(sum(method == "getblockreceipts" for method, _ in client.calls), 1)

        evicted = FakeClient([receipt(11)])
        with self.assertRaisesRegex(MeasurementError, "missing"):
            collect_window(evicted, 10, 2, 11)  # type: ignore[arg-type]


class CliTransportTests(unittest.TestCase):
    def test_raw_hash_and_json_results_use_real_bounded_subprocess_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cli = directory / "fake-avila-cli"
            config = directory / "node.toml"
            config.write_text("# test fixture\n", encoding="utf-8")
            cli.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "method_index = args.index('rpc') + 1\n"
                "method = args[method_index]\n"
                "if method == 'getblockhash':\n"
                "    sys.stdout.write(('xyz' if args[method_index + 1] == '\"bad\"' else '" + "a" * 64 + "') + '\\n')\n"
                "elif method == 'uptime':\n"
                "    print(json.dumps(123))\n"
                "elif method == 'getblockchaininfo':\n"
                "    print(json.dumps({'chain': 'main'}))\n"
                "else:\n"
                "    sys.stdout.write('not-json\\n')\n",
                encoding="utf-8",
            )
            cli.chmod(0o755)
            client = AvilaCli(cli, config, "127.0.0.1:18443", timeout=2)
            self.assertEqual(client.call("getblockhash", 1), "a" * 64)
            self.assertEqual(client.call("uptime"), 123)
            self.assertEqual(client.call("getblockchaininfo"), {"chain": "main"})
            with self.assertRaisesRegex(RpcCallError, "invalid JSON"):
                client.call("malformed")
            with self.assertRaisesRegex(RpcCallError, "invalid hash"):
                client.call("getblockhash", "bad")


class WindowAndTimingTests(unittest.TestCase):
    def test_parser_default_and_bound(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--cli", "node", "--config", "node.toml", "--output", "result.json"])
        self.assertEqual(args.start_height, 600_000)
        self.assertEqual(args.count, MAX_WINDOW)
        with self.assertRaises(MeasurementError):
            from tools.measure_live_ibd import validate_args

            args.count = MAX_WINDOW + 1
            validate_args(args)

    def test_rpc_endpoint_must_be_numeric_loopback(self) -> None:
        validate_rpc_addr("127.0.0.1:18443")
        validate_rpc_addr("[::1]:18443")
        for endpoint in ("example.com:18443", "0.0.0.0:18443", "127.0.0.1:0", "127.0.0.1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(MeasurementError):
                validate_rpc_addr(endpoint)

    def test_late_attach_has_no_claimed_external_window(self) -> None:
        sample = build_external_sample(None, fake_state(600_127), 600_000, 600_127, 5, 15)
        self.assertFalse(sample["available"])
        self.assertIn("at or above", sample["reason"])

    def test_external_timing_uses_enclosing_height_delta(self) -> None:
        sample = build_external_sample(fake_state(7, mono=2), fake_state(13, mono=8), 10, 11, 0.5, 2)
        self.assertEqual(sample["sampled_elapsed_seconds"], 6)
        self.assertEqual(sample["observed_advanced_checked_blocks"], 6)
        self.assertEqual(sample["observed_checked_blocks_per_second"], 1.0)
        self.assertEqual(sample["prefix_blocks_before_target"], 2)
        self.assertEqual(sample["suffix_blocks_after_target"], 2)
        self.assertTrue(sample["interval_encloses_target_window"])
        self.assertFalse(sample["exact_target_height_endpoints"])
        self.assertEqual(sample["endpoint_overshoot_blocks"], 2)
        self.assertFalse(sample["exact_target_endpoint_observed"])
        self.assertEqual(sample["status_observation_uncertainty_allowance_seconds"], 21)
        self.assertIn("does not bound target-only", sample["boundary_note"])

    def test_exact_height_endpoints_are_explicitly_labeled(self) -> None:
        sample = build_external_sample(fake_state(9, mono=2), fake_state(11, mono=8), 10, 11, 1, 3)
        self.assertTrue(sample["exact_target_height_endpoints"])
        self.assertEqual(sample["observed_advanced_checked_blocks"], 2)

    def test_run_loop_baseline_tracks_latest_pre_window_status(self) -> None:
        baseline = None
        late_attach = False
        for height in (100, 104, 108):
            baseline, late_attach, refreshed = update_pre_window_observation(
                fake_state(height), 110, baseline, late_attach
            )
            self.assertTrue(refreshed)
            self.assertFalse(late_attach)
        self.assertEqual(baseline.connected_height, 108)  # type: ignore[union-attr]

        baseline, late_attach, refreshed = update_pre_window_observation(
            fake_state(112), 110, baseline, late_attach
        )
        self.assertEqual(baseline.connected_height, 108)  # type: ignore[union-attr]
        self.assertFalse(late_attach)
        self.assertFalse(refreshed)

        missing, late, refreshed = update_pre_window_observation(fake_state(110), 110, None, False)
        self.assertIsNone(missing)
        self.assertTrue(late)
        self.assertFalse(refreshed)

    def test_run_retries_busy_continuity_hash_and_keeps_latest_baseline(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.hash_calls: list[int] = []
                self.busy_once = True

            def call(self, method: str, *params: object) -> object:
                if method == "getblockhash":
                    height = int(params[0])
                    self.hash_calls.append(height)
                    if height == 8 and self.busy_once:
                        self.busy_once = False
                        raise RpcCallError("temporary busy response")
                    return f"{height:064x}" if height >= 10 else "a" * 64
                if method == "getblockreceipts":
                    return [receipt(10), receipt(11)]
                raise AssertionError(f"unexpected RPC method {method}")

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cli = directory / "fake-avila-cli"
            config = directory / "node.toml"
            output = directory / "result.json"
            cli.write_text("test executable", encoding="utf-8")
            cli.chmod(0o755)
            config.write_text("test config", encoding="utf-8")
            args = build_parser().parse_args(
                [
                    "--cli", str(cli), "--config", str(config), "--output", str(output),
                    "--start-height", "10", "--count", "2", "--wait-seconds", "30",
                    "--poll-seconds", "0.25", "--rpc-timeout", "1",
                ]
            )
            client = FakeClient()
            observations = iter(
                [
                    fake_state(8, mono=10),
                    fake_state(9, mono=11),  # discarded: continuity RPC is transiently busy
                    fake_state(9, mono=12),  # successful retry becomes the pre-window baseline
                    fake_state(11, mono=13),
                    fake_state(11, mono=14),
                    fake_state(11, mono=15),
                ]
            )
            with (
                patch("tools.measure_live_ibd.AvilaCli", return_value=client),
                patch("tools.measure_live_ibd.read_state", side_effect=lambda _client: next(observations)),
                patch("tools.measure_live_ibd.time.sleep"),
            ):
                result = run(args)

            self.assertEqual(result["observations"]["first_status"]["connected_height"], 8)
            self.assertEqual(result["external_sample"]["observed_connected_height_start"], 9)
            self.assertTrue(result["external_sample"]["interval_encloses_target_window"])
            self.assertEqual(client.hash_calls.count(8), 2)

    def test_run_does_not_retry_wrong_continuity_hash(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.hash_calls = 0

            def call(self, method: str, *params: object) -> object:
                if method == "getblockhash":
                    self.hash_calls += 1
                    return "b" * 64
                raise AssertionError(f"unexpected RPC method {method}")

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cli = directory / "fake-avila-cli"
            config = directory / "node.toml"
            cli.write_text("test executable", encoding="utf-8")
            cli.chmod(0o755)
            config.write_text("test config", encoding="utf-8")
            args = build_parser().parse_args(
                [
                    "--cli", str(cli), "--config", str(config), "--output", str(directory / "result.json"),
                    "--start-height", "10", "--count", "2", "--wait-seconds", "30",
                    "--poll-seconds", "0.25", "--rpc-timeout", "1",
                ]
            )
            client = FakeClient()
            observations = iter([fake_state(8, mono=10), fake_state(9, mono=11)])
            with (
                patch("tools.measure_live_ibd.AvilaCli", return_value=client),
                patch("tools.measure_live_ibd.read_state", side_effect=lambda _client: next(observations)),
                patch("tools.measure_live_ibd.time.sleep"),
                self.assertRaisesRegex(MeasurementError, "active chain changed below"),
            ):
                run(args)
            self.assertEqual(client.hash_calls, 1)

    def test_run_detects_restart_before_retrying_continuity_hash(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.hash_calls = 0

            def call(self, method: str, *params: object) -> object:
                if method == "getblockhash":
                    self.hash_calls += 1
                    raise RpcCallError("temporary busy response")
                raise AssertionError(f"unexpected RPC method {method}")

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cli = directory / "fake-avila-cli"
            config = directory / "node.toml"
            cli.write_text("test executable", encoding="utf-8")
            cli.chmod(0o755)
            config.write_text("test config", encoding="utf-8")
            args = build_parser().parse_args(
                [
                    "--cli", str(cli), "--config", str(config), "--output", str(directory / "result.json"),
                    "--start-height", "10", "--count", "2", "--wait-seconds", "30",
                    "--poll-seconds", "0.25", "--rpc-timeout", "1",
                ]
            )
            client = FakeClient()
            observations = iter(
                [fake_state(8, mono=10, uptime=600), fake_state(9, mono=11, uptime=599)]
            )
            with (
                patch("tools.measure_live_ibd.AvilaCli", return_value=client),
                patch("tools.measure_live_ibd.read_state", side_effect=lambda _client: next(observations)),
                patch("tools.measure_live_ibd.time.sleep"),
                self.assertRaisesRegex(MeasurementError, "uptime decreased"),
            ):
                run(args)
            self.assertEqual(client.hash_calls, 0)

    def test_serial_timing_percentiles(self) -> None:
        self.assertEqual(percentiles([10, 20, 30, 40]), {"median": 25.0, "p95": 40, "min": 10, "max": 40})

    def test_atomic_output_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "receipt.json"
            write_atomic_new(output, b"{}\n")
            self.assertEqual(output.read_bytes(), b"{}\n")
            with self.assertRaisesRegex(MeasurementError, "already exists"):
                write_atomic_new(output, b"changed")


if __name__ == "__main__":
    unittest.main()
