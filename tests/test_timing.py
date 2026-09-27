"""
test_timing.py

Regression tests for how container lifetime and poller snapshot age
are measured. These run without Docker: every call that would reach
the daemon is replaced with a fake that returns a known answer.

Run from the code/ folder with:
    python -m unittest discover tests
"""

import datetime
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import capture  # noqa: E402
import listener  # noqa: E402
import poller  # noqa: E402


def docker_ts(epoch):
    """Format an epoch time the way Docker does: RFC3339, nanoseconds, Z."""
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


class ParseDockerTimestampTests(unittest.TestCase):
    def test_nanosecond_precision_is_truncated_to_microseconds(self):
        dt = capture.parse_docker_timestamp("2026-08-11T11:50:07.234855127Z")
        self.assertEqual(dt.microsecond, 234855)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_short_fraction_is_padded(self):
        # Go drops trailing zeros, so '.23' means 230000 microseconds.
        dt = capture.parse_docker_timestamp("2026-08-11T11:50:07.23Z")
        self.assertEqual(dt.microsecond, 230000)

    def test_no_fraction(self):
        dt = capture.parse_docker_timestamp("2026-08-11T11:50:07Z")
        self.assertEqual(dt.second, 7)

    def test_numeric_utc_offset_is_honoured(self):
        local = capture.parse_docker_timestamp("2026-08-11T17:35:07.5+05:45")
        utc = capture.parse_docker_timestamp("2026-08-11T11:50:07.5Z")
        self.assertEqual(local.timestamp(), utc.timestamp())

    def test_garbage_raises_value_error(self):
        with self.assertRaises(ValueError):
            capture.parse_docker_timestamp("not a timestamp")


class DaemonClockOffsetTests(unittest.TestCase):
    def test_measures_known_offset_within_reported_uncertainty(self):
        true_offset = 2.5  # daemon clock runs 2.5s ahead of the host

        class FakeClient:
            def info(self):
                return {"SystemTime": docker_ts(time.time() + true_offset)}

        with mock.patch.object(capture, "get_client", return_value=FakeClient()):
            result = capture.measure_daemon_clock_offset()

        self.assertNotIn("error", result)
        # Allow 1us on top of the round-trip bound for the microsecond
        # truncation in parse_docker_timestamp.
        self.assertLessEqual(
            abs(result["offset_seconds"] - true_offset),
            result["uncertainty_seconds"] + 1e-6,
        )

    def test_unreachable_daemon_reports_error_instead_of_raising(self):
        class BrokenClient:
            def info(self):
                raise ConnectionError("daemon gone")

        with mock.patch.object(capture, "get_client", return_value=BrokenClient()):
            result = capture.measure_daemon_clock_offset()
        self.assertIn("error", result)


class ReconstructTimingTests(unittest.TestCase):
    # Daemon-clock timeline, matching what Docker Desktop actually does:
    # started at S, SIGKILL at S+0.400, process exits (FinishedAt) at
    # S+0.401, and the die event only fires ~0.28s later at S+0.681.
    S = 1_786_449_007.234855
    OFFSET = {"offset_seconds": 2.0, "uncertainty_seconds": 0.001}  # host 2s behind

    def _run(self, finished_at_raw, sigkill_ns, offset=OFFSET):
        with mock.patch.object(listener, "measure_daemon_clock_offset", return_value=offset):
            return listener._reconstruct_timing(
                started_at_raw=docker_ts(self.S),
                finished_at_raw=finished_at_raw,
                sigkill_event_time_ns=sigkill_ns,
                die_event_time_ns=int((self.S + 0.681) * 1e9),
                # die handler got to it 20ms after the die event (host clock)
                die_handled_at=self.S + 0.681 - 2.0 + 0.020,
            )

    def test_death_is_finished_at_not_the_late_die_event(self):
        lifetime, timing = self._run(docker_ts(self.S + 0.401), int((self.S + 0.400) * 1e9))
        self.assertAlmostEqual(lifetime, 0.401, places=5)
        self.assertIn("FinishedAt", timing["death_time_source"])
        self.assertAlmostEqual(timing["death_time_host_clock"], self.S + 0.401 - 2.0, places=5)
        self.assertAlmostEqual(timing["exit_to_die_event_seconds"], 0.280, places=5)
        self.assertAlmostEqual(timing["die_handling_lag_seconds"], 0.020, places=5)

    def test_removed_container_falls_back_to_sigkill_event(self):
        lifetime, timing = self._run({"error": "No such container"}, int((self.S + 0.400) * 1e9))
        self.assertAlmostEqual(lifetime, 0.400, places=5)
        self.assertIn("SIGKILL", timing["death_time_source"])

    def test_no_finished_at_or_sigkill_uses_die_event_and_says_so(self):
        lifetime, timing = self._run({"error": "No such container"}, None)
        self.assertAlmostEqual(lifetime, 0.681, places=5)
        self.assertIn("FALLBACK", timing["death_time_source"])

    def test_offset_failure_keeps_lifetime_but_flags_ages(self):
        lifetime, timing = self._run(docker_ts(self.S + 0.401), None, offset={"error": "daemon gone"})
        # Lifetime is daemon-clock only, so it doesn't need the offset.
        self.assertAlmostEqual(lifetime, 0.401, places=5)
        self.assertIn("FALLBACK", timing["death_time_host_clock_source"])
        self.assertIsNone(timing["die_handling_lag_seconds"])

    def test_missing_started_at_is_reported_not_guessed(self):
        with mock.patch.object(listener, "measure_daemon_clock_offset", return_value=self.OFFSET):
            lifetime, timing = listener._reconstruct_timing(
                {"error": "no such container"}, docker_ts(self.S), None, int(self.S * 1e9), self.S,
            )
        self.assertIsNone(lifetime)
        self.assertIn("lifetime_unavailable_reason", timing)


class HandleKillSignalTests(unittest.TestCase):
    def test_docker_stop_records_the_later_sigkill_without_recapturing(self):
        cid = "d" * 64
        self.addCleanup(listener._pending_live_capture.pop, cid, None)
        with mock.patch.object(listener, "capture_network_state", return_value={}) as net, \
             mock.patch.object(listener, "capture_process_list", return_value={}), \
             mock.patch.object(listener, "get_container_started_at", return_value="x"):
            listener.handle_kill(cid, "graceful", 1_000_000_000, "15")   # SIGTERM
            listener.handle_kill(cid, "graceful", 11_000_000_000, "9")   # SIGKILL after grace
        self.assertEqual(net.call_count, 1)
        self.assertEqual(listener._pending_live_capture[cid]["sigkill_event_time_ns"], 11_000_000_000)

    def test_started_at_is_read_before_the_slow_live_captures(self):
        # A --rm container is gone ~0.3s after SIGKILL -- about as long as
        # the failed live captures take -- so StartedAt must be read first.
        cid, calls = "e" * 64, []
        self.addCleanup(listener._pending_live_capture.pop, cid, None)
        with mock.patch.object(listener, "get_container_started_at",
                               side_effect=lambda _: calls.append("started_at") or "x"), \
             mock.patch.object(listener, "capture_network_state",
                               side_effect=lambda _: calls.append("network") or {}), \
             mock.patch.object(listener, "capture_process_list",
                               side_effect=lambda _: calls.append("process") or {}):
            listener.handle_kill(cid, "rm_container", 1, "9")
        self.assertEqual(calls[0], "started_at")


class HandleKillThenDieRegressionTest(unittest.TestCase):
    """Replays the timeline that produced inflated numbers, as measured
    on Docker Desktop: SIGKILL, process exits within 1ms, but the die
    event only arrives ~0.3s later. Before the fix, lifetime and
    snapshot age were both measured from whenever handle_die ran, so
    both came out ~0.3s too large."""

    def test_late_die_event_does_not_leak_into_measurements(self):
        cid, name = "c" * 64, "rescuetest_regress"
        now = time.time()
        started = now - 1.0
        died = now - 0.30          # real exit, 0.3s before the die handler runs
        net_snapshot_at = now - 0.60
        proc_snapshot_at = now - 0.59

        poller._latest_snapshot[cid] = {
            "network_state": {"method": "exec_fallback", "latency_seconds": 0.03, "data": "sl local_address"},
            "network_state_snapshot_at": net_snapshot_at,
            "process_list": {"Titles": ["PID"], "Processes": [["1"]]},
            "process_list_snapshot_at": proc_snapshot_at,
        }
        saved = []
        dead = {"error": '409 Conflict ("container is not running")'}
        patches = [
            mock.patch.object(listener, "capture_network_state",
                              return_value={"method": "exec_fallback", "data": dead}),
            mock.patch.object(listener, "capture_process_list", return_value=dead),
            mock.patch.object(listener, "get_container_started_at", return_value=docker_ts(started)),
            mock.patch.object(listener, "get_container_finished_at", return_value=docker_ts(died)),
            mock.patch.object(listener, "capture_filesystem_diff",
                              return_value=[{"Path": "/tmp/test.txt", "Kind": 1}]),
            mock.patch.object(listener, "capture_logs", return_value=""),
            mock.patch.object(listener, "measure_daemon_clock_offset",
                              return_value={"offset_seconds": 0.0, "uncertainty_seconds": 0.0005}),
            mock.patch.object(listener, "save_evidence", side_effect=saved.append),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        listener.handle_kill(cid, name, int((died - 0.001) * 1e9), "9")
        listener.handle_die(cid, name, int((died + 0.28) * 1e9))

        (evidence,) = saved
        self.assertAlmostEqual(evidence["container_lifetime_seconds"], died - started, places=4)
        self.assertEqual(evidence["network_state"]["source"], "poller_snapshot")
        self.assertAlmostEqual(evidence["network_state"]["snapshot_age_seconds"],
                               died - net_snapshot_at, places=4)
        self.assertAlmostEqual(evidence["process_list"]["snapshot_age_seconds"],
                               died - proc_snapshot_at, places=4)
        self.assertAlmostEqual(evidence["timing"]["exit_to_die_event_seconds"], 0.28, places=4)
        # When the kill-trigger capture actually started (host clock), so
        # the GUI can place it without assuming it began at SIGKILL.
        self.assertIsInstance(evidence["live_kill_trigger_started_at"], float)

        without_hash = {k: v for k, v in evidence.items() if k != "sha256"}
        self.assertEqual(evidence["sha256"], capture.hash_evidence(without_hash))


if __name__ == "__main__":
    unittest.main()
