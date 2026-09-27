"""
test_resources.py

CPU / memory / network sampling: the CPU % maths, the poller's history
(and how it thins when long), and the timeline saved as evidence.
No Docker needed.

Run from the code/ folder with:
    python -m unittest discover tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import capture  # noqa: E402
import listener  # noqa: E402
import poller  # noqa: E402


def counters(cpu_ns, sys_ns, rx=0, tx=0, mem=50_000_000, cpus=4):
    return {"cpu_total_ns": cpu_ns, "system_cpu_ns": sys_ns, "online_cpus": cpus,
            "mem_bytes": mem, "mem_limit_bytes": 1_000_000_000, "rx_bytes": rx, "tx_bytes": tx, "pids": 3}


class ResourceDeltaTests(unittest.TestCase):
    def test_one_busy_core_of_four_is_100_percent(self):
        # System time counts all 4 cores: in 1 s it advances 4e9 ns. One core
        # fully busy uses 1e9 of those -> 25% of the machine = 100% of a core.
        d = capture.resource_delta(counters(0, 0), counters(1_000_000_000, 4_000_000_000), 1.0)
        self.assertAlmostEqual(d["cpu_pct"], 100.0)

    def test_network_rates_are_bytes_per_second(self):
        d = capture.resource_delta(counters(0, 0, rx=1000, tx=0), counters(0, 1, rx=3000, tx=500), 0.5)
        self.assertEqual((d["rx_rate"], d["tx_rate"]), (4000.0, 1000.0))

    def test_first_reading_has_no_delta(self):
        self.assertIsNone(capture.resource_delta(None, counters(1, 1), 0.5))

    def test_counter_reset_does_not_go_negative(self):
        d = capture.resource_delta(counters(5, 5, rx=900), counters(1, 10, rx=100), 1.0)
        self.assertEqual((d["cpu_pct"], d["rx_rate"]), (0.0, 0.0))


class ResourceHistoryTests(unittest.TestCase):
    CID = "r" * 64

    def setUp(self):
        poller._resources.pop(self.CID, None)
        self.addCleanup(poller._resources.pop, self.CID, None)

    def test_history_and_live_figures(self):
        poller._running_ids = {self.CID}
        for i in range(4):
            poller._record_resources(self.CID, "web", counters(i * 500_000_000, i * 2_000_000_000, rx=i * 100), 100 + i * 0.5)
        history = poller._resources[self.CID]
        self.assertEqual(len(history["samples"]), 3)  # the first reading only anchors
        (live,) = [x for x in poller.live_resources() if x["name"] == "web"]
        self.assertAlmostEqual(live["cpu_pct"], 100.0)
        self.assertEqual(live["rx_rate"], 200.0)

    def test_long_history_is_thinned_not_truncated(self):
        for i in range(poller._MAX_RESOURCE_SAMPLES + 2):
            poller._record_resources(self.CID, "long", counters(i, i), float(i))
        history = poller._resources[self.CID]
        self.assertLessEqual(len(history["samples"]), poller._MAX_RESOURCE_SAMPLES)
        self.assertEqual(history["thinned"], 2)
        self.assertEqual(history["samples"][0]["at"], 1.0)  # still starts at the beginning


class ResourceTimelineTests(unittest.TestCase):
    def test_timeline_times_peaks_and_totals(self):
        samples = [
            {"at": 100.5, "cpu_pct": 10.0, "mem_bytes": 5, "rx_bytes": 10, "tx_bytes": 1, "rx_rate": 0, "tx_rate": 0},
            {"at": 101.0, "cpu_pct": 90.0, "mem_bytes": 9, "rx_bytes": 30, "tx_bytes": 4, "rx_rate": 40, "tx_rate": 6},
        ]
        t = listener._resource_timeline({"samples": samples, "mem_limit_bytes": 100}, lifetime=2.0, death_time_host=101.5)
        self.assertEqual([x["t_s"] for x in t["samples"]], [1.0, 1.5])
        self.assertEqual((t["peak_cpu_pct"], t["avg_cpu_pct"], t["peak_mem_bytes"]), (90.0, 50.0, 9))
        self.assertEqual((t["total_rx_bytes"], t["total_tx_bytes"]), (30, 4))

    def test_no_samples_says_so(self):
        self.assertIn("error", listener._resource_timeline(None, 1.0, 100.0))


if __name__ == "__main__":
    unittest.main()
