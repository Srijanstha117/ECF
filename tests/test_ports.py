"""
test_ports.py

Tests for port tracking: parsing the kernel's socket tables, and the
poller's record of when each port or connection was open. No Docker
needed.

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

TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
UDP_HEADER = TCP_HEADER + " ref pointer drops"

SAMPLE = "\n".join([
    "### tcp",
    TCP_HEADER,
    # 0.0.0.0:8080 listening
    "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0",
    # 127.0.0.1:8080 <-> 127.0.0.1:54321 established
    "   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 20 4 30 10 -1",
    "   2: this line is garbage and must be skipped",
    "### tcp6",
    TCP_HEADER,
    # [::]:80 listening
    "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0",
    "### udp",
    UDP_HEADER,
    # 0.0.0.0:53 bound
    "  123: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 44444 2 0000000000000000 0",
    "### udp6",
    UDP_HEADER,
])


class ParseProcNetTests(unittest.TestCase):
    def setUp(self):
        self.sockets = capture.parse_proc_net(SAMPLE)

    def test_every_valid_line_is_parsed_and_garbage_skipped(self):
        self.assertEqual(len(self.sockets), 4)

    def test_ipv4_listening_port(self):
        s = self.sockets[0]
        self.assertEqual((s["proto"], s["local_ip"], s["local_port"], s["state"], s["kind"]),
                         ("tcp", "0.0.0.0", 8080, "LISTEN", "listening"))

    def test_ipv4_connection_decodes_little_endian_address(self):
        s = self.sockets[1]
        self.assertEqual((s["local_ip"], s["remote_ip"], s["remote_port"], s["state"], s["kind"]),
                         ("127.0.0.1", "127.0.0.1", 54321, "ESTABLISHED", "connection"))

    def test_ipv6_listening_port(self):
        s = self.sockets[2]
        self.assertEqual((s["proto"], s["local_ip"], s["local_port"], s["kind"]), ("tcp6", "::", 80, "listening"))

    def test_udp_bound_counts_as_listening(self):
        s = self.sockets[3]
        self.assertEqual((s["proto"], s["local_port"], s["state"], s["kind"]), ("udp", 53, "BOUND", "listening"))

    def test_ipv4_mapped_ipv6_is_shown_as_ipv4(self):
        self.assertEqual(capture._hex_ip("0000000000000000FFFF00000100007F"), "127.0.0.1")

    def test_text_without_table_markers_yields_nothing(self):
        # Pre-2026-09-26 evidence stored bare /proc/net/tcp text; it isn't
        # guessed at -- those packages keep only their raw text.
        self.assertEqual(capture.parse_proc_net(SAMPLE.replace("### ", "")), [])


def listen(port):
    return {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": port, "remote_ip": "0.0.0.0",
            "remote_port": 0, "state": "LISTEN", "kind": "listening"}


class PortHistoryTests(unittest.TestCase):
    CID = "p" * 64

    def setUp(self):
        poller._port_history.pop(self.CID, None)
        self.addCleanup(poller._port_history.pop, self.CID, None)
        # Polls at t=100, 100.5, 101, 101.5 (host clock). Port 8080 is
        # seen at 100.5 and 101 only; 9090 appears at 101.5 and is still
        # open when the container dies.
        for t, socks in [(100.0, []), (100.5, [listen(8080)]), (101.0, [listen(8080)]), (101.5, [listen(9090)])]:
            poller._update_port_history(self.CID, socks, t)
        self.history = poller._finish_port_history(poller._port_history.pop(self.CID))

    def test_windows_around_each_change(self):
        closed, still_open = self.history["sockets"]
        self.assertEqual((closed["local_port"], closed["not_seen_at"], closed["first_seen_at"],
                          closed["last_seen_at"], closed["gone_at"]), (8080, 100.0, 100.5, 101.0, 101.5))
        self.assertEqual((still_open["local_port"], still_open["not_seen_at"], still_open["gone_at"]),
                         (9090, 101.0, None))
        self.assertEqual(self.history["polls"], 4)

    def test_timeline_in_seconds_since_start(self):
        # Container started at host time 99.8 and died at 101.8 (lifetime 2.0).
        timeline = listener._port_timeline(self.history, lifetime=2.0, death_time_host=101.8)
        closed, still_open = timeline["sockets"]
        self.assertAlmostEqual(closed["opened_after_s"], 0.2)
        self.assertAlmostEqual(closed["first_seen_s"], 0.7)
        self.assertAlmostEqual(closed["last_seen_s"], 1.2)
        self.assertAlmostEqual(closed["closed_by_s"], 1.7)
        self.assertFalse(closed["open_at_exit"])
        self.assertTrue(still_open["open_at_exit"])
        self.assertAlmostEqual(still_open["closed_by_s"], 2.0)  # ended with the container

    def test_socket_present_at_first_poll_opened_after_start(self):
        poller._update_port_history(self.CID, [listen(22)], 200.0)
        history = poller._finish_port_history(poller._port_history.pop(self.CID))
        (sock,) = listener._port_timeline(history, lifetime=1.0, death_time_host=200.5)["sockets"]
        self.assertIsNone(sock["not_seen_at"])
        self.assertEqual(sock["opened_after_s"], 0.0)

    def test_unknown_death_time_keeps_raw_times_only(self):
        timeline = listener._port_timeline(self.history, lifetime=None, death_time_host=None)
        self.assertIsNone(timeline["sockets"][0]["first_seen_s"])
        self.assertEqual(timeline["sockets"][0]["first_seen_at"], 100.5)

    def test_no_history_says_so(self):
        self.assertIn("error", listener._port_timeline(None, 1.0, 100.0))


class FilesystemDiffTests(unittest.TestCase):
    def test_no_changes_is_an_empty_list_not_a_failure(self):
        from unittest import mock

        class FakeAPI:
            def diff(self, _):
                return None  # what Docker returns when nothing changed

        class FakeClient:
            api = FakeAPI()

        with mock.patch.object(capture, "get_client", return_value=FakeClient()):
            result = capture.capture_filesystem_diff("x")
        self.assertEqual(result, [])
        self.assertFalse(capture.is_failure(result))


class TerminationTests(unittest.TestCase):
    def test_docker_kill(self):
        t = listener._termination("9", 5_000, 5_000, "137")
        self.assertEqual((t["verdict"], t["label"], t["exit_code"]), ("killed", "Killed", 137))

    def test_docker_stop_graceful(self):
        t = listener._termination("15", None, 5_000, "0")
        self.assertEqual((t["verdict"], t["label"], t["sigkill_sent"]), ("stopped", "Stopped", False))

    def test_docker_stop_timed_out(self):
        t = listener._termination("15", 2_000_000_000 + 5_000, 5_000, "137")
        self.assertEqual(t["verdict"], "stopped_then_killed")
        self.assertIn("2.0 s later", t["detail"])

    def test_exited_on_its_own(self):
        self.assertEqual(listener._termination(None, None, None, "0")["label"], "Exited on its own")
        self.assertEqual(listener._termination(None, None, None, "3")["label"], "Exited on its own with an error")


class SaveEvidenceTests(unittest.TestCase):
    def test_same_name_and_second_never_overwrites(self):
        import json
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(listener, "EVIDENCE_DIR", tmp):
            first = listener.save_evidence({"container_name": "dup", "captured_at": 1.2, "who": "first"})
            second = listener.save_evidence({"container_name": "dup", "captured_at": 1.7, "who": "second"})
            self.assertNotEqual(first, second)
            for path, who in ((first, "first"), (second, "second")):
                with open(path) as f:
                    self.assertEqual(json.load(f)["who"], who)
            # no temp files left behind
            self.assertEqual(sorted(os.listdir(tmp)), ["dup_1.json", "dup_1_1.json"])


if __name__ == "__main__":
    unittest.main()
