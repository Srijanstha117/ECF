"""
test_status.py

The listener's heartbeat, its refusal to run twice, and the dashboard's
"Listener running / not running" reading of it. No Docker needed.

Run from the code/ folder with:
    python -m unittest discover tests
"""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, "..", "gui"))

import listener  # noqa: E402
import app as dashboard  # noqa: E402


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, ".listener.json")
        patches = [
            mock.patch.object(listener, "HEARTBEAT_PATH", self.path),
            mock.patch.object(dashboard, "EVIDENCE_DIR", self.tmp.name),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write(self, **fields):
        with open(self.path, "w") as f:
            json.dump(fields, f)

    def test_written_heartbeat_reads_as_running(self):
        listener._write_heartbeat("running")
        status = dashboard.listener_status()
        self.assertEqual(status["state"], "running")
        self.assertIn("watching", status["sub"])

    def test_clean_stop_reads_as_stopped(self):
        listener._write_heartbeat("stopped")
        self.assertEqual(dashboard.listener_status()["state"], "stopped")

    def test_stale_heartbeat_reads_as_not_running(self):
        # A listener whose window was closed never writes "stopped"; its
        # heartbeat just goes stale.
        self.write(state="running", pid=1, last_beat=time.time() - 120)
        status = dashboard.listener_status()
        self.assertEqual((status["state"], status["sub"]), ("stale", "last seen 2 min ago"))

    def test_no_heartbeat_file(self):
        self.assertEqual(dashboard.listener_status()["state"], "never")

    def test_second_listener_detects_a_live_one(self):
        self.write(state="running", pid=os.getpid() + 1, last_beat=time.time())
        self.assertIsNotNone(listener.other_listener_running())

    def test_stale_or_own_heartbeat_does_not_block(self):
        self.write(state="running", pid=os.getpid() + 1, last_beat=time.time() - 30)
        self.assertIsNone(listener.other_listener_running())
        self.write(state="running", pid=os.getpid(), last_beat=time.time())
        self.assertIsNone(listener.other_listener_running())

    def test_heartbeat_is_not_listed_as_evidence(self):
        listener._write_heartbeat("running")
        self.assertEqual(dashboard.load_all_evidence(), [])

    def test_waiting_for_docker_counts_as_alive(self):
        self.write(state="waiting_docker", pid=os.getpid() + 1, last_beat=time.time())
        self.assertEqual(dashboard.listener_status()["state"], "waiting")
        self.assertIsNotNone(listener.other_listener_running())

    def test_dashboard_does_not_start_a_second_listener(self):
        listener._write_heartbeat("running")
        with mock.patch("subprocess.Popen") as popen:
            started, message = dashboard.start_listener()
        self.assertEqual((started, message), (False, "already running"))
        popen.assert_not_called()

    def test_dashboard_starts_listener_when_none_running(self):
        self.write(state="running", pid=1, last_beat=time.time() - 300)  # stale
        with mock.patch.dict(dashboard._last_launch, {"at": 0.0}), mock.patch("subprocess.Popen") as popen:
            started, _ = dashboard.start_listener()
            again, message = dashboard.start_listener()  # before its first heartbeat
        self.assertTrue(started)
        self.assertEqual((again, message), (False, "starting"))
        self.assertEqual(popen.call_count, 1)
        self.assertTrue(popen.call_args.args[0][1].endswith("listener.py"))

    def test_start_endpoint_rejects_other_websites(self):
        client = dashboard.app.test_client()
        response = client.post("/api/listener/start", headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_status_endpoint(self):
        import auth
        store = auth.AuthStore(os.path.join(self.tmp.name, "users.json"))
        store.create_user("status_test", "test-status-pass", role="admin")
        with mock.patch.object(dashboard, "AUTH", store):
            client = dashboard.app.test_client()
            client.set_cookie(dashboard.SESSION_COOKIE, store.issue_token("status_test"))
            listener._write_heartbeat("running")
            body = client.get("/api/status").get_json()
        self.assertEqual(body["listener"]["state"], "running")
        self.assertIn("evidence_sig", body)


if __name__ == "__main__":
    unittest.main()
