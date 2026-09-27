"""
Running with no windows: the listener and dashboard start windowless,
log to files, and are stopped from the dashboard instead of by closing a
console window.

Run from code/:  venv\\Scripts\\python.exe -m unittest discover tests
"""

import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, "..", "gui"))

import listener  # noqa: E402
import runlog  # noqa: E402
import app as dashboard  # noqa: E402
import auth  # noqa: E402


class _TempDirs(unittest.TestCase):
    """Points the heartbeat, stop request, logs and accounts at a temp
    folder, so the tests never touch (or stop) a real running listener."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stop_path = os.path.join(self.tmp.name, ".listener.stop")
        self.logs = os.path.join(self.tmp.name, "logs")
        self.store = auth.AuthStore(os.path.join(self.tmp.name, "users.json"))
        patches = [
            mock.patch.object(listener, "HEARTBEAT_PATH", os.path.join(self.tmp.name, ".listener.json")),
            mock.patch.object(listener, "STOP_REQUEST_PATH", self.stop_path),
            mock.patch.object(dashboard, "EVIDENCE_DIR", self.tmp.name),
            mock.patch.object(dashboard, "LISTENER_STOP_PATH", self.stop_path),
            mock.patch.object(dashboard, "LOGS_DIR", self.logs),
            mock.patch.object(dashboard, "AUTH", self.store),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def signed_in_client(self):
        self.store.create_user("bg_test", "test-bg-password", role="analyst")
        client = dashboard.app.test_client()
        client.set_cookie(dashboard.SESSION_COOKIE, self.store.issue_token("bg_test"))
        return client


class StartWindowlessTests(_TempDirs):
    def test_listener_starts_without_a_window(self):
        with mock.patch.dict(dashboard._last_launch, {"at": 0.0}), mock.patch("subprocess.Popen") as popen:
            started, _ = dashboard.start_listener()
        self.assertTrue(started)
        command = popen.call_args.args[0]
        self.assertIn("--background", command)
        self.assertNotIn("--keep-open", command)
        kwargs = popen.call_args.kwargs
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        if os.name == "nt":
            self.assertTrue(kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW)
            self.assertFalse(kwargs["creationflags"] & subprocess.CREATE_NEW_CONSOLE)
            venv_pythonw = os.path.join(dashboard.CODE_DIR, "venv", "Scripts", "pythonw.exe")
            if os.path.isfile(venv_pythonw):
                self.assertEqual(os.path.basename(command[0]).lower(), "pythonw.exe")
        else:
            self.assertTrue(kwargs["start_new_session"])


class StopListenerTests(_TempDirs):
    def test_stop_request_reaches_the_listener(self):
        listener._write_heartbeat("running")
        self.assertFalse(listener.stop_requested())
        asked, message = dashboard.stop_listener()
        self.assertEqual((asked, message), (True, "stopping"))
        self.assertTrue(listener.stop_requested())

    def test_nothing_to_stop(self):
        self.assertEqual(dashboard.stop_listener(), (False, "not running"))
        self.assertFalse(os.path.exists(self.stop_path))

    def test_old_request_does_not_stop_a_new_listener(self):
        with open(self.stop_path, "w") as f:
            f.write("old")
        with mock.patch.object(listener, "_started_at", time.time() + 60):
            self.assertFalse(listener.stop_requested())

    def test_heartbeat_loop_stops_on_request(self):
        with open(self.stop_path, "w") as f:
            f.write("now")
        stop = threading.Event()
        with mock.patch.object(listener, "HEARTBEAT_SECONDS", 0.01), \
                mock.patch.object(listener, "_stop_event_loop") as stop_loop, \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            worker = threading.Thread(target=listener._heartbeat_loop, args=(stop,))
            worker.start()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        stop_loop.assert_called_once()
        self.assertFalse(os.path.exists(self.stop_path))  # consumed

    def test_stop_endpoint(self):
        client = self.signed_in_client()
        listener._write_heartbeat("running")
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            body = client.post("/api/listener/stop").get_json()
        self.assertTrue(body["stopping"])
        self.assertTrue(os.path.exists(self.stop_path))

    def test_stop_endpoint_needs_sign_in_and_same_origin(self):
        self.store.create_user("bg_admin", "test-bg-password", role="admin")
        client = dashboard.app.test_client()
        self.assertEqual(client.post("/api/listener/stop").status_code, 401)
        self.assertEqual(client.post("/api/listener/stop", headers={"Origin": "https://evil.example"}).status_code, 403)


class ShutdownAndLogsTests(_TempDirs):
    def test_shutdown_can_stop_both(self):
        client = self.signed_in_client()
        listener._write_heartbeat("running")
        with mock.patch.object(dashboard, "_exit_soon") as exit_soon, \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            page = client.post("/shutdown", data={"what": "all"}).get_data(as_text=True)
        exit_soon.assert_called_once()
        self.assertTrue(os.path.exists(self.stop_path))
        self.assertIn("The dashboard has stopped", page)
        self.assertIn("The listener is stopping too", page)

    def test_shutdown_dashboard_only_leaves_listener(self):
        client = self.signed_in_client()
        listener._write_heartbeat("running")
        with mock.patch.object(dashboard, "_exit_soon") as exit_soon, \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            page = client.post("/shutdown", data={"what": "dashboard"}).get_data(as_text=True)
        exit_soon.assert_called_once()
        self.assertFalse(os.path.exists(self.stop_path))
        self.assertIn("keeps capturing", page)

    def test_shutdown_page_asks_first(self):
        client = self.signed_in_client()
        listener._write_heartbeat("running")
        with mock.patch.object(dashboard, "_exit_soon") as exit_soon:
            page = client.get("/shutdown").get_data(as_text=True)
        exit_soon.assert_not_called()
        self.assertIn("Stop dashboard and listener", page)

    def test_shutdown_without_a_listener_does_not_claim_capture(self):
        client = self.signed_in_client()
        with mock.patch.object(dashboard, "_exit_soon"), mock.patch("sys.stdout", new_callable=io.StringIO):
            page = client.post("/shutdown", data={"what": "dashboard"}).get_data(as_text=True)
        self.assertNotIn("keeps capturing", page)
        self.assertIn("isn't running", page)

    def test_shutdown_page_without_a_listener_offers_one_choice(self):
        page = self.signed_in_client().get("/shutdown").get_data(as_text=True)
        self.assertNotIn("Stop dashboard and listener", page)
        self.assertIn(">Stop dashboard<", page)

    def test_logs_page_shows_the_newest_lines(self):
        os.makedirs(self.logs)
        with open(os.path.join(self.logs, "listener.log"), "w") as f:
            f.writelines(f"line {i}\n" for i in range(1000))
        page = self.signed_in_client().get("/logs").get_data(as_text=True)
        self.assertIn("line 999", page)
        self.assertNotIn("line 500\n", page)
        self.assertIn("Nothing logged yet", page)  # no dashboard.log

    def test_ping_is_public_even_before_setup(self):
        body = dashboard.app.test_client().get("/api/ping").get_json()
        self.assertEqual(body, {"app": "ecf-dashboard"})


class RunLogTests(unittest.TestCase):
    def test_windowless_output_goes_to_a_timestamped_log(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = sys.stdout, sys.stderr
        try:
            sys.stdout = sys.stderr = None  # what pythonw gives a process
            path = runlog.log_to_file_if_windowless(tmp.name, "listener")
            print("[*] Listening")
            sys.stderr.write("Traceback (most recent call last):\n  boom\n")
            sys.stdout._stream.close()
        finally:
            sys.stdout, sys.stderr = saved
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertRegex(lines[0], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  \[\*\] Listening$")
        self.assertTrue(lines[1].endswith("Traceback (most recent call last):"))
        self.assertEqual(len(lines), 3)

    def test_bytes_are_refused_so_libraries_fall_back_to_text(self):
        # click (Flask's startup banner) probes write(b"") and switches to
        # bytes if it's accepted -- which crashed the windowless exe.
        import click
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "x.log"), "w", encoding="utf-8") as raw:
            writer = runlog._TimestampedWriter(raw)
            with self.assertRaises(TypeError):
                writer.write(b"")
            click.echo(" * Serving Flask app 'app'", file=writer)
        with open(os.path.join(tmp.name, "x.log"), encoding="utf-8") as f:
            self.assertTrue(f.read().rstrip().endswith(" * Serving Flask app 'app'"))

    def test_console_output_is_left_alone(self):
        with mock.patch.object(sys, "argv", ["listener.py"]):
            self.assertIsNone(runlog.log_to_file_if_windowless(tempfile.gettempdir(), "x"))

    def test_src_and_gui_copies_match(self):
        with open(os.path.join(HERE, "..", "src", "runlog.py"), "rb") as a, \
                open(os.path.join(HERE, "..", "gui", "runlog.py"), "rb") as b:
            self.assertEqual(a.read(), b.read())


class SingleDashboardTests(unittest.TestCase):
    def test_second_launch_just_opens_the_browser(self):
        with mock.patch.object(sys, "argv", ["app.py", "--open", "--no-listener"]), \
                mock.patch.object(dashboard, "_dashboard_at", side_effect=lambda p: p == 5000), \
                mock.patch.object(dashboard, "_port_free", return_value=False), \
                mock.patch("webbrowser.open") as open_browser, \
                mock.patch.object(dashboard.app, "run") as run, \
                mock.patch.dict(os.environ, {"PORT": "5000"}):
            dashboard.main()
        open_browser.assert_called_once_with("http://127.0.0.1:5000")
        run.assert_not_called()

    def test_port_taken_by_something_else_uses_the_next(self):
        with mock.patch.object(sys, "argv", ["app.py", "--open", "--no-listener"]), \
                mock.patch.object(dashboard, "_dashboard_at", return_value=False), \
                mock.patch.object(dashboard, "_port_free", side_effect=lambda p: p != 5000), \
                mock.patch("threading.Timer"), \
                mock.patch.object(dashboard.app, "run") as run, \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch.dict(os.environ, {"PORT": "5000"}):
            dashboard.main()
        self.assertEqual(run.call_args.kwargs["port"], 5001)


if __name__ == "__main__":
    unittest.main()
