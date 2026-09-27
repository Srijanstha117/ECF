"""
Search suggestions: what drops down under the search box as you type.

Run from code/:  venv\\Scripts\\python.exe -m unittest discover tests
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "gui"))

import app as dashboard  # noqa: E402
import auth  # noqa: E402

DAY = 1_790_000_000  # 2026-09-21 UTC


def row(name, cid, ended="Killed", ports=(), captured=DAY, legacy=False, filename=None):
    return {"name": name, "full_id": cid, "id": cid[:12], "filename": filename or f"{name}.json",
            "ended": {"label": ended}, "captured_at": captured, "legacy": legacy, "live": "saved",
            "ports": {"status": "ok", "ports": list(ports)} if ports else {"status": "not_recorded"}}


ROWS = [
    row("web_server", "abc123def4567890", ports=["8080/tcp"], captured=DAY + 300),
    row("web_worker", "abc999000111", ended="Stopped", ports=["8080/tcp", "9090/tcp"], captured=DAY + 200),
    row("webhook", "fff000", ports=["80/tcp"], captured=DAY + 100),
    row("my_web_app", "eee000", captured=DAY + 50),
    row("web_old", "ddd000", captured=DAY - 86400 * 3, legacy=True),
    row("database", "ccc000", ended="Stopped", ports=["5432/tcp"], captured=DAY + 400),
]


def suggest(q, rows=ROWS):
    with dashboard.app.test_request_context():
        return dashboard.search_suggestions(rows, q)


class SuggestionTests(unittest.TestCase):
    def test_nothing_before_two_characters(self):
        self.assertEqual(suggest(""), [])
        self.assertEqual(suggest("w"), [])
        self.assertEqual(suggest(" w "), [])

    def test_at_most_four(self):
        self.assertEqual(len(suggest("web")), 4)

    def test_name_prefix_before_substring_and_newest_first(self):
        labels = [s["label"] for s in suggest("web") if s["kind"] == "Container"]
        self.assertEqual(labels[:3], ["web_server", "web_worker", "webhook"])
        self.assertNotIn("my_web_app", labels[:3])  # only contains "web"

    def test_container_opens_its_page(self):
        first = suggest("web_se")[0]
        self.assertEqual((first["kind"], first["label"]), ("Container", "web_server"))
        self.assertEqual(first["url"], "/evidence/web_server.json")
        self.assertIn("Killed", first["detail"])

    def test_container_id_prefix(self):
        found = suggest("abc123")
        self.assertEqual(found[0]["label"], "web_server")
        self.assertIn("ID abc123def456", found[0]["detail"])

    def test_port_groups_open_a_search(self):
        found = suggest("808")
        port = next(s for s in found if s["kind"] == "Port")
        self.assertEqual((port["label"], port["detail"]), ("8080/tcp", "2 containers"))
        self.assertEqual(port["url"], "/search?q=8080")
        # The containers with that port are suggested too.
        self.assertIn("web_server", [s["label"] for s in found])

    def test_how_it_ended(self):
        found = suggest("stop")
        ended = next(s for s in found if s["kind"] == "Ended")
        self.assertEqual((ended["label"], ended["detail"]), ("Stopped", "2 containers"))
        self.assertEqual(ended["url"], "/search?q=stopped")

    def test_dates_are_utc_like_the_search(self):
        found = suggest("2026-09-2")
        dates = [s["label"] for s in found if s["kind"] == "Date"]
        self.assertIn("2026-09-21", dates)

    def test_dates_newest_first(self):
        rows = [row("a1", "a1", captured=DAY), row("a2", "a2", captured=DAY + 86400)]
        dates = [s["label"] for s in suggest("2026-09", rows) if s["kind"] == "Date"]
        self.assertEqual(dates, ["2026-09-22", "2026-09-21"])

    def test_old_packages_say_so(self):
        found = next(s for s in suggest("web_old") if s["label"] == "web_old")
        self.assertIn("old", found["detail"])

    def test_mix_leaves_room_for_a_group(self):
        kinds = [s["kind"] for s in suggest("80")]
        self.assertIn("Port", kinds)
        self.assertLessEqual(len(kinds), 4)

    def test_several_words_match_containers_on_every_word(self):
        found = suggest("web stopped")
        self.assertEqual([s["label"] for s in found], ["web_worker"])

    def test_other_fields_only_match_at_the_start_of_a_word(self):
        # "urr" is inside "current" (and nothing else): no suggestion.
        self.assertEqual(suggest("urr"), [])
        # "kill" starts "Killed": the killed containers are suggested.
        self.assertIn("web_server", [s["label"] for s in suggest("kill")])

    def test_no_match(self):
        self.assertEqual(suggest("zzzz"), [])


class SuggestEndpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = auth.AuthStore(os.path.join(tmp.name, "users.json"))
        self.store.create_user("search_test", "test-search-pass", role="analyst")
        for p in (mock.patch.object(dashboard, "AUTH", self.store),
                  mock.patch.object(dashboard, "_cached_rows", return_value=ROWS)):
            p.start()
            self.addCleanup(p.stop)

    def test_needs_sign_in(self):
        self.assertEqual(dashboard.app.test_client().get("/api/search/suggest?q=web").status_code, 401)

    def test_returns_suggestions(self):
        client = dashboard.app.test_client()
        client.set_cookie(dashboard.SESSION_COOKIE, self.store.issue_token("search_test"))
        body = client.get("/api/search/suggest?q=web").get_json()
        self.assertEqual(body["q"], "web")
        self.assertEqual(len(body["suggestions"]), 4)


if __name__ == "__main__":
    unittest.main()
