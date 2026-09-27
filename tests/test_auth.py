"""
test_auth.py

Analyst accounts and JWT sessions: password hashing, first-run setup,
sign-in, lockout, revocation on password change / deletion, admin-only
account management, and that every page and API needs a session.
No Docker needed; uses a throwaway accounts file.

Run from the code/ folder with:
    python -m unittest discover tests
"""

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "gui"))

import jwt  # noqa: E402

import app as dashboard  # noqa: E402
import auth  # noqa: E402

# Test-only credentials for a throwaway accounts file.
ADMIN, ADMIN_PW = "admin_test", "test-admin-pass-1"
ANALYST, ANALYST_PW = "analyst_test", "test-analyst-pass-1"


def fresh_store(test):
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    store = auth.AuthStore(os.path.join(tmp.name, "config", "users.json"))
    patcher = mock.patch.object(dashboard, "AUTH", store)
    patcher.start()
    test.addCleanup(patcher.stop)
    return store


def signed_in_client(store, username):
    client = dashboard.app.test_client()
    client.set_cookie(dashboard.SESSION_COOKIE, store.issue_token(username))
    return client


class PasswordTests(unittest.TestCase):
    def test_hash_is_salted_and_verifies(self):
        a, b = auth._hash_password("same password"), auth._hash_password("same password")
        self.assertNotEqual(a, b)
        self.assertTrue(auth._check_password("same password", a))
        self.assertFalse(auth._check_password("other password", a))
        self.assertNotIn("same password", a)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store(self)
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")

    def test_rules_on_usernames_and_passwords(self):
        with self.assertRaises(auth.AuthError):
            self.store.create_user("x", "long enough pw")
        with self.assertRaises(auth.AuthError):
            self.store.create_user("valid_name", "short")
        with self.assertRaises(auth.AuthError):
            self.store.create_user(ADMIN.upper(), ADMIN_PW)  # names are unique, ignoring case

    def test_token_round_trip_and_tampering(self):
        token = self.store.issue_token(ADMIN)
        self.assertEqual(self.store.read_token(token)["username"], ADMIN)
        forged = jwt.encode({"sub": ADMIN, "role": "admin", "pwv": 1, "exp": time.time() + 60}, "a-different-secret-that-is-long-enough", algorithm="HS256")
        self.assertIsNone(self.store.read_token(forged))
        expired = jwt.encode({"sub": ADMIN, "role": "admin", "pwv": 1, "exp": time.time() - 1},
                             self.store._load()["secret"], algorithm="HS256")
        self.assertIsNone(self.store.read_token(expired))

    def test_password_change_and_deletion_end_sessions(self):
        self.store.create_user(ANALYST, ANALYST_PW)
        token = self.store.issue_token(ANALYST)
        self.store.set_password(ANALYST, "a-new-password-2")
        self.assertIsNone(self.store.read_token(token))
        token = self.store.issue_token(ANALYST)
        self.store.delete_user(ANALYST)
        self.assertIsNone(self.store.read_token(token))

    def test_lockout_after_repeated_failures(self):
        for _ in range(auth._LOCKOUT_FAILURES):
            self.assertIsNone(self.store.authenticate(ADMIN, "wrong"))
        self.assertGreater(self.store.locked_for(ADMIN), 0)

    def test_last_admin_cannot_be_deleted(self):
        with self.assertRaises(auth.AuthError):
            self.store.delete_user(ADMIN)


class WebFlowTests(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store(self)
        self.client = dashboard.app.test_client()

    def test_first_run_goes_to_setup_and_creates_admin(self):
        self.assertIn("/setup", self.client.get("/").headers["Location"])
        r = self.client.post("/setup", data={"username": ADMIN, "password": ADMIN_PW, "confirm": ADMIN_PW})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.store.list_users()[0]["role"], "admin")
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(self.client.get("/").status_code, 200)  # signed in by setup

    def test_every_page_and_api_needs_a_session(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        for path in ("/", "/search?q=x", "/account", "/users"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers["Location"])
        for path in ("/api/status", "/api/live"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.get("/login").status_code, 200)

    def test_sign_in_wrong_then_right(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        self.assertEqual(self.client.post("/login", data={"username": ADMIN, "password": "nope"}).status_code, 401)
        r = self.client.post("/login", data={"username": ADMIN, "password": ADMIN_PW, "next": "/search?q=a"})
        self.assertEqual(r.headers["Location"], "/search?q=a")

    def test_sign_in_never_redirects_off_site(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        r = self.client.post("/login", data={"username": ADMIN, "password": ADMIN_PW, "next": "//evil.example/"})
        self.assertEqual(r.headers["Location"], "/")

    def test_analysts_cannot_manage_accounts(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        self.store.create_user(ANALYST, ANALYST_PW)
        client = signed_in_client(self.store, ANALYST)
        self.assertEqual(client.get("/users").status_code, 403)
        self.assertEqual(client.get("/").status_code, 200)

    def test_admin_adds_and_deletes_accounts(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        client = signed_in_client(self.store, ADMIN)
        client.post("/users", data={"action": "add", "username": ANALYST, "password": ANALYST_PW,
                                    "confirm": ANALYST_PW, "role": "analyst"})
        self.assertIn(ANALYST, [u["username"] for u in self.store.list_users()])
        client.post("/users", data={"action": "delete", "username": ANALYST})
        self.assertNotIn(ANALYST, [u["username"] for u in self.store.list_users()])

    def test_cross_site_posts_are_refused(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        client = signed_in_client(self.store, ADMIN)
        r = client.post("/users", data={"action": "delete", "username": ADMIN}, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_sign_out_clears_the_cookie(self):
        self.store.create_user(ADMIN, ADMIN_PW, role="admin")
        client = signed_in_client(self.store, ADMIN)
        r = client.post("/logout")
        self.assertIn("ecf_session=;", r.headers.get("Set-Cookie", ""))


class SearchTests(unittest.TestCase):
    def test_search_matches_every_word(self):
        store = fresh_store(self)
        store.create_user(ADMIN, ADMIN_PW, role="admin")
        client = signed_in_client(store, ADMIN)
        rows = [
            {"name": "web_server", "full_id": "abc123", "filename": "web_server_1.json", "ended": {"label": "Killed"},
             "ports": {"status": "ok", "ports": ["8080/tcp"]}, "captured_at": 1_790_000_000, "legacy": False, "live": "saved"},
            {"name": "db", "full_id": "def456", "filename": "db_1.json", "ended": {"label": "Stopped"},
             "ports": {"status": "not_recorded"}, "captured_at": 1_790_000_000, "legacy": False, "live": "lost"},
        ]
        texts = [dashboard._search_text(r) for r in rows]
        self.assertTrue(all(t in texts[0] for t in ("web", "8080", "killed", "abc")))
        self.assertNotIn("8080", texts[1])
        self.assertEqual(client.get("/search?q=8080").status_code, 200)


if __name__ == "__main__":
    unittest.main()
