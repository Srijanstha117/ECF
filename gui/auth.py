"""
gui/auth.py -- analyst accounts and JWT sessions for the dashboard.

Accounts live in one JSON file (config/users.json, git-ignored):
  - passwords are stored only as scrypt hashes with a random salt each;
  - the JWT signing secret is generated on first use and kept in the same
    file, so sessions survive a restart but a copied token is useless
    against another install;
  - every user has a password version ("pwv"). It's inside each token, and
    changing the password bumps it -- so a password change or a deleted
    account ends that user's existing sessions immediately, not at expiry.

Roles: "admin" can manage accounts; "analyst" can review evidence.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

import jwt

SESSION_HOURS = 8
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8
_LOCKOUT_FAILURES = 5
_LOCKOUT_SECONDS = 60


class AuthError(ValueError):
    """A request the user can fix (bad username, weak password...)."""


def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


def _check_password(password, stored):
    try:
        _, n, r, p, salt, digest = stored.split("$")
        candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), dklen=32,
                                   n=int(n), r=int(r), p=int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest)


# Checked when the username doesn't exist, so a wrong username takes as
# long as a wrong password and response time doesn't reveal which accounts exist.
_DUMMY_HASH = _hash_password(secrets.token_hex(8))


class AuthStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._failures = {}  # username -> [count, first failure time]

    # ------------------------------------------------------------ storage
    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        data.setdefault("users", {})
        if not data.get("secret"):
            data["secret"] = secrets.token_hex(32)
            if data["users"]:
                self._save(data)  # keep it, or every read would mint a new one
        return data

    def _save(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------ accounts
    def has_users(self):
        return bool(self._load()["users"])

    def list_users(self):
        users = self._load()["users"]
        return [{"username": name, "role": u["role"], "created": u.get("created"), "last_login": u.get("last_login")}
                for name, u in sorted(users.items())]

    def create_user(self, username, password, role="analyst"):
        username = (username or "").strip()
        if not _USERNAME_RE.match(username):
            raise AuthError("Usernames are 3–32 characters: letters, digits, dot, dash or underscore.")
        if len(password or "") < MIN_PASSWORD:
            raise AuthError(f"Passwords need at least {MIN_PASSWORD} characters.")
        if role not in ("admin", "analyst"):
            raise AuthError("Unknown role.")
        with self._lock:
            data = self._load()
            if username.lower() in (u.lower() for u in data["users"]):
                raise AuthError(f"There is already an account called {username}.")
            data["users"][username] = {"hash": _hash_password(password), "role": role,
                                       "created": time.time(), "pwv": 1, "last_login": None}
            self._save(data)

    def set_password(self, username, password):
        if len(password or "") < MIN_PASSWORD:
            raise AuthError(f"Passwords need at least {MIN_PASSWORD} characters.")
        with self._lock:
            data = self._load()
            user = data["users"].get(username)
            if user is None:
                raise AuthError("No such account.")
            user["hash"] = _hash_password(password)
            user["pwv"] = user.get("pwv", 1) + 1  # ends this user's other sessions
            self._save(data)

    def delete_user(self, username):
        with self._lock:
            data = self._load()
            user = data["users"].get(username)
            if user is None:
                raise AuthError("No such account.")
            admins = [n for n, u in data["users"].items() if u["role"] == "admin"]
            if user["role"] == "admin" and admins == [username]:
                raise AuthError("That's the only admin account; make another admin first.")
            del data["users"][username]
            self._save(data)

    # ------------------------------------------------------------ signing in
    def locked_for(self, username):
        """Seconds left on a lockout after repeated wrong passwords, or 0."""
        count, since = self._failures.get(username.lower(), (0, 0))
        if count >= _LOCKOUT_FAILURES:
            left = _LOCKOUT_SECONDS - (time.time() - since)
            if left > 0:
                return int(left) + 1
            self._failures.pop(username.lower(), None)
        return 0

    def authenticate(self, username, password):
        """The account for a correct username + password, else None."""
        username = (username or "").strip()
        user = self._load()["users"].get(username)
        ok = _check_password(password or "", user["hash"] if user else _DUMMY_HASH) and user is not None
        key = username.lower()
        if not ok:
            count, since = self._failures.get(key, (0, time.time()))
            self._failures[key] = (count + 1, since if count else time.time())
            return None
        self._failures.pop(key, None)
        with self._lock:
            data = self._load()
            data["users"][username]["last_login"] = time.time()
            self._save(data)
        return {"username": username, "role": user["role"]}

    def issue_token(self, username):
        data = self._load()
        user = data["users"][username]
        now = int(time.time())
        claims = {"sub": username, "role": user["role"], "pwv": user.get("pwv", 1),
                  "iat": now, "exp": now + SESSION_HOURS * 3600}
        return jwt.encode(claims, data["secret"], algorithm="HS256")

    def read_token(self, token):
        """The signed-in account for a valid, unexpired, unrevoked token."""
        if not token:
            return None
        data = self._load()
        try:
            claims = jwt.decode(token, data["secret"], algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return None
        user = data["users"].get(claims["sub"])
        if user is None or claims.get("pwv") != user.get("pwv", 1):
            return None  # account deleted or password changed since
        return {"username": claims["sub"], "role": user["role"], "expires": claims["exp"]}
