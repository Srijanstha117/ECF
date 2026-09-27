"""
gui/app.py

Evidence review dashboard for the ephemeral container forensics tool.

Read-only web UI over the evidence/ folder produced by listener.py --
lists every captured evidence package, says in plain words what was
saved and what was lost for each container, which ports it had open
and when, and independently RE-VERIFIES each file's SHA-256 hash on
every page load rather than trusting the stored value blindly. That
check catches accidental change; because the hash lives in the same
file, it can't by itself prove the file wasn't deliberately rewritten
-- the UI says so rather than overclaiming.

Run in dev with:     python app.py
Run as packaged exe: ContainerForensicsGUI.exe (see BUILD.md)
Then open:           http://127.0.0.1:5000 (opens automatically when
                      running as a packaged exe)

This deliberately binds to 127.0.0.1 only, never 0.0.0.0 -- it reads
whatever Docker daemon is on THIS machine, so there is no meaningful
sense in which it should be reachable from other machines. It's a
local review tool, not a hosted service.
"""

import datetime
import glob
import hashlib
import json
import os
import re
import sys

from flask import Flask, Response, abort, render_template, request


def resource_path(relative_path):
    """Path to bundled templates/static. When PyInstaller packages
    this into a single exe, bundled files are unpacked to a temp
    directory at runtime (sys._MEIPASS) -- this resolves correctly
    either way, packaged or run directly with `python app.py`."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


def external_base_dir():
    """Directory to resolve the EXTERNAL evidence/ folder from. This
    is deliberately NOT the same as resource_path(): evidence files
    are written by listener.py at capture time and must be found next
    to wherever this program actually lives on disk, not inside the
    temp bundle PyInstaller extracts itself into. Uses the exe's own
    location when frozen, or this script's location in dev."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"),
)

EVIDENCE_DIR = os.path.join(external_base_dir(), "..", "evidence")

# (field, plain name). Network state and the process list only exist
# while the container runs -- the "live state" the project is about.
# Files and logs survive the process, until the container is removed.
FIELD_NAMES = [
    ("network_state", "Network"),
    ("process_list", "Processes"),
    ("filesystem_diff", "Files"),
    ("logs", "Logs"),
]
FIELDS = [field for field, _ in FIELD_NAMES]
LIVE_FIELDS = ("network_state", "process_list")

# What a "direct" capture actually was, per field. The evidence JSON
# labels both as 'live_kill_trigger', but only network/process come
# from the kill handler; filesystem/logs are captured by the die
# handler after the process has exited.
DIRECT_PATH = {
    "network_state": "Kill-trigger capture",
    "process_list": "Kill-trigger capture",
    "filesystem_diff": "Post-mortem capture",
    "logs": "Post-mortem capture",
}

# Mirrors POLL_INTERVAL_SECONDS in src/poller.py. Evidence files don't
# record it (older ones, anyway), and the GUI deliberately can't import
# src/ (that needs the docker package), so it's restated here. Keep the
# two in step.
POLL_INTERVAL_SECONDS = 0.5


def recompute_hash(evidence):
    """Mirrors capture.py's hash_evidence() exactly: hash everything
    except the stored hash itself, using the same canonical JSON
    encoding (sort_keys=True, default=str). If this doesn't match the
    stored 'sha256' field, the file was altered after capture -- that
    mismatch IS the finding, not a bug to hide."""
    without_hash = {k: v for k, v in evidence.items() if k != "sha256"}
    canonical = json.dumps(without_hash, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def load_evidence_file(path):
    """Never lets one bad file take the whole dashboard down. A
    forensic review tool that crashes because ONE evidence file is
    empty/corrupt is worse than useless -- it hides every other piece
    of evidence too. Unreadable files are surfaced explicitly instead,
    which is itself useful information (why is this file empty? did
    the write get interrupted?), not swept under the rug."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {
            "_filename": os.path.basename(path),
            "_load_error": str(e),
        }

    stored_hash = data.get("sha256")
    recomputed = recompute_hash(data)
    data["_hash_verified"] = stored_hash == recomputed
    data["_recomputed_hash"] = recomputed
    data["_filename"] = os.path.basename(path)
    return data


def load_all_evidence():
    files = sorted(
        glob.glob(os.path.join(EVIDENCE_DIR, "*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    return [load_evidence_file(f) for f in files]


_DOCKER_TS_RE = re.compile(
    r"^(?P<base>[^.]+?)(?:\.(?P<frac>\d+))?(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)


def parse_docker_ts(raw):
    """Epoch seconds from a Docker RFC3339 timestamp, or None. Mirrors
    capture.parse_docker_timestamp -- restated because the GUI can't
    import src/ without the docker package."""
    if not isinstance(raw, str):
        return None
    m = _DOCKER_TS_RE.match(raw)
    if not m:
        return None
    frac = (m["frac"] or "")[:6].ljust(6, "0")
    tz = "+00:00" if m["tz"] in (None, "Z") else m["tz"]
    try:
        return datetime.datetime.fromisoformat(f"{m['base']}.{frac}{tz}").timestamp()
    except ValueError:
        return None


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


# ---------------------------------------------------------------- outcomes

def kill_trigger_start_after_exit(evidence):
    """When the kill-trigger capture really started, in seconds after the
    container exited (host clock), or None if the package doesn't record
    it. Packages before 2026-09-26 13:25 don't: for those the start is
    unknown, and measured packages show it's NOT "just after SIGKILL" --
    Docker holds API calls until it has finished handling the exit."""
    timing = evidence.get("timing")
    if not isinstance(timing, dict):
        return None
    started = _num(evidence.get("live_kill_trigger_started_at"))
    death = _num(timing.get("death_time_host_clock"))
    if started is None or death is None or "FALLBACK" in str(timing.get("death_time_host_clock_source", "FALLBACK")):
        return None
    return started - death


def _kill_trigger_net_latency(evidence):
    """The NET part of the kill-trigger attempt, when recorded. It's lost
    whenever the poller supplied NET: the package then keeps only the
    rescued value, not the failed live attempt."""
    entry = evidence.get("network_state") or {}
    attempt = entry.get("data") if entry.get("source") == "live_kill_trigger" else entry.get("live_attempt")
    return _num(attempt.get("latency_seconds")) if isinstance(attempt, dict) else None


def field_times(evidence):
    """Each field's capture time relative to the container's exit, in
    seconds (negative = before exit), for whichever path supplied it --
    or None where the package doesn't record one. Lost fields have none."""
    timing = evidence.get("timing") if isinstance(evidence.get("timing"), dict) else {}
    exit_to_die = _num(timing.get("exit_to_die_event_seconds"))
    lag = _num(timing.get("die_handling_lag_seconds"))
    postmortem = _num(evidence.get("reactive_postmortem_latency_seconds"))
    handled = exit_to_die + lag if exit_to_die is not None and lag is not None else None
    kill_start = kill_trigger_start_after_exit(evidence)
    net_latency = _kill_trigger_net_latency(evidence)
    total = _num(evidence.get("live_kill_trigger_latency_seconds"))

    direct = {
        "network_state": kill_start + net_latency if kill_start is not None and net_latency is not None else None,
        "process_list": kill_start + total if kill_start is not None and total is not None else None,
        "filesystem_diff": handled,
        "logs": handled + postmortem if handled is not None and postmortem is not None else None,
    }
    times = {}
    for field in FIELDS:
        entry = evidence.get(field) or {}
        if entry.get("source") == "live_kill_trigger":
            times[field] = direct[field]
        elif entry.get("source") == "poller_snapshot":
            age = _num(entry.get("snapshot_age_seconds"))
            times[field] = -age if age is not None else None
        else:
            times[field] = None
    return times


def field_outcome(evidence, field, t=None):
    """Every field lands in exactly one of three outcomes: captured
    directly by the listener, rescued from the poller's last snapshot,
    or lost because both paths failed. `t` is the capture time relative
    to exit (see field_times)."""
    entry = evidence.get(field) or {}
    source = entry.get("source", "")
    if source == "live_kill_trigger":
        return {"kind": "direct", "age": None, "t": t, "path": DIRECT_PATH[field]}
    if source == "poller_snapshot":
        return {"kind": "poller", "age": _num(entry.get("snapshot_age_seconds")), "t": t, "path": "Poller snapshot"}
    if field == "filesystem_diff" and "live_attempt" in entry and entry["live_attempt"] is None:
        # Packages captured before 2026-09-26 ~20:15 recorded "no files
        # changed" as a failure: Docker answers null for an unchanged
        # container, and the old code treated null as failed. A real
        # failure is always stored as an error, so null can only mean
        # "no changes" -- shown as such, with the bug named on the page.
        return {"kind": "empty", "age": None, "t": None, "path": "No changes"}
    return {"kind": "lost", "age": None, "t": None, "path": "Lost"}


def outcomes_for(evidence):
    times = field_times(evidence)
    return {field: field_outcome(evidence, field, times[field]) for field in FIELDS}


def termination_of(evidence):
    """How the container ended: stopped, killed, or exited on its own.
    Packages from 2026-09-27 record it (first signal + exit code). Older
    ones don't; for those it's inferred from what they do record, and
    marked as inferred so the page can say so."""
    recorded = evidence.get("termination")
    if isinstance(recorded, dict) and recorded.get("label"):
        return {**recorded, "inferred": False}
    timing = evidence.get("timing") if isinstance(evidence.get("timing"), dict) else {}
    if timing.get("sigkill_event_time_ns"):
        return {"verdict": "killed", "label": "Killed", "inferred": True,
                "detail": "A SIGKILL was recorded. This older package doesn't record whether a SIGTERM "
                          "came first, so a timed-out docker stop can't be ruled out."}
    if evidence.get("live_kill_trigger_latency_seconds") is not None:
        return {"verdict": "signalled", "label": "Stopped or killed", "inferred": True,
                "detail": "A stop/kill signal was seen, but this older package doesn't record which one."}
    if timing:
        return {"verdict": "exited", "label": "Exited on its own", "inferred": True,
                "detail": "No stop or kill signal was seen before it died."}
    return {"verdict": "unknown", "label": "Not recorded", "inferred": True,
            "detail": "This older package doesn't record how the container ended."}


def live_state(outcomes):
    """The headline outcome: was the live state -- network and processes,
    which vanish with the process -- saved, partly saved, or lost?"""
    kept = sum(outcomes[f]["kind"] != "lost" for f in LIVE_FIELDS)
    return {2: "saved", 1: "partly", 0: "lost"}[kept]


def ports_brief(evidence):
    """What the index says about ports: the listening ports and number of
    connections the poller saw, or why there's nothing to say."""
    timeline = evidence.get("port_timeline")
    if not isinstance(timeline, dict):
        return {"status": "not_recorded"}
    if "error" in timeline:
        return {"status": "never_read"}
    listening = sorted({(s["local_port"], s["proto"].rstrip("6")) for s in timeline["sockets"] if s["kind"] == "listening"})
    connections = sum(1 for s in timeline["sockets"] if s["kind"] == "connection")
    return {
        "status": "ok",
        "ports": [f"{port}/{proto}" for port, proto in listening],
        "connections": connections,
    }


def summarize(evidence):
    """Flattens one readable package into what the index needs."""
    outcomes = outcomes_for(evidence)
    return {
        "filename": evidence["_filename"],
        "name": evidence.get("container_name") or evidence["_filename"],
        "lifetime": _num(evidence.get("container_lifetime_seconds")),
        "legacy": "timing" not in evidence,
        "hash_ok": evidence["_hash_verified"],
        "outcomes": outcomes,
        "live": live_state(outcomes),
        "ports": ports_brief(evidence),
        "ended": termination_of(evidence),
    }


# ---------------------------------------------------------------- the result

# Lifetime bands for the result chart, in multiples of the poll interval:
# under one poll, one to two polls, two to four, four or more.
def _bands():
    p = POLL_INTERVAL_SECONDS
    return [
        (0, p, f"Under {p:g} s"),
        (p, 2 * p, f"{p:g} – {2 * p:g} s"),
        (2 * p, 4 * p, f"{2 * p:g} – {4 * p:g} s"),
        (4 * p, None, f"{4 * p:g} s or more"),
    ]


def result_summary(rows):
    """The finding in numbers: how many containers kept their live state,
    the lifetime above which every one did, and saved/lost per band."""
    known = [r for r in rows if r["lifetime"] is not None]
    if not rows:
        return None
    saved = [r for r in rows if r["live"] == "saved"]
    not_saved = [r for r in known if r["live"] != "saved"]
    cutoff = max((r["lifetime"] for r in not_saved), default=None)
    below = [r for r in known if cutoff is not None and r["lifetime"] <= cutoff]

    bands = []
    for low, high, label in _bands():
        members = [r for r in known if r["lifetime"] >= low and (high is None or r["lifetime"] < high)]
        if members:
            counts = {kind: sum(r["live"] == kind for r in members) for kind in ("saved", "partly", "lost")}
            bands.append({"label": label, "total": len(members), **counts})
    widest = max((b["total"] for b in bands), default=1)
    for b in bands:
        for kind in ("saved", "partly", "lost"):
            b[f"{kind}_w"] = b[kind] / widest * 100

    return {
        "total": len(rows),
        "saved": len(saved),
        "cutoff": cutoff,
        "below_total": len(below),
        "below_saved": sum(r["live"] == "saved" for r in below),
        "above_total": len(known) - len(below),
        "files_saved": sum(r["outcomes"]["filesystem_diff"]["kind"] != "lost" and r["outcomes"]["logs"]["kind"] != "lost" for r in rows),
        "bands": bands,
        "any_partly": any(b["partly"] for b in bands),
        "max_lifetime": max((r["lifetime"] for r in known), default=None),
    }


# ---------------------------------------------------------------- the story

def _clock(epoch):
    if epoch is None:
        return None
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _field_list(fields):
    names = [dict(FIELD_NAMES)[f].lower() for f in fields]
    names = ["network state" if n == "network" else "process list" if n == "processes" else
             "filesystem changes" if n == "files" else n for n in names]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _socket_label(s):
    proto = s["proto"].rstrip("6").upper()
    if s["kind"] == "listening":
        return f"Port {s['local_port']} ({proto})"
    return f"Connection {s['local_ip']}:{s['local_port']} → {s['remote_ip']}:{s['remote_port']} ({proto})"


def story(evidence):
    """What happened to this container, in order, as plain sentences.
    Each event: seconds since start (None = time not recorded), clock time
    (UTC, daemon clock), the sentence, and a kind for its marker. Only
    events the package records are told; nothing is placed at a guessed
    time."""
    timing = evidence.get("timing")
    lifetime = _num(evidence.get("container_lifetime_seconds"))
    if not isinstance(timing, dict) or lifetime is None:
        return None
    started = parse_docker_ts(evidence.get("container_started_at_raw"))

    def clock(t):
        return _clock(started + t) if started is not None and t is not None else None

    outcomes = outcomes_for(evidence)
    events = []

    def add(t, kind, text, note=None):
        events.append({"t": t, "clock": clock(t), "kind": kind, "text": text, "note": note})

    add(0.0, "start", "Container started.")

    # The poller's copies, grouped when they came from the same poll.
    poller = sorted((lifetime + outcomes[f]["t"], f) for f in FIELDS
                    if outcomes[f]["kind"] == "poller" and outcomes[f]["t"] is not None)
    group = []
    for t, f in poller + [(None, None)]:
        if group and (t is None or t - group[0][0] > POLL_INTERVAL_SECONDS / 2):
            add(group[0][0], "saved", f"The poller saved a copy of the {_field_list([g[1] for g in group])}.",
                "Its last copy before the container stopped.")
            group = []
        if t is not None:
            group.append((t, f))

    ports = evidence.get("port_timeline")
    if isinstance(ports, dict) and "error" not in ports:
        for s in ports.get("sockets", []):
            if s.get("first_seen_s") is not None:
                window = (f"Opened between {s['opened_after_s']:.2f} s and {s['first_seen_s']:.2f} s."
                          if s.get("opened_after_s") is not None else None)
                add(s["first_seen_s"], "port", f"{_socket_label(s)} seen open.", window)
            if not s.get("open_at_exit") and s.get("closed_by_s") is not None:
                add(s["closed_by_s"], "port-closed", f"{_socket_label(s)} no longer open.",
                    f"Closed between {s['last_seen_s']:.2f} s and {s['closed_by_s']:.2f} s.")

    ended = termination_of(evidence)
    sigkill_ns = _num(timing.get("sigkill_event_time_ns"))
    sigkill_t = sigkill_ns / 1e9 - started if sigkill_ns and started is not None else None
    first_ns = _num(ended.get("first_signal_time_ns"))
    first_t = first_ns / 1e9 - started if first_ns and started is not None else None
    code = ended.get("exit_code")
    code_text = f" Exit code {code}." if code is not None else ""
    if ended["verdict"] in ("stopped", "stopped_then_killed") and first_t is not None:
        add(first_t, "stop", "Asked to stop: sent SIGTERM (docker stop).")
        if ended["verdict"] == "stopped_then_killed" and sigkill_t is not None:
            add(sigkill_t, "stop", f"Still running {sigkill_t - first_t:.1f} s later, so force-killed with SIGKILL.")
        add(lifetime, "stop", f"The process stopped.{code_text}")
    elif ended["verdict"] == "exited":
        add(lifetime, "stop", f"The container's process ended by itself.{code_text}")
    elif sigkill_t is not None and abs(sigkill_t - lifetime) < 0.02:
        how = "" if ended.get("inferred") else " (docker kill)"
        add(lifetime, "stop", f"Killed with SIGKILL{how}. The process stopped immediately.{code_text}")
    else:
        if sigkill_t is not None:
            add(sigkill_t, "stop", "Sent SIGKILL.")
        add(lifetime, "stop", f"The container's process stopped.{code_text}")

    exit_to_die = _num(timing.get("exit_to_die_event_seconds"))
    die_t = lifetime + exit_to_die if exit_to_die is not None else None
    if die_t is not None:
        add(die_t, "docker", f"Docker reported the container as dead, {exit_to_die:.3f} s after it actually stopped.")

    total = _num(evidence.get("live_kill_trigger_latency_seconds"))
    live_ok = [f for f in LIVE_FIELDS if outcomes[f]["kind"] == "direct"]
    if total is not None:
        signal_word = "stop" if ended["verdict"] in ("stopped", "stopped_then_killed") else "kill"
        result = (f"It saved the {_field_list(live_ok)}." if live_ok
                  else "It failed: the container was already gone.")
        start_after = kill_trigger_start_after_exit(evidence)
        if start_after is not None:
            add(lifetime + start_after, "capture" if live_ok else "failed",
                f"A capture triggered by the {signal_word} signal tried to read the network state and processes. {result}")
        else:
            add(None, "capture" if live_ok else "failed",
                f"A capture triggered by the {signal_word} signal tried to read the network state and processes. {result}",
                "This package doesn't record when it started.")

    lag = _num(timing.get("die_handling_lag_seconds"))
    handled = die_t + lag if die_t is not None and lag is not None else None
    post_ok = [f for f in ("filesystem_diff", "logs") if outcomes[f]["kind"] in ("direct", "empty")]
    post_text = (f"Saved the {_field_list(post_ok)} from the stopped container." if len(post_ok) == 2
                 else f"Saved the {_field_list(post_ok)} from the stopped container; the rest was already gone." if post_ok
                 else "Tried to save the filesystem changes and logs, but the container had already been removed.")
    add(handled, "capture" if post_ok else "failed", post_text)

    lost = [f for f in FIELDS if outcomes[f]["kind"] == "lost"]
    if lost:
        add(None, "lost", f"Lost for good: the {_field_list(lost)}.",
            "Neither the poller nor a direct capture got a copy before it disappeared.")

    timed = sorted((e for e in events if e["t"] is not None), key=lambda e: e["t"])
    return timed + [e for e in events if e["t"] is None]


def port_rows(evidence):
    """Each port / connection with when it was open, plus geometry for a
    bar across the container's life: a solid part where the poller saw it
    open, and faint ends for the windows where it may have opened or
    closed (the poller only looks every poll interval)."""
    timeline = evidence.get("port_timeline")
    if not isinstance(timeline, dict):
        return {"status": "not_recorded"}
    if "error" in timeline:
        return {"status": "never_read"}
    lifetime = _num(evidence.get("container_lifetime_seconds"))
    started = parse_docker_ts(evidence.get("container_started_at_raw"))

    def pct(t):
        return max(0.0, min(100.0, t / lifetime * 100)) if lifetime and t is not None else None

    def clock(t):
        return _clock(started + t) if started is not None and t is not None else None

    rows = []
    for s in sorted(timeline.get("sockets", []), key=lambda s: (s["kind"] != "listening", s.get("first_seen_s") or 0)):
        rows.append({
            **s,
            "label": _socket_label(s),
            "proto_label": s["proto"].rstrip("6").upper() + (" (IPv6)" if s["proto"].endswith("6") else ""),
            "open_from_clock": clock(s.get("first_seen_s")),
            "open_until_clock": clock(s.get("closed_by_s")),
            "bar": None if lifetime is None or s.get("first_seen_s") is None else {
                "a": pct(s["opened_after_s"]), "b": pct(s["first_seen_s"]),
                "c": pct(s["last_seen_s"]), "d": pct(s["closed_by_s"]),
            },
        })
    return {
        "status": "ok",
        "rows": rows,
        "polls": timeline.get("polls"),
        "first_poll_s": timeline.get("first_poll_s"),
        "last_poll_s": timeline.get("last_poll_s"),
        "poll_interval": timeline.get("poll_interval_seconds", POLL_INTERVAL_SECONDS),
        "truncated": timeline.get("truncated"),
        "lifetime": lifetime,
        "poll_x": pct(POLL_INTERVAL_SECONDS) if lifetime and POLL_INTERVAL_SECONDS < lifetime else None,
    }


# ---------------------------------------------------------------- why lost

def _error_text(attempt):
    if not isinstance(attempt, dict):
        return None
    if "error" in attempt:
        return str(attempt["error"])
    data = attempt.get("data")
    if isinstance(data, dict) and "error" in data:
        return str(data["error"])
    return None


def _plain_reason(message):
    """Turns the Docker / pipeline errors this project actually produces
    into one plain sentence. Unknown errors fall through to None and the
    raw text is shown instead -- never guessed at."""
    if not message:
        return None
    if "is not running" in message:
        return "The container had already stopped, so there was nothing live to read."
    if "No such container" in message:
        return "The container had already been removed."
    if "no successful poller snapshot" in message:
        return "The poller never captured this before the container stopped."
    return None


def loss_explanations(evidence, field):
    """For a lost field: what each capture path tried and why it failed."""
    entry = evidence.get(field) or {}
    rows = []
    live = entry.get("live_attempt")
    if live is None:
        rows.append({
            "path": DIRECT_PATH[field],
            "reason": "Not attempted: no kill signal was seen for this container."
            if DIRECT_PATH[field] == "Kill-trigger capture" else "Not attempted.",
            "raw": None,
        })
    else:
        raw = _error_text(live)
        rows.append({"path": DIRECT_PATH[field], "reason": _plain_reason(raw), "raw": raw or live})
    raw = _error_text(entry.get("snapshot_attempt"))
    rows.append({"path": "Poller", "reason": _plain_reason(raw), "raw": raw or entry.get("snapshot_attempt")})
    return rows


# ---------------------------------------------------------------- filters

def format_timestamp(ts):
    """Unix epoch float -> human-readable UTC string. Evidence stores
    raw epoch floats for precision, but nobody wants to read those in
    a review UI."""
    if not isinstance(ts, (int, float)):
        return "unknown"
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def format_seconds(value, places=3):
    value = _num(value)
    return "—" if value is None else f"{value:.{places}f} s"


def format_ns(value):
    """Daemon-clock event timestamp (ns since epoch) -> readable UTC."""
    value = _num(value)
    if value is None:
        return "—"
    dt = datetime.datetime.fromtimestamp(value / 1e9, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(value % 1_000_000_000):09d} UTC"


def format_when(t):
    """Capture time relative to exit, in words."""
    t = _num(t)
    if t is None:
        return ""
    return f"{abs(t):.2f} s {'before' if t < 0 else 'after'} it stopped"


app.jinja_env.filters["format_ts"] = format_timestamp
app.jinja_env.filters["secs"] = format_seconds
app.jinja_env.filters["ns_ts"] = format_ns
app.jinja_env.filters["when"] = format_when


# ---------------------------------------------------------------- text report

def text_report(evidence):
    """The container's details as plain text, for download. Built from the
    same story/ports/outcomes as the page, so the two never disagree. It's
    a readable summary, not the evidence: the JSON file (and its hash) is
    the evidence, and the report says so."""
    outcomes = outcomes_for(evidence)
    ended = termination_of(evidence)
    lifetime = _num(evidence.get("container_lifetime_seconds"))
    lines = []

    def heading(title):
        lines.extend(["", title.upper(), "-" * len(title)])

    name = evidence.get("container_name") or evidence["_filename"]
    lines += [
        f"CONTAINER EVIDENCE REPORT: {name}",
        "=" * (27 + len(name)),
        f"Evidence file:  {evidence['_filename']}",
        f"Container ID:   {evidence.get('container_id', 'unknown')}",
        f"Captured:       {format_timestamp(evidence.get('captured_at'))}",
        f"Started:        {evidence.get('container_started_at_raw') if isinstance(evidence.get('container_started_at_raw'), str) else 'not recorded'}",
        f"Lived:          {format_seconds(lifetime)}",
        f"How it ended:   {ended['label']}" + (" (inferred)" if ended.get("inferred") else ""),
        f"                {ended['detail']}",
    ]
    if ended.get("exit_code") is not None:
        lines.append(f"Exit code:      {ended['exit_code']}")
    if "timing" not in evidence:
        lines.append("NOTE: old (legacy) package, captured before the timing fix; its lifetime reads ~0.3 s too long.")

    heading("Evidence saved")
    for field, label in FIELD_NAMES:
        o = outcomes[field]
        if o["kind"] == "lost":
            text = "LOST - both capture paths failed"
        elif o["kind"] == "empty":
            text = "saved - no files changed"
        else:
            how = "poller copy" if o["kind"] == "poller" else o["path"].lower()
            text = f"saved ({how}{', ' + format_when(o['t']) if o['t'] is not None else ''})"
        lines.append(f"  {label:<10} {text}")
        if o["kind"] == "lost":
            for x in loss_explanations(evidence, field):
                raw = x["raw"] if isinstance(x["raw"], str) else json.dumps(x["raw"]) if x["raw"] else ""
                lines.append(f"             {x['path']}: {x['reason'] or raw}")

    heading("What happened")
    events = story(evidence)
    if events:
        for ev in events:
            when = f"{ev['t']:7.2f} s" if ev["t"] is not None else "      —  "
            clock = f"  [{ev['clock']} UTC]" if ev.get("clock") else ""
            lines.append(f"{when}  {ev['text']}{clock}")
            if ev.get("note"):
                lines.append(f"{'':11}{ev['note']}")
    else:
        lines.append("Not available: this package doesn't record when things happened.")

    heading("Ports and connections")
    ports = port_rows(evidence)
    if ports["status"] == "ok":
        if ports["rows"]:
            for p in ports["rows"]:
                opened = (f"{p['opened_after_s']:.2f}-{p['first_seen_s']:.2f} s"
                          if p.get("first_seen_s") is not None and p.get("opened_after_s") is not None else "unknown")
                closed = ("until it stopped" if p["open_at_exit"] else
                          f"{p['last_seen_s']:.2f}-{p['closed_by_s']:.2f} s" if p.get("last_seen_s") is not None else "unknown")
                lines.append(f"  {p['label']}")
                lines.append(f"      open from {opened}, open until {closed}; states: {' -> '.join(p['states']).lower()}")
            lines.append(f"  ({ports['polls']} reads, every {ports['poll_interval']} s; times are windows - "
                         "anything that opened and closed between two reads is not seen.)")
        else:
            lines.append("  None were open whenever the poller looked.")
    elif ports["status"] == "never_read":
        lines.append("  No port history: the poller never read this container's sockets before it stopped.")
    else:
        lines.append("  Not tracked: this package is from before port tracking was added.")

    processes = (evidence.get("process_list") or {}).get("data")
    if isinstance(processes, dict) and processes.get("Titles"):
        heading("Processes (last copy)")
        widths = [max(len(str(v)) for v in col) for col in zip(processes["Titles"], *processes["Processes"])]
        for row in [processes["Titles"]] + processes["Processes"]:
            lines.append("  " + "  ".join(str(v).ljust(w) for v, w in zip(row, widths)))

    changes = (evidence.get("filesystem_diff") or {}).get("data")
    if isinstance(changes, list):
        heading("Files changed")
        kinds = {0: "changed", 1: "added", 2: "deleted"}
        lines += [f"  {kinds.get(c.get('Kind'), c.get('Kind')):<8} {c.get('Path')}" for c in changes] or ["  none"]

    logs = (evidence.get("logs") or {}).get("data")
    if isinstance(logs, str):
        heading("Logs")
        lines += ["  " + line for line in logs.splitlines()] or ["  (the container printed nothing)"]

    heading("Integrity")
    lines += [
        f"Stored SHA-256:     {evidence.get('sha256')}",
        f"Recomputed SHA-256: {evidence['_recomputed_hash']}",
        "Result:             " + ("MATCH" if evidence["_hash_verified"] else "MISMATCH - the file has changed since capture"),
        "This report is a readable summary generated from the evidence file named above; the JSON",
        "file and its hash are the evidence. A hash stored in the same file rules out accidental",
        "change, not deliberate rewriting.",
        "",
        f"Generated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} by the evidence review dashboard.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- routes

@app.route("/")
def index():
    loaded = load_all_evidence()
    unreadable = [e for e in loaded if e.get("_load_error")]
    rows = [summarize(e) for e in loaded if not e.get("_load_error")]
    datasets = {
        "corrected": [r for r in rows if not r["legacy"]],
        "legacy": [r for r in rows if r["legacy"]],
    }
    dataset = request.args.get("data", "corrected")
    if dataset not in datasets:
        dataset = "corrected"
    shown = sorted(datasets[dataset], key=lambda r: (r["lifetime"] is None, r["lifetime"] or 0))
    summary = result_summary(shown)
    longest = summary["max_lifetime"] if summary and summary["max_lifetime"] else 1.0
    for r in shown:
        r["bar_w"] = r["lifetime"] / longest * 100 if r["lifetime"] is not None else None
    return render_template(
        "index.html",
        rows=shown,
        summary=summary,
        poll_x=POLL_INTERVAL_SECONDS / longest * 100 if POLL_INTERVAL_SECONDS < longest else None,
        dataset=dataset,
        dataset_sizes={name: len(members) for name, members in datasets.items()},
        unreadable=unreadable,
        mismatches=[r for r in rows if not r["hash_ok"]],
        total=len(loaded),
        field_names=FIELD_NAMES,
        poll_interval=POLL_INTERVAL_SECONDS,
    )


def _evidence_path(filename):
    # Reject anything that isn't a bare filename inside EVIDENCE_DIR --
    # no path traversal via ../, no absolute paths.
    if os.path.basename(filename) != filename or not filename.endswith(".json"):
        abort(404)
    path = os.path.join(EVIDENCE_DIR, filename)
    if not os.path.isfile(path):
        abort(404)
    return path


@app.route("/evidence/<filename>/report.txt")
def report(filename):
    data = load_evidence_file(_evidence_path(filename))
    if data.get("_load_error"):
        abort(404)
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", data.get("container_name") or filename[:-5])
    return Response(
        text_report(data),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}_report.txt"'},
    )


@app.route("/evidence/<filename>")
def detail(filename):
    data = load_evidence_file(_evidence_path(filename))
    if data.get("_load_error"):
        return render_template("detail.html", e=data)
    outcomes = outcomes_for(data)
    return render_template(
        "detail.html",
        e=data,
        field_names=FIELD_NAMES,
        outcomes=outcomes,
        live=live_state(outcomes),
        ended=termination_of(data),
        losses={field: loss_explanations(data, field) for field in FIELDS},
        events=story(data),
        ports=port_rows(data),
        legacy="timing" not in data,
        kill_start_after_exit=kill_trigger_start_after_exit(data),
        poll_interval=POLL_INTERVAL_SECONDS,
    )


def main():
    # PORT override lets a dev copy run alongside a packaged one.
    port = int(os.environ.get("PORT", 5000))
    url = f"http://127.0.0.1:{port}"

    if not getattr(sys, "frozen", False):
        # Dev mode: keep the familiar debug/auto-reload workflow.
        app.run(host="127.0.0.1", port=port, debug=True)
        return

    # Packaged mode: no debugger/reloader (both assume a live source
    # tree and a terminal watching it, neither of which exist in a
    # frozen exe), and open the browser automatically so there's
    # nothing for the person running it to type or configure.
    import threading
    import webbrowser

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"Container Forensics evidence viewer running at {url}")
    print("Close this window to stop it.")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
