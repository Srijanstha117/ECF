"""
poller.py

Proactive evidence capture -- the fix for what reactive (event-
triggered) capture provably cannot do.

Originally built for network/process state (can't survive a SIGKILL
death, proven by testing). Extended to ALSO cover filesystem_diff and
logs, because the exact same class of problem applies to them: a
`--rm` container can be fully removed within tens of milliseconds of
"die" firing (seen in the very first test of this project), which
would kill a die-triggered filesystem_diff/logs capture just as surely
as SIGKILL kills a kill-triggered network/process capture. Same
disease, same fix: snapshot continuously, before it's too late, rather
than reacting after the fact.

A poll cycle can itself lose the race against a fast death -- so a
stored snapshot is ONLY ever overwritten by a NEW one if that new
capture actually succeeded. A failed cycle never overwrites
previously-good data with garbage. Each field tracks its own success
and timestamp independently, since they don't all succeed or fail
together.
"""

import threading
import time

from capture import (
    capture_filesystem_diff,
    capture_logs,
    capture_network_state,
    capture_process_list,
    capture_resource_counters,
    get_client,
    is_failure,
    resource_delta,
)

POLL_INTERVAL_SECONDS = 0.5  # tunable -- lower = fresher snapshots, more overhead

_CAPTURE_FIELDS = {
    "network_state": capture_network_state,
    "process_list": capture_process_list,
    "filesystem_diff": capture_filesystem_diff,
    "logs": capture_logs,
}

_latest_snapshot = {}
_lock = threading.Lock()
_watching = 0  # running containers seen by the last poll cycle (for the listener's heartbeat)
_running_ids = set()
_stop_flag = threading.Event()

# Per-container history of every socket (listening port or connection)
# the poller has seen. The snapshot above only keeps the LATEST network
# table, so without this there'd be no way to say when a port opened or
# closed. Each record carries the poll times either side of the change,
# because a poll only ever sees the state at one instant: a port first
# seen at poll N opened somewhere between poll N-1 and poll N.
_port_history = {}
_MAX_SOCKETS_PER_CONTAINER = 500  # a busy server could otherwise grow this without bound
_SOCKET_FIELDS = ("proto", "local_ip", "local_port", "remote_ip", "remote_port", "kind")


# Per-container CPU / memory / network history, one sample per poll cycle,
# for the evidence ("how hard was it working before it died?"). Kept whole
# up to _MAX_RESOURCE_SAMPLES, then halved in resolution each time it
# fills, so a long-lived container keeps its whole life at coarser detail.
_resources = {}
_MAX_RESOURCE_SAMPLES = 1200


def _record_resources(cid, name, counters, at):
    """Record one reading. Caller holds _lock."""
    history = _resources.setdefault(cid, {"name": name, "last": None, "samples": []})
    last = history["last"]
    delta = resource_delta(last["counters"], counters, at - last["at"]) if last else None
    history["last"] = {"counters": counters, "at": at}
    if delta is None:
        return  # the first reading only anchors the next one
    sample = {
        "at": at,
        "cpu_pct": delta["cpu_pct"],
        "mem_bytes": counters["mem_bytes"],
        "rx_bytes": counters["rx_bytes"],
        "tx_bytes": counters["tx_bytes"],
        "rx_rate": delta["rx_rate"],
        "tx_rate": delta["tx_rate"],
    }
    history["samples"].append(sample)
    history["latest"] = {**sample, "mem_limit_bytes": counters["mem_limit_bytes"], "pids": counters["pids"]}
    if len(history["samples"]) > _MAX_RESOURCE_SAMPLES:
        history["samples"] = history["samples"][::2]
        history["thinned"] = history.get("thinned", 1) * 2


def live_resources():
    """The latest figures for every running container, for the dashboard."""
    with _lock:
        return [
            {"id": cid[:12], "name": h["name"], **{k: v for k, v in h["latest"].items() if k != "at"},
             "sampled_at": h["latest"]["at"]}
            for cid, h in _resources.items()
            if h.get("latest") and cid in _running_ids
        ]


def _socket_key(sock):
    return (sock["proto"], sock["local_ip"], sock["local_port"], sock["remote_ip"], sock["remote_port"])


def _update_port_history(cid, sockets, seen_at):
    """Record one successful network read. Caller holds _lock."""
    history = _port_history.setdefault(cid, {
        "first_poll": seen_at, "last_poll": None, "polls": 0,
        "open": {}, "closed": [], "truncated": False,
    })
    previous_poll = history["last_poll"]
    present = set()
    for sock in sockets:
        key = _socket_key(sock)
        present.add(key)
        record = history["open"].get(key)
        if record is None:
            if len(history["open"]) + len(history["closed"]) >= _MAX_SOCKETS_PER_CONTAINER:
                history["truncated"] = True
                continue
            record = {field: sock[field] for field in _SOCKET_FIELDS}
            record.update({
                # None = it was already there at the first poll we made
                "not_seen_at": previous_poll,
                "first_seen_at": seen_at,
                "last_seen_at": seen_at,
                "gone_at": None,
                "states": [sock["state"]],
            })
            history["open"][key] = record
        else:
            record["last_seen_at"] = seen_at
            if record["states"][-1] != sock["state"]:
                record["states"].append(sock["state"])
    for key in [k for k in history["open"] if k not in present]:
        record = history["open"].pop(key)
        record["gone_at"] = seen_at
        history["closed"].append(record)
    history["last_poll"] = seen_at
    history["polls"] += 1


def _poll_loop():
    global _watching, _running_ids
    client = get_client()
    while not _stop_flag.is_set():
        cycle_start = time.time()
        try:
            running = client.containers.list()  # running containers only
            _watching = len(running)
            _running_ids = {c.id for c in running}
            for container in running:
                cid = container.id
                # Each field is timestamped when ITS capture started.
                # Previously one timestamp was taken after all four had
                # finished, which made network_state (captured first) look
                # fresher than it really was. Start-of-capture is the
                # conservative choice: whatever state was read, it was read
                # no earlier than this, so the age reported at death is an
                # upper bound on staleness, never an understatement.
                results = {}
                for field, fn in _CAPTURE_FIELDS.items():
                    started = time.time()
                    results[field] = (started, fn(cid))
                resources_at = time.time()
                counters = capture_resource_counters(cid)

                with _lock:
                    if counters is not None:
                        _record_resources(cid, container.name, counters, resources_at)
                    entry = _latest_snapshot.setdefault(cid, {})
                    for field, (started, result) in results.items():
                        if not is_failure(result):
                            entry[field] = result
                            entry[f"{field}_snapshot_at"] = started
                    started, network = results["network_state"]
                    if not is_failure(network) and "sockets" in network:
                        _update_port_history(cid, network["sockets"], started)
        except Exception as e:
            print(f"[poller] error during poll cycle: {e}")

        # NOTE: previously this waited the full POLL_INTERVAL_SECONDS
        # regardless of how long the cycle itself took, meaning the real
        # gap between cycles was actually (cycle time + interval), not
        # the interval alone -- a real accuracy bug, not just a cosmetic
        # one, since it silently made every snapshot staler than the
        # configured interval implied. Fixed: only wait for whatever time
        # remains, and say so plainly when a cycle can't keep pace at all.
        cycle_duration = time.time() - cycle_start
        if cycle_duration > POLL_INTERVAL_SECONDS:
            print(
                f"[poller] WARNING: poll cycle took {cycle_duration:.3f}s, "
                f"longer than the {POLL_INTERVAL_SECONDS}s target interval -- "
                "falling behind schedule. Real snapshot freshness is worse "
                "than POLL_INTERVAL_SECONDS alone suggests."
            )
        _stop_flag.wait(max(0.0, POLL_INTERVAL_SECONDS - cycle_duration))


def start():
    """Starts the background poller. Call once, before listening for
    events. Runs as a daemon thread so it never blocks the program
    from exiting."""
    _stop_flag.clear()
    thread = threading.Thread(target=_poll_loop, daemon=True)
    thread.start()
    print(f"[*] Background poller started (snapshotting every {POLL_INTERVAL_SECONDS}s)")


def stop():
    _stop_flag.set()


def watching_count():
    """How many running containers the last poll cycle covered."""
    return _watching


def get_last_snapshot(container_id, died_at=None):
    """Retrieve the most recent successful pre-death snapshot for a
    container, per field. A field that never succeeded says so
    honestly rather than returning stale garbage. Ages are per-field,
    since different fields may have last succeeded at different times.

    died_at must be the actual moment of death on THIS host's clock
    (listener.py derives it from State.FinishedAt), not whenever the
    die handler happened to run -- Docker's die event arrives ~0.3s
    after the real exit, which would silently inflate every age.

    A slightly negative age is possible, and honest, for filesystem_diff
    and logs only: both stay readable after death until the container
    is removed, so a poll can capture them a few ms post-mortem. Network
    state and the process list can't be captured after death at all, so
    theirs can only dip below zero by the clock-offset uncertainty."""
    with _lock:
        entry = _latest_snapshot.pop(container_id, {})
        history = _port_history.pop(container_id, None)
        resources = _resources.pop(container_id, None)

    result = {
        "port_history": _finish_port_history(history),
        "resource_history": None if not resources or not resources["samples"] else {
            "samples": resources["samples"],
            "mem_limit_bytes": (resources.get("latest") or {}).get("mem_limit_bytes"),
            "thinned": resources.get("thinned", 1),
        },
    }
    for field in _CAPTURE_FIELDS:
        ts_key = f"{field}_snapshot_at"
        if field in entry:
            result[field] = entry[field]
            if died_at is not None:
                result[f"{field}_age_seconds"] = died_at - entry[ts_key]
        else:
            result[field] = {
                "error": f"no successful poller snapshot was ever captured for '{field}' before the container died"
            }
    return result


def _finish_port_history(history):
    """Every socket seen over the container's life, closed ones first in
    the order they closed, then those still open at the last poll (their
    gone_at is None: they ended when the container itself did)."""
    if history is None:
        return None
    return {
        "first_poll_at": history["first_poll"],
        "last_poll_at": history["last_poll"],
        "polls": history["polls"],
        "truncated": history["truncated"],
        "sockets": history["closed"] + list(history["open"].values()),
    }
