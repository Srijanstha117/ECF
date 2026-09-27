"""
listener.py

Three-source evidence capture, built up from what testing actually
proved (see the Issues Faced log in Notion for the full story):

1. "kill" event (reactive, best-effort): races to capture live network/
   process state the moment a stop/kill signal is sent. Works for
   graceful shutdowns with a real grace period; proven to lose the race
   against a hard SIGKILL every time -- kept anyway because it's free
   and occasionally wins.

2. Background poller (proactive, the real fix for SIGKILL): continuously
   snapshots every running container's network/process state in the
   background (see poller.py). When a container dies, its last snapshot
   -- however many milliseconds old -- is used if the reactive capture
   above failed. Staleness is recorded explicitly, not hidden.

3. "die" event (post-mortem, always safe): filesystem diff and logs,
   proven to work fine after death as long as the container object
   hasn't been auto-removed yet.

All three are merged into ONE evidence package per container, with
each field labeled with exactly which source supplied it -- that
provenance is real evaluation data, not just plumbing.

Run with:   python listener.py              (in a terminal, prints as it goes)
            pythonw listener.py --background (no window: what the dashboard
                                              starts; output goes to logs/listener.log)
Stop with:  Ctrl+C in the terminal, or the dashboard's "Stop listener"
            button (it drops a stop-request file this process watches for).
"""

import itertools
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import poller
import runlog
from capture import (
    capture_filesystem_diff,
    capture_logs,
    capture_network_state,
    capture_process_list,
    get_client,
    get_container_finished_at,
    get_container_started_at,
    hash_evidence,
    is_failure,
    measure_daemon_clock_offset,
    parse_docker_timestamp,
)

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")

# Started with --background (by the dashboard, with no window): log to a
# file, wait for Docker instead of failing, and start Docker Desktop.
BACKGROUND = "--background" in sys.argv

# Evidence captured on "kill", keyed by container_id, held until "die"
# fires for the same container.
_pending_live_capture = {}

# ---------------------------------------------------------------- heartbeat
# While running, the listener rewrites a small status file every couple of
# seconds. The dashboard reads it to show "Listener running" or "not
# running, last seen ...", and a second listener refuses to start while
# it's fresh (two listeners capture every death twice). The dot-prefixed
# name keeps it out of the dashboard's evidence list (*.json skips it).
HEARTBEAT_PATH = os.path.join(EVIDENCE_DIR, ".listener.json")
HEARTBEAT_SECONDS = 2
HEARTBEAT_STALE_SECONDS = 6
_started_at = time.time()
_saved = {"count": 0, "last_file": None, "last_at": None}


def _write_heartbeat(state):
    data = {
        "state": state,
        "pid": os.getpid(),
        "started_at": _started_at,
        "last_beat": time.time(),
        "heartbeat_seconds": HEARTBEAT_SECONDS,
        "poll_interval_seconds": poller.POLL_INTERVAL_SECONDS,
        "watching": poller.watching_count(),
        "live": poller.live_resources(),
        "evidence_saved": _saved["count"],
        "last_evidence_file": _saved["last_file"],
        "last_evidence_at": _saved["last_at"],
    }
    tmp = HEARTBEAT_PATH + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, HEARTBEAT_PATH)
    except OSError:
        pass  # e.g. the dashboard had it open for a moment; the next beat retries


# With no window to close, the dashboard's "Stop listener" button asks for
# a stop by creating this file; the heartbeat loop notices it within
# HEARTBEAT_SECONDS. A request older than this listener is ignored.
STOP_REQUEST_PATH = os.path.join(EVIDENCE_DIR, ".listener.stop")
_stopping = threading.Event()
_events_stream = None


def stop_requested():
    try:
        return os.path.getmtime(STOP_REQUEST_PATH) >= _started_at - 1
    except OSError:
        return False


def _clear_stop_request():
    try:
        os.remove(STOP_REQUEST_PATH)
    except OSError:
        pass


def _heartbeat_loop(stop):
    while not stop.wait(HEARTBEAT_SECONDS):
        if stop_requested():
            _clear_stop_request()
            print("[*] Stop requested from the dashboard.")
            _stop_event_loop()
            return
        _write_heartbeat("running")


def _stop_event_loop():
    """End _event_loop from another thread: closing Docker's event stream
    unblocks it. If that doesn't work within 5 s, exit outright -- any
    save in progress is atomic (see save_evidence), so nothing half-written
    is left behind."""
    _stopping.set()
    if _events_stream is not None:
        try:
            _events_stream.close()
        except Exception:
            pass

    def _force():
        time.sleep(5)
        _write_heartbeat("stopped")
        os._exit(0)
    threading.Thread(target=_force, daemon=True).start()


def other_listener_running():
    """The heartbeat of another live listener, or None."""
    try:
        with open(HEARTBEAT_PATH) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    fresh = time.time() - data.get("last_beat", 0) < HEARTBEAT_STALE_SECONDS
    if data.get("state") in ("running", "waiting_docker") and fresh and data.get("pid") != os.getpid():
        return data
    return None


def save_evidence(evidence):
    """Writes the package without ever overwriting or half-writing one.

    The full JSON goes to a temporary file first, then gets hard-linked
    to its final name, which fails rather than replacing an existing file.
    Previously a plain open("w") could leave an empty file if interrupted
    (the unreadable testcontainer6 package), and two listeners handling
    the same death in the same second silently overwrote each other. A
    name collision now gets a _1, _2... suffix instead."""
    base = f"{evidence['container_name']}_{int(evidence['captured_at'])}"
    fd, tmp_path = tempfile.mkstemp(dir=EVIDENCE_DIR, prefix=f".{base}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(evidence, f, indent=2, default=str)
        for n in itertools.count():
            path = os.path.join(EVIDENCE_DIR, f"{base}_{n}.json" if n else f"{base}.json")
            try:
                os.link(tmp_path, path)
                break
            except FileExistsError:
                continue
    finally:
        os.unlink(tmp_path)
    print(f"[+] Evidence saved: {path}")
    _saved.update(count=_saved["count"] + 1, last_file=os.path.basename(path), last_at=time.time())
    return path


def _pick_best(live_result, snapshot_value, snapshot_age):
    """Prefer the live (kill-triggered) result if it's real data.
    Otherwise, ONLY use the poller snapshot if it's ALSO actually real
    data -- not just whatever happened to be sitting there. If both
    sources failed, say so honestly instead of mislabeling a failure
    as a successful rescue (a real bug, caught by testing: the poller
    can itself lose the race against a fast death, and blindly trusting
    its output produced a nonsensical negative-age 'snapshot' that was
    actually just another error)."""
    if not is_failure(live_result):
        return {"source": "live_kill_trigger", "data": live_result}
    if not is_failure(snapshot_value):
        return {
            "source": "poller_snapshot",
            "snapshot_age_seconds": snapshot_age,
            "data": snapshot_value,
        }
    return {
        "source": "none -- both live capture and poller snapshot failed",
        "live_attempt": live_result,
        "snapshot_attempt": snapshot_value,
    }


def _is_sigkill(signal):
    # The daemon reports the signal as a number ("9"); names accepted too.
    return str(signal).upper() in ("9", "SIGKILL", "KILL")


def _parse_docker_ts_or_none(raw):
    if not isinstance(raw, str):
        return None
    try:
        return parse_docker_timestamp(raw).timestamp()
    except ValueError:
        return None


def _reconstruct_timing(started_at_raw, finished_at_raw, sigkill_event_time_ns,
                        die_event_time_ns, die_handled_at):
    """Works out when the container really started and died, from
    Docker's own records rather than from when this code got round to
    handling an event.

    Previously both lifetime and snapshot age were measured from
    time.time() inside the die handler. But the `die` event is late:
    measured on Docker Desktop, it fires 0.26-0.34s AFTER the process
    has exited, while State.FinishedAt lands within 1ms of the SIGKILL.
    So every lifetime and every snapshot age came out ~0.3s too large --
    enough to shift the rescue threshold this project reports.

    The moment of death, best source first:
      1. State.FinishedAt -- the runtime's own exit time, correct for
         any cause of death. Gone once a --rm container is removed.
      2. The SIGKILL kill event -- a process can't outlive SIGKILL.
      3. The die event -- labelled as a fallback, since it's ~0.3s late.

    Returns (lifetime_seconds, timing_details). Lifetime is death minus
    StartedAt, both on the daemon's clock, so no clock conversion is
    involved. Poller snapshot times are on THIS host's clock, though,
    so the death is also converted onto the host clock (via a measured
    offset) for computing snapshot ages. The details record every raw
    timestamp and which source was used, so any file can be re-derived.
    """
    started = _parse_docker_ts_or_none(started_at_raw)
    finished = _parse_docker_ts_or_none(finished_at_raw)
    die_event = die_event_time_ns / 1e9 if die_event_time_ns else None

    if finished is not None:
        death = finished
        death_source = "State.FinishedAt (runtime-reported exit time)"
    elif sigkill_event_time_ns:
        death = sigkill_event_time_ns / 1e9
        death_source = "SIGKILL kill event (FinishedAt unavailable -- container probably already removed)"
    elif die_event is not None:
        death = die_event
        death_source = (
            "FALLBACK: die event -- fires ~0.3s after the real exit on "
            "Docker Desktop, so lifetime and snapshot ages are overstated"
        )
    else:
        death = None
        death_source = "unknown: no FinishedAt, SIGKILL or die timestamp"

    lifetime = None
    lifetime_unavailable_reason = None
    if started is None:
        lifetime_unavailable_reason = f"no usable StartedAt: {started_at_raw!r}"
    elif death is None:
        lifetime_unavailable_reason = "no usable death time"
    else:
        lifetime = death - started

    offset = measure_daemon_clock_offset()
    offset_ok = "error" not in offset
    if death is not None and offset_ok:
        death_time_host = death - offset["offset_seconds"]
        death_time_host_source = "death time converted to host clock via measured offset"
    else:
        death_time_host = die_handled_at
        death_time_host_source = (
            "FALLBACK: when the die handler started -- snapshot ages are "
            "overstated by the exit-to-die delay plus handling lag"
        )

    timing = {
        "container_finished_at_raw": finished_at_raw,
        "sigkill_event_time_ns": sigkill_event_time_ns,
        "die_event_time_ns": die_event_time_ns,
        "death_time_source": death_source,
        "daemon_clock_offset": offset,
        "death_time_host_clock": death_time_host,
        "death_time_host_clock_source": death_time_host_source,
        # How late Docker's own die event was, and how late this code
        # then got to it. Together these are what the old measurement
        # silently added to every lifetime and snapshot age.
        "exit_to_die_event_seconds": (
            die_event - death if die_event is not None and death is not None else None
        ),
        "die_handling_lag_seconds": (
            die_handled_at - (die_event - offset["offset_seconds"])
            if die_event is not None and offset_ok else None
        ),
    }
    if lifetime_unavailable_reason:
        timing["lifetime_unavailable_reason"] = lifetime_unavailable_reason
    return lifetime, timing


def _port_timeline(history, lifetime, death_time_host):
    """Every port and connection the poller saw over the container's life,
    with when each was open. Each time is really a window: a socket first
    seen at one poll opened after the previous poll (or after the
    container started, if it was there at the very first poll), and one
    missing at a poll closed after the last poll that saw it (or when the
    container exited, if it was still open at the end).

    Times are stored both raw (this host's clock, epoch seconds) and as
    seconds since the container started -- the latter only when the time
    of death is known on this host's clock, else None."""
    note = (
        f"From the poller, which reads the socket tables every "
        f"{poller.POLL_INTERVAL_SECONDS} s. A socket that opened and closed "
        "between two reads is never seen."
    )
    if history is None:
        return {"error": "the poller never read this container's sockets before it died", "note": note}

    def since_start(t):
        if t is None or lifetime is None or death_time_host is None:
            return None
        return lifetime - (death_time_host - t)

    sockets = []
    for record in history["sockets"]:
        still_open = record["gone_at"] is None
        sockets.append({
            "proto": record["proto"],
            "local_ip": record["local_ip"],
            "local_port": record["local_port"],
            "remote_ip": record["remote_ip"],
            "remote_port": record["remote_port"],
            "kind": record["kind"],
            "states": record["states"],
            "open_at_exit": still_open,
            # opened somewhere in [opened_after_s, first_seen_s]
            "opened_after_s": since_start(record["not_seen_at"]) if record["not_seen_at"] is not None
            else (0.0 if lifetime is not None else None),
            "first_seen_s": since_start(record["first_seen_at"]),
            # closed somewhere in [last_seen_s, closed_by_s]
            "last_seen_s": since_start(record["last_seen_at"]),
            "closed_by_s": lifetime if still_open else since_start(record["gone_at"]),
            "not_seen_at": record["not_seen_at"],
            "first_seen_at": record["first_seen_at"],
            "last_seen_at": record["last_seen_at"],
            "gone_at": record["gone_at"],
        })
    return {
        "source": "poller history",
        "poll_interval_seconds": poller.POLL_INTERVAL_SECONDS,
        "polls": history["polls"],
        "first_poll_s": since_start(history["first_poll_at"]),
        "last_poll_s": since_start(history["last_poll_at"]),
        "first_poll_at": history["first_poll_at"],
        "last_poll_at": history["last_poll_at"],
        "truncated": history["truncated"],
        "note": note,
        "sockets": sockets,
    }


def _resource_timeline(history, lifetime, death_time_host):
    """CPU %, memory and network over the container's life, one sample per
    poll, with times in seconds since start (when the time of death is
    known on this host's clock) and the raw host-clock time. Also the
    peaks and totals, so the headline figures don't need recomputing."""
    note = (f"Sampled by the poller every {poller.POLL_INTERVAL_SECONDS} s from Docker's stats. "
            "CPU % is relative to one core (200% = two cores busy); memory excludes reclaimable page cache. "
            "Where the poller reads sockets with docker exec (Docker Desktop), that small command runs "
            "inside the container and its CPU counts here: about 3-4% of a core on an idle container in testing.")
    if not history:
        return {"error": "the poller never sampled this container's resource use before it died", "note": note}

    def since_start(t):
        if lifetime is None or death_time_host is None:
            return None
        return round(lifetime - (death_time_host - t), 4)

    samples = [{
        "t_s": since_start(x["at"]),
        "at": x["at"],
        "cpu_pct": x["cpu_pct"],
        "mem_bytes": x["mem_bytes"],
        "rx_bytes": x["rx_bytes"],
        "tx_bytes": x["tx_bytes"],
        "rx_rate": round(x["rx_rate"], 1),
        "tx_rate": round(x["tx_rate"], 1),
    } for x in history["samples"]]
    return {
        "source": "poller stats",
        "interval_seconds": poller.POLL_INTERVAL_SECONDS * history.get("thinned", 1),
        "mem_limit_bytes": history.get("mem_limit_bytes"),
        "peak_cpu_pct": max(x["cpu_pct"] for x in samples),
        "avg_cpu_pct": round(sum(x["cpu_pct"] for x in samples) / len(samples), 2),
        "peak_mem_bytes": max(x["mem_bytes"] for x in samples),
        "total_rx_bytes": samples[-1]["rx_bytes"],
        "total_tx_bytes": samples[-1]["tx_bytes"],
        "note": note,
        "samples": samples,
    }


def handle_kill(container_id, container_name, kill_event_time_ns, signal):
    """Reactive, best-effort: race to capture live-only evidence
    before the process actually exits. Known to lose against SIGKILL;
    kept because it's free and can win against a graceful stop."""
    pending = _pending_live_capture.get(container_id)
    if pending is not None:
        # docker stop sends SIGTERM, then SIGKILL once the grace period
        # runs out. Only capture once, but do note when the SIGKILL
        # landed -- it's a fallback timestamp for the moment of death,
        # and it's what tells "stopped" apart from "stopped, then killed".
        if _is_sigkill(signal) and pending.get("sigkill_event_time_ns") is None:
            pending["sigkill_event_time_ns"] = kill_event_time_ns
        return

    # Read first, before the live-capture race below. It's what lets every
    # evidence file carry its own ground-truth lifetime instead of relying
    # on someone remembering what --delay a test used -- and a --rm
    # container is removed right after "die" (~0.3s after SIGKILL), which
    # is about how long the failed captures below take. Read after them,
    # it was lost for every killed --rm container. Costs ~5ms of a race
    # that SIGKILL wins regardless.
    started_at_raw = get_container_started_at(container_id)

    t0 = time.time()
    print(f"[!] KILL signal detected on {container_name} -- racing to capture live state")

    t_net = time.time()
    network_state = capture_network_state(container_id)
    net_latency = time.time() - t_net

    t_proc = time.time()
    process_list = capture_process_list(container_id)
    proc_latency = time.time() - t_proc

    _pending_live_capture[container_id] = {
        "network_state": network_state,
        "process_list": process_list,
        # Host clock. Recorded because the StartedAt read above can itself
        # stall while Docker finishes handling the exit, so the capture
        # doesn't reliably start "just after" the SIGKILL event.
        "live_capture_started_at": t0,
        "live_capture_latency_seconds": time.time() - t0,
        "network_capture_latency_seconds": net_latency,
        "process_capture_latency_seconds": proc_latency,
        "started_at_raw": started_at_raw,
        "sigkill_event_time_ns": kill_event_time_ns if _is_sigkill(signal) else None,
        # The FIRST signal is what separates `docker kill` (SIGKILL straight
        # away) from `docker stop` (SIGTERM first, SIGKILL only if the
        # container ignores it past the grace period).
        "first_kill_signal": str(signal) if signal is not None else None,
        "first_kill_event_time_ns": kill_event_time_ns,
    }


_SIGNAL_NAMES = {"1": "SIGHUP", "2": "SIGINT", "3": "SIGQUIT", "9": "SIGKILL", "15": "SIGTERM"}


def _termination(first_signal, sigkill_event_time_ns, first_kill_event_time_ns, exit_code):
    """How the container ended, from the signals Docker sent it and its
    exit code:
      - no signal at all            -> it exited on its own
      - SIGKILL first               -> killed (`docker kill`)
      - SIGTERM, no SIGKILL after   -> stopped: shut down within the grace period
      - SIGTERM, then SIGKILL       -> stopped, then force-killed (`docker stop`
                                       timed out)
    """
    name = _SIGNAL_NAMES.get(str(first_signal), f"signal {first_signal}") if first_signal else None
    code = int(exit_code) if exit_code not in (None, "") and str(exit_code).lstrip("-").isdigit() else None
    if first_signal is None:
        verdict = "exited"
        label = "Exited on its own" if code in (0, None) else "Exited on its own with an error"
        detail = "No stop or kill signal was sent; the container's main process ended by itself."
    elif _is_sigkill(first_signal):
        verdict, label = "killed", "Killed"
        detail = "Sent SIGKILL straight away (docker kill), with no chance to shut down."
    elif str(first_signal) in ("15", "SIGTERM", "TERM") and sigkill_event_time_ns:
        verdict, label = "stopped_then_killed", "Stopped, then force-killed"
        after = (sigkill_event_time_ns - first_kill_event_time_ns) / 1e9 if first_kill_event_time_ns else None
        detail = ("Asked to shut down with SIGTERM (docker stop), but it hadn't exited "
                  + (f"{after:.1f} s later" if after is not None else "within the grace period")
                  + ", so it was force-killed with SIGKILL.")
    elif str(first_signal) in ("15", "SIGTERM", "TERM"):
        verdict, label = "stopped", "Stopped"
        detail = "Asked to shut down with SIGTERM (docker stop) and exited within the grace period."
    else:
        verdict, label = "signalled", f"Sent {name}"
        detail = f"Sent {name}" + (", then SIGKILL." if sigkill_event_time_ns else ".")
    return {
        "verdict": verdict,
        "label": label,
        "detail": detail,
        "first_signal": name,
        "first_signal_time_ns": first_kill_event_time_ns,
        "sigkill_sent": bool(sigkill_event_time_ns),
        "exit_code": code,
    }


def handle_die(container_id, container_name, die_event_time_ns, exit_code=None):
    """Post-mortem. ALL FOUR evidence types go through the same rescue
    logic now: try the reactive/direct capture first, fall back to the
    poller's last good snapshot if that fails. filesystem_diff/logs
    were previously treated as "always safe" -- that was wrong. A
    `--rm` container can be fully removed within tens of milliseconds
    of "die" (seen in this project's very first test), which can kill
    a direct capture just as surely as SIGKILL kills a live one."""
    t0 = time.time()
    print(f"[!] DIE detected on {container_name} -- capturing post-mortem evidence")

    reactive = {
        "filesystem_diff": capture_filesystem_diff(container_id),
        "logs": capture_logs(container_id),
    }
    reactive_postmortem_latency = time.time() - t0
    # Straight after the evidence itself: a --rm container is about to be
    # removed, and this is the only exact record of when it died.
    finished_at_raw = get_container_finished_at(container_id)

    live = _pending_live_capture.pop(container_id, {})
    reactive["network_state"] = live.get("network_state")
    reactive["process_list"] = live.get("process_list")

    # StartedAt is normally captured at "kill" time, while the container
    # still existed. Falls back to a best-effort direct check at "die"
    # time only if no kill event was ever seen (which will usually fail
    # for --rm containers already removed by now -- reported honestly,
    # not hidden).
    started_at_raw = live.get("started_at_raw") or get_container_started_at(container_id)
    container_lifetime_seconds, timing = _reconstruct_timing(
        started_at_raw,
        finished_at_raw,
        live.get("sigkill_event_time_ns"),
        die_event_time_ns,
        die_handled_at=t0,
    )

    snapshot = poller.get_last_snapshot(container_id, died_at=timing["death_time_host_clock"])
    captured_at = time.time()

    evidence = {
        "container_id": container_id,
        "container_name": container_name,
        "captured_at": captured_at,
        "container_lifetime_seconds": container_lifetime_seconds,
        "container_started_at_raw": started_at_raw,
        "termination": _termination(
            live.get("first_kill_signal"),
            live.get("sigkill_event_time_ns"),
            live.get("first_kill_event_time_ns"),
            exit_code,
        ),
        "timing": timing,
        "reactive_postmortem_latency_seconds": reactive_postmortem_latency,
        "live_kill_trigger_started_at": live.get("live_capture_started_at"),
        "live_kill_trigger_latency_seconds": live.get("live_capture_latency_seconds"),
    }
    for field in ("network_state", "process_list", "filesystem_diff", "logs"):
        evidence[field] = _pick_best(
            reactive[field],
            snapshot[field],
            snapshot.get(f"{field}_age_seconds"),
        )
    death_host_reliable = "FALLBACK" not in timing["death_time_host_clock_source"]
    evidence["port_timeline"] = _port_timeline(
        snapshot.get("port_history"),
        container_lifetime_seconds,
        timing["death_time_host_clock"] if death_host_reliable else None,
    )
    evidence["resource_timeline"] = _resource_timeline(
        snapshot.get("resource_history"),
        container_lifetime_seconds,
        timing["death_time_host_clock"] if death_host_reliable else None,
    )

    evidence["sha256"] = hash_evidence(evidence)
    save_evidence(evidence)


def main():
    other = other_listener_running()
    if other and "--force" not in sys.argv:
        print(f"[!] Another listener is already running (PID {other['pid']}). Running two captures "
              "every container death twice. Stop the other one first, or pass --force.")
        sys.exit(1)

    _clear_stop_request()  # a leftover request is not meant for this listener

    # Started by the dashboard, Docker Desktop may not be up yet: start it,
    # then wait (saying so in the heartbeat) instead of crashing.
    _write_heartbeat("waiting_docker")
    launched_docker = False
    while True:
        try:
            client = get_client()
            client.ping()
            break
        except Exception as e:
            if not BACKGROUND:
                raise
            if stop_requested():
                _clear_stop_request()
                print("[*] Stop requested while waiting for Docker.")
                return
            if not launched_docker:
                launched_docker = True
                if start_docker_desktop():
                    print("[*] Docker isn't running -- started Docker Desktop.")
            print(f"[*] Waiting for Docker ({str(e).splitlines()[0][:90]})")
            _write_heartbeat("waiting_docker")
            time.sleep(3)

    poller.start()
    stop = threading.Event()
    _write_heartbeat("running")
    threading.Thread(target=_heartbeat_loop, args=(stop,), daemon=True).start()
    print("[*] Listening for container lifecycle events...")
    try:
        _event_loop(client)
    except Exception:
        if not _stopping.is_set():
            raise  # a real failure; a requested stop just breaks the stream
    finally:
        stop.set()
        _write_heartbeat("stopped")
        print("[*] Stopped.")


DOCKER_DESKTOP_PATHS = [
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Docker", "Docker", "Docker Desktop.exe"),
]


def start_docker_desktop():
    """Start Docker Desktop if it's installed (Windows / macOS). Returns
    True if something was launched."""
    try:
        if os.name == "nt":
            exe = next((p for p in DOCKER_DESKTOP_PATHS if os.path.exists(p)), None)
            if exe:
                subprocess.Popen([exe], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                return True
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-a", "Docker"])
            return True
    except OSError as e:
        print(f"[!] Couldn't start Docker Desktop: {e}")
    return False


def _event_loop(client):
    global _events_stream
    _events_stream = client.events(decode=True)
    for event in _events_stream:
        if _stopping.is_set():
            break
        if event.get("Type") != "container":
            continue

        action = event.get("Action")
        actor = event.get("Actor", {})
        container_id = actor.get("ID")
        if not container_id:
            continue
        attributes = actor.get("Attributes", {})
        container_name = attributes.get("name", container_id[:12])
        # Stamped by the daemon when the event was emitted, not when this
        # loop got round to reading it.
        event_time_ns = event.get("timeNano")

        if action == "kill":
            handle_kill(container_id, container_name, event_time_ns, attributes.get("signal"))
        elif action == "die":
            handle_die(container_id, container_name, event_time_ns, attributes.get("exitCode"))


if __name__ == "__main__":
    # No window (pythonw / --background): print() and any crash go to
    # logs/listener.log, which the dashboard's Logs page shows.
    runlog.log_to_file_if_windowless(LOGS_DIR, "listener")
    try:
        main()
    except KeyboardInterrupt:
        pass  # main() has already said "Stopped."
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
