"""
capture.py

Evidence capture functions for a single container. Each function pulls
one type of evidence and returns it as plain Python data (dict/str/list)
so it can be hashed and dumped to JSON by listener.py.

None of this is exotic -- it's the same primitives `docker` CLI uses
under the hood (docker top / docker diff / docker logs), just called
through the Docker API directly so it can run unattended.
"""

import datetime
import hashlib
import ipaddress
import json
import re
import threading
import time

import docker

# The client is created lazily, on first use, rather than the moment this
# module is imported. docker.from_env() tries to connect to the Docker
# daemon immediately -- if Docker Desktop isn't running yet (or is still
# starting up), an eager connection here would crash on `import capture`
# with a confusing stack trace, before anything useful even ran.
#
# Scoped per-thread (not a single shared global) because this project
# genuinely has two threads hitting the Docker API concurrently -- the
# main event loop and the background poller -- and docker-py's client
# isn't guaranteed thread-safe for concurrent use. Each thread lazily
# creates and caches its own client on first use here.
_thread_local = threading.local()


def get_client():
    if not hasattr(_thread_local, "client"):
        try:
            _thread_local.client = docker.from_env()
        except docker.errors.DockerException as e:
            raise RuntimeError(
                "Can't reach the Docker daemon. Is Docker Desktop open and "
                f"running? (underlying error: {e})"
            ) from e
    return _thread_local.client


def capture_process_list(container_id):
    """Process list from inside the container, as the host sees it.
    Equivalent to `docker top <container>`."""
    try:
        return get_client().api.top(container_id)
    except docker.errors.APIError as e:
        return {"error": str(e)}


def capture_filesystem_diff(container_id):
    """Filesystem changes vs. the base image. Equivalent to `docker diff`.
    Docker computes this from the union filesystem layers, so it's cheap
    even on a large image -- it only reports what actually changed.
    Kind: 0 = modified, 1 = added, 2 = deleted.

    Docker answers None (not []) when nothing changed. That used to go
    straight through, and is_failure(None) is True -- so every container
    that never touched its filesystem was reported as having LOST its
    filesystem evidence. None is normalised to [] here: errors always
    arrive as exceptions, so None can only mean "no changes"."""
    try:
        return get_client().api.diff(container_id) or []
    except docker.errors.APIError as e:
        return {"error": str(e)}


def capture_logs(container_id, tail=200):
    """Recent stdout/stderr, timestamped. Equivalent to `docker logs`."""
    try:
        raw = get_client().api.logs(container_id, tail=tail, timestamps=True)
        return raw.decode("utf-8", errors="replace")
    except docker.errors.APIError as e:
        return {"error": str(e)}


# The socket tables read on every network capture. tcp/udp are IPv4,
# tcp6/udp6 IPv6 (an IPv4 service bound to [::] only shows up in tcp6).
PROC_NET_TABLES = ("tcp", "tcp6", "udp", "udp6")

# One exec reads all four tables, each preceded by a "### <name>" marker:
# tcp and udp tables are identical line by line, so without the markers
# there'd be no telling them apart.
_EXEC_READ_TABLES = [
    "sh", "-c",
    'for f in tcp tcp6 udp udp6; do echo "### $f"; cat /proc/net/$f 2>/dev/null; done',
]

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _hex_ip(hex_addr):
    """Kernel hex address -> dotted/colon notation. IPv4 is one 32-bit word
    in host (little-endian) byte order; IPv6 is four such words."""
    if len(hex_addr) == 8:
        return str(ipaddress.IPv4Address(bytes.fromhex(hex_addr)[::-1]))
    raw = b"".join(bytes.fromhex(hex_addr[i:i + 8])[::-1] for i in range(0, 32, 8))
    addr = ipaddress.IPv6Address(raw)
    return str(addr.ipv4_mapped or addr)


def parse_proc_net(text):
    """Parses the "### tcp" / tcp6 / udp / udp6 tables into one dict per
    socket: protocol, local and remote address/port, state, and whether
    it's a listening port or a connection. Lines that don't parse are
    skipped, never guessed at -- the raw text is kept in the evidence."""
    sockets, proto = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("### "):
            proto = line[4:].strip()
            continue
        if not line or proto not in PROC_NET_TABLES or line.startswith("sl"):
            continue
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_hex, local_port_hex = fields[1].split(":")
            remote_hex, remote_port_hex = fields[2].split(":")
            code = fields[3].upper()
            local_ip, remote_ip = _hex_ip(local_hex), _hex_ip(remote_hex)
            local_port, remote_port = int(local_port_hex, 16), int(remote_port_hex, 16)
        except ValueError:
            continue
        if proto.startswith("tcp"):
            state = _TCP_STATES.get(code, code)
            kind = "listening" if state == "LISTEN" else "connection"
        else:
            # UDP has no LISTEN: 07 means bound and waiting, 01 connected.
            state = {"07": "BOUND", "01": "CONNECTED"}.get(code, code)
            kind = "listening" if code == "07" else "connection"
        sockets.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "kind": kind,
            "inode": fields[9],
        })
    return sockets


def _read_proc_net_direct(container_id):
    """Fast path: read /proc/<pid>/net/{tcp,tcp6,udp,udp6} directly from
    the host, using the container's host-side PID (from `docker inspect`).

    PLATFORM CAVEAT, and it's a real one -- not a minor footnote: this
    only works when the code running this capture shares a kernel with
    the Docker daemon and its containers, i.e. a native Linux host.
    Docker Desktop on Windows/Mac runs containers inside a hidden Linux
    VM, so there is NO /proc/<pid> visible from the Windows/Mac side at
    all -- this will always fail there, by platform design, not a bug.
    It's expected to work once tested against your AWS EC2/ECS target,
    which is real Linux. Test this specifically there before concluding
    whether the fast path actually helps.

    Returns {'ok': True, 'data': ...} or {'ok': False, 'error': ...}.
    """
    try:
        inspect_data = get_client().api.inspect_container(container_id)
        pid = inspect_data.get("State", {}).get("Pid")
        if not pid:
            return {"ok": False, "error": "docker inspect reported no host PID (process likely already gone)"}
        parts = []
        for name in PROC_NET_TABLES:
            try:
                with open(f"/proc/{pid}/net/{name}", "r") as f:
                    parts.append(f"### {name}\n{f.read()}")
            except FileNotFoundError:
                if name == "tcp":
                    raise  # no /proc/<pid> at all -- the platform case below
                # tcp6/udp6 are simply absent when IPv6 is disabled
        return {"ok": True, "data": "".join(parts)}
    except FileNotFoundError:
        return {
            "ok": False,
            "error": (
                "/proc/<pid> not accessible from this host -- expected on "
                "Docker Desktop (Windows/Mac), which isolates containers "
                "inside a VM. Should work on a native Linux host."
            ),
        }
    except docker.errors.APIError as e:
        return {"ok": False, "error": str(e)}


def _exec_read_proc_net(container_id):
    """Slow fallback path -- docker exec inside the container. Requires
    the container to still have a live process to exec into, and pays
    the cost of a full exec session (create, start, wait for output)
    on every call.

    The exit code is checked: previously it was ignored, so an image
    without the needed binary would have had its error message recorded
    as if it were the socket table. Images with no shell (distroless)
    fall back to `cat` of the IPv4 TCP table alone."""
    try:
        container = get_client().containers.get(container_id)
        code, output = container.exec_run(_EXEC_READ_TABLES)
        text = output.decode("utf-8", errors="replace")
        if code == 0:
            return text
        code, output = container.exec_run(["cat", "/proc/net/tcp"])
        text = output.decode("utf-8", errors="replace")
        if code == 0:
            return "### tcp\n" + text
        return {"error": f"exec exited {code}: {text.strip()[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def capture_network_state(container_id):
    """Open connections inside the container's network namespace.

    Two-tier: tries the fast /proc-based read first (see
    _read_proc_net_direct's docstring for the platform caveat), falls back
    to the slower docker-exec method if that's unavailable. Records
    which method actually worked and how long the whole attempt took --
    that comparison is real evaluation data, not just plumbing detail,
    since it's exactly what your Results section needs to report.

    IMPORTANT: even the fast path only helps if the process hasn't
    already exited by the time this runs -- by the time you get a
    `die` event, it's already too late either way. This is exactly the
    'order of volatility' problem from your DFIR notes, playing out in
    miniature inside a single capture function.

    The raw tables are kept as captured ("data"); "sockets" is the same
    content parsed into readable ports and connections.
    """
    t0 = time.time()
    proc_result = _read_proc_net_direct(container_id)
    if proc_result.get("ok"):
        return {
            "method": "proc",
            "latency_seconds": time.time() - t0,
            "data": proc_result["data"],
            "sockets": parse_proc_net(proc_result["data"]),
        }

    exec_result = _exec_read_proc_net(container_id)
    result = {
        "method": "exec_fallback",
        "proc_unavailable_reason": proc_result["error"],
        "latency_seconds": time.time() - t0,
        "data": exec_result,
    }
    if isinstance(exec_result, str):
        result["sockets"] = parse_proc_net(exec_result)
    return result


def is_failure(result):
    """True if a capture result is an error placeholder rather than
    real data. Shared between listener.py and poller.py so both agree
    on what counts as 'this actually worked' -- a bug earlier came from
    only checking this in one place and not the other."""
    if result is None:
        return True
    if not isinstance(result, dict):
        return False  # e.g. a raw proc-read string -- real data
    if "error" in result:
        return True
    data = result.get("data")
    if isinstance(data, dict) and "error" in data:
        return True
    return False


def _get_state_timestamp(container_id, key):
    try:
        state = get_client().api.inspect_container(container_id)["State"]
        raw = state.get(key)
        if not raw or raw.startswith("0001-01-01"):
            return {"error": f"no valid {key} timestamp available"}
        return raw
    except Exception as e:
        return {"error": str(e)}


def get_container_started_at(container_id):
    """Docker's own record of when the container actually started,
    straight from `docker inspect`. Used to compute real container
    lifetime in the evidence -- so test results carry their own ground
    truth instead of relying on separately remembering what --delay
    was used for a given run, which doesn't scale and isn't rigorous."""
    return _get_state_timestamp(container_id, "StartedAt")


def get_container_finished_at(container_id):
    """The container runtime's own record of when the process actually
    exited -- the real moment of death, whatever caused it (SIGKILL,
    graceful stop, natural exit, OOM). Measured against the `die` event
    on Docker Desktop, `die` fires 0.26-0.34s AFTER this, so the event
    time is not a substitute. Only readable until the container is
    removed, so a --rm container may already have lost it."""
    return _get_state_timestamp(container_id, "FinishedAt")


_DOCKER_TS_RE = re.compile(
    r"^(?P<base>[^.]+?)(?:\.(?P<frac>\d+))?(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)


def parse_docker_timestamp(raw):
    """Docker timestamps are RFC3339 with nanosecond precision (e.g.
    '2026-08-11T11:13:16.123456789Z'). Python's datetime only handles
    microseconds, so the fractional part is trimmed to 6 digits -- and
    padded back up to 6, because Go drops trailing zeros ('.23Z'), which
    Python < 3.11 refuses to parse. A numeric UTC offset (a daemon whose
    local timezone isn't UTC) is honoured rather than silently dropped."""
    m = _DOCKER_TS_RE.match(raw)
    if not m:
        raise ValueError(f"unrecognised Docker timestamp: {raw!r}")
    frac = (m["frac"] or "")[:6].ljust(6, "0")
    tz = "+00:00" if m["tz"] in (None, "Z") else m["tz"]
    return datetime.datetime.fromisoformat(f"{m['base']}.{frac}{tz}")


def measure_daemon_clock_offset(samples=3):
    """Daemon clock minus host clock, in seconds.

    Docker's own timestamps (StartedAt, event timeNano) come from the
    daemon's clock; the poller's snapshot times come from this host's
    clock. On Docker Desktop those are two different machines -- the
    daemon runs inside a Linux VM -- so they can't be subtracted from
    each other directly. This asks the daemon for its current time
    (/info SystemTime) and compares it against the host time halfway
    through the request, NTP-style: the true offset lies within +/- half
    the round trip. Of a few samples, the one with the shortest round
    trip is kept, since it gives the tightest bound."""
    best_rtt, best_offset = None, None
    try:
        for _ in range(samples):
            t_send = time.time()
            system_time_raw = get_client().info()["SystemTime"]
            t_recv = time.time()
            rtt = t_recv - t_send
            if best_rtt is None or rtt < best_rtt:
                daemon_now = parse_docker_timestamp(system_time_raw).timestamp()
                best_rtt, best_offset = rtt, daemon_now - (t_send + t_recv) / 2
    except Exception as e:
        return {"error": f"could not measure daemon clock offset: {e}"}
    return {"offset_seconds": best_offset, "uncertainty_seconds": best_rtt / 2}


def hash_evidence(evidence_dict):
    """SHA-256 hash of the evidence package, for integrity verification.
    This is what lets you claim in the report that evidence wasn't
    altered after capture -- the forensic soundness principle."""
    canonical = json.dumps(evidence_dict, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def build_evidence_package(container_id, container_name):
    """Pull every evidence type and package it with metadata + hash.

    Order matters here: network state is the most volatile (see the
    docstring above), so it's captured first, before anything else has
    a chance to slow things down.
    """
    evidence = {
        "container_id": container_id,
        "container_name": container_name,
        "captured_at": time.time(),
        "network_state": capture_network_state(container_id),
        "process_list": capture_process_list(container_id),
        "filesystem_diff": capture_filesystem_diff(container_id),
        "logs": capture_logs(container_id),
    }
    evidence["sha256"] = hash_evidence(evidence)
    return evidence
