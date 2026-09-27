# Forensic Evidence Capture for Ephemeral Containers — Full Project Context

This document exists so a fresh Claude Code session (or any developer with no
prior context) can pick this project up and continue or rebuild it correctly,
without repeating mistakes already found and fixed. Paste this whole file as
the first message in a new Claude Code session, or point Claude Code at this
file directly if it has folder access.

## 1. What this is and why

**FYP context:** Final year BSc (Hons) Computer Networking & IT Security,
Islington College (London Met), module CS6P05NI.

**The research problem:** Containers are ephemeral by design — they can be
killed, auto-removed (`--rm`), or rescheduled within seconds. Forensic
evidence that would normally persist on a host (live network connections,
running processes, filesystem changes, logs) is lost the moment a container
terminates, unless it's actively captured before that happens. Published
research explicitly notes the literature on evidence collection from
containerized applications is limited, with a specific gap around analyzing
container runtime events for forensic investigation — this is under-researched,
not just under-tooled.

**The actual research question this project answers empirically:** Can
reactive, event-triggered capture (react to a kill/die signal, then grab
evidence) reliably rescue evidence before it's gone? Answer, proven through
real testing, not assumed: **no** — reactive capture provably cannot win
against a hard `SIGKILL`, because process death is near-instantaneous and even
a ~300ms reactive capture latency is too slow. This motivated a second
architecture (continuous background polling) which **was** proven to work,
with a measured empirical threshold.

## 2. Architecture

Three evidence sources, merged into one package per container, each field
individually labeled with which source actually supplied it:

1. **Reactive "kill" handler** (`listener.py: handle_kill`) — best-effort. On
   a `kill` Docker event, races to capture live network state + process list
   before the process actually dies. Proven to lose against `SIGKILL` every
   time; kept because it's free and can win against a graceful `docker stop`
   with a real grace period.

2. **Background poller** (`poller.py`) — the actual fix for what reactive
   capture cannot do. Runs on a separate thread, continuously snapshotting
   *every running container's* network state, process list, filesystem diff,
   and logs every 0.5s (`POLL_INTERVAL_SECONDS`). When a container dies, its
   last successful snapshot — however many milliseconds old — is used if the
   reactive/direct capture failed. Critical design rule: **a stored snapshot
   is only ever overwritten by a new one if the new capture itself
   succeeded** — a failed poll cycle never clobbers previously-good data with
   garbage (this was a real bug, see §5).
   **Port history (added 2026-09-26):**
   - Each network read covers all four socket tables (tcp, tcp6, udp, udp6)
     in one exec, split by `### <table>` markers, and is parsed into
     sockets by `capture.parse_proc_net`.
   - The poller keeps `_port_history` per container. For every port or
     connection it records the poll before it was first seen, when it was
     first and last seen, and the poll where it had gone.
   - At death, `listener._port_timeline` turns this into
     `evidence["port_timeline"]`, holding windows in seconds since start
     (opened between X and Y, closed between Y and Z) plus the raw
     host-clock times.
   - Anything that opens and closes between two polls (0.5s) is never seen,
     and the evidence says so. It is capped at 500 sockets per container.
   **Resource use (added 2026-09-27):**
   - Each poll also takes Docker's one-shot stats (~10 ms; the normal call
     waits 1 s) via `capture.capture_resource_counters`.
   - CPU % comes from the difference between consecutive readings
     (`resource_delta`, 100% = one core), plus memory (excluding page
     cache) and network in/out.
   - The poller keeps a history per container, halving its resolution
     when it passes 1200 samples, and `live_resources()` holds the latest
     figures.
   - The listener publishes those live figures in its heartbeat and writes
     `evidence["resource_timeline"]` (samples, peaks, totals) at death.
   - **Finding:** on Docker Desktop, the poller's `docker exec` socket read
     runs inside the container and counts against it: about 3-4% of a core
     on an idle container (seen in testing). The evidence note says so.
   **How it ended (added 2026-09-27):** `handle_kill` records the first
   signal, and `handle_die` the exit code from the die event.
   `evidence["termination"]` then says one of four things:
   - killed: SIGKILL first (`docker kill`);
   - stopped: SIGTERM, exited within the grace period;
   - stopped, then force-killed: SIGTERM, then SIGKILL after the grace
     period;
   - exited on its own, with its exit code.
   All four were verified with real containers. Older packages are inferred
   in the GUI and marked "inferred". A graceful `docker stop` gives the
   kill-trigger capture time to succeed; it saved network and processes
   directly in the test.

3. **Post-mortem "die" handler** (`listener.py: handle_die`) — filesystem diff
   and logs, which normally still work after death as long as the container
   object hasn't been auto-removed yet. But a `--rm` container can be fully
   removed within tens of milliseconds of `die` firing (seen in this
   project's very first test), so even these two fields go through the same
   rescue logic as network/process — direct capture first, poller fallback
   second.

**Merge logic** (`listener.py: _pick_best`): for every field, prefer the live
result if it's real data; otherwise use the poller snapshot only if *that*
is also real data (not itself a failure); otherwise report honestly that both
sources failed. Never mislabel a failure as a successful rescue.

**Integrity:** every evidence package is SHA-256 hashed at capture time
(`capture.py: hash_evidence`), hashing everything except the hash field
itself, using `json.dumps(data, sort_keys=True, default=str)`.

## 3. Empirical findings (already proven, don't re-derive from scratch)

- Reactive-only capture on a hard `docker kill` fails for network/process
  state every time — `live_capture_latency_seconds` (~285-300ms) always
  exceeds SIGKILL's near-instant death.
- A positive-control test *without* `--rm` still showed only 2/4 fields
  (filesystem_diff, logs) succeeding reactively; network_state/process_list
  require a still-living process and fail with "container not running"
  regardless of `--rm`.
- **Rescue threshold — legacy data.** The first 14-trial sweep (Aug 11–12,
  via `tools/test_rescue_threshold.py --delay N`) recorded every lifetime
  and snapshot age ~0.3s too high (timing bug, §5). It also shows no sharp
  cut-off: a trial recorded at 0.723s was lost, while one at 0.546s was
  rescued. Corrected, those are ~0.38s and ~0.21s. `analyze_evidence.py`
  and the GUI mark these files `legacy`. Don't mix them with corrected
  data.
- **Rescue threshold — corrected data** (2026-09-26, 16 trials including 4
  `--rm`; files with a `timing` block). Of the containers whose real
  lifetime was ≤0.454s, 1 in 5 was rescued. All 11 at ≥0.639s were
  rescued, with all four fields, including `--rm` containers, where the
  poller supplied everything. Real lifetime ≈ `--delay` + ~0.15s
  (start/kill API overhead). The transition lies somewhere between ~0.45s
  and ~0.65s, but n is too small to pin it down. Rescue there is expected
  to be *probabilistic*: a new container's first snapshot lands at a random
  point in the 0.5s poll period. The Phase 3 harness should report a
  rescue-probability curve with many trials per delay, not a single
  threshold.
- **Docker Desktop's `die` event is ~0.3s late.** Across every trial on
  2026-09-26, `die` fired 0.25–0.34s after the process exited.
  `State.FinishedAt` falls within 1ms of the SIGKILL `kill` event (12/12).
  Two consequences:
  - A `die`-triggered capture of anything that needs a live process is
    structurally impossible, however fast the handler is.
  - The `die` event's time must never be treated as the time of death.
  The die handler itself runs only ~20ms after the event. The kill
  handler's ~0.3s attempt *overlaps* Docker's own delay instead of adding
  to it. (The first diagnosis blamed handler queueing — wrong, and
  recorded here so nobody re-derives it.)
- Poller-side `docker exec cat /proc/net/tcp` takes ~30–55ms when it
  succeeds. The ~300ms `live_capture_latency_seconds` in the kill handler is
  the *failure* path (inspect + exec against a dying container → 409).
- **Docker API calls against a SIGKILLed container stall until the daemon
  finishes handling the exit** (2026-09-26, 2 trials after
  `live_kill_trigger_started_at` was added). Whichever call reaches the
  dying container first absorbs the ~0.25–0.3s wait: previously the
  `exec`, now the `StartedAt` inspect that runs first. After that, the
  kill-trigger capture itself fails in ~10–14ms. It started 0.24–0.32s
  after exit, right as the late `die` event fired. So the ~0.3s is one
  daemon-side delay, seen three ways: the exec latency, the die-event
  delay, and the capture's late start.
- **Platform-dependent network capture path**: `capture.py` has a two-tier
  network capture (fast `/proc/<pid>/net/tcp` read vs. slow `docker exec cat
  /proc/net/tcp` fallback). The fast path requires sharing a kernel/PID
  namespace with the Docker daemon. Tested and found to *always* fall back to
  `exec_fallback` on: Windows + Docker Desktop, and WSL2 Ubuntu + Docker
  Desktop's WSL2 integration backend. Root cause identified: Docker Desktop's
  WSL2 backend still runs containers inside its own separate internal
  `docker-desktop` distro/VM, not the user's own WSL distro — so even genuine
  Linux kernel doesn't help if Docker Desktop specifically is what's running
  the daemon. **Not yet tested**: native Docker Engine (not Docker Desktop) on
  a genuine Linux host (WSL2 with `dockerd` installed directly via
  `get.docker.com`, bypassing Docker Desktop's WSL integration entirely, or a
  cloud VM). This remains the one open empirical question.

## 4. Current file structure

```
code/
├── README.md
├── requirements.txt          -- docker>=7.0.0, flask>=3.0.0, PyJWT>=2.8
├── start.vbs                 -- double-click (Windows): starts everything with no windows, opens the browser
├── start.py                  -- the same for any OS (venv python start.py)
├── logs/                     -- listener.log / dashboard.log from windowless runs (git-ignored; Logs page)
├── PROJECT_CONTEXT.md         -- this file
├── PRODUCT.md                 -- product facts for design work (users, constraints, principles)
├── DESIGN.md                  -- the GUI's visual system (tokens, rules, components)
├── .impeccable/               -- design-tool metadata (design.json sidecar, surface brief)
├── src/                       -- core artifact only
│   ├── capture.py             -- evidence-pulling primitives
│   ├── runlog.py              -- print() to logs/<name>.log when there's no console (copy in gui/)
│   ├── listener.py            -- main event loop, kill/die handlers, merge logic
│   └── poller.py               -- background proactive snapshotting
├── tools/                     -- dev/evaluation utilities, not part of the artifact
│   ├── analyze_evidence.py    -- summarizes evidence/ into a sorted table
│   ├── test_rescue_threshold.py -- automates the rescue-threshold sweep
│   └── debug_events.py        -- prints raw Docker events, unfiltered
├── tests/
│   ├── test_timing.py         -- regression tests for lifetime/age timing (no Docker needed)
│   ├── test_ports.py          -- socket-table parsing, port history windows, safe evidence writes
│   ├── test_resources.py      -- CPU % maths, resource history thinning, resource timeline
│   ├── test_auth.py           -- accounts, JWT sessions, revocation, lockout, setup, admin-only, search
│   ├── test_status.py         -- listener heartbeat, single-instance guard, dashboard status
│   ├── test_search.py         -- search suggestions: ranking, mix, groups, endpoint
│   └── test_background.py     -- windowless start, stop request, shut down, logs page, one dashboard
├── gui/                        -- evidence review dashboard (Phase 4)
│   ├── app.py                  -- Flask app: pages, APIs, listener control, search, logs, shut down
│   ├── auth.py                 -- accounts (scrypt), JWT sessions, lockout
│   ├── runlog.py               -- identical copy of src/runlog.py (the exe can't import src/)
│   ├── BUILD.md                -- PyInstaller packaging instructions
│   ├── ContainerForensicsGUI.spec -- console=False (windowless)
│   ├── ContainerForensicsGUI.exe -- packaged build (rebuild after any gui/ change: stop the running one first, it locks the file)
│   ├── templates/
│   │   ├── base.html           -- shell: nav, search + suggestions, listener status, user, Shut down
│   │   ├── _macros.html        -- container table and tags
│   │   ├── index.html          -- tactical dashboard: KPIs, running now, evidence rescue, container log
│   │   ├── detail.html         -- one package: how it ended, what happened, resources, ports, evidence, integrity
│   │   ├── search.html         -- search results
│   │   ├── login.html / setup.html / account.html / users.html -- sign-in and accounts
│   │   └── logs.html / shutdown.html -- windowless-run controls
│   └── static/
│       ├── style.css           -- Carbon g100 tokens and components (see DESIGN.md)
│       └── app.js              -- listener status, live panel, suggestions, list filter/sort (pages work without it)
├── config/users.json           -- accounts + JWT secret (git-ignored, never commit)
└── evidence/                   -- captured evidence lands here as timestamped JSON
```

## 5. Key bugs already found and fixed (do not reintroduce)

- **Docker event schema mismatch**: assumed `status`/`id` fields, real API
  sends `Action`/`Actor.ID`. Found via `tools/debug_events.py` (prints every
  raw event unfiltered; still there for when event handling seems to
  silently do nothing).
- **Eager `docker.from_env()` at import time** crashed if Docker Desktop
  wasn't running yet. Fixed with lazy `get_client()`, thread-local
  (`threading.local()`) since the poller and main event loop are on separate
  threads and docker-py's client isn't guaranteed thread-safe for concurrent
  use.
- **Poller could itself lose the race** against a fast death, producing a
  negative `snapshot_age_seconds` when its own failed/partial capture was
  blindly trusted. Fixed: poller never overwrites good data with a failed
  capture; `_pick_best` checks both sources for failure before accepting
  either.
- **Poller timing bug**: originally waited the full `POLL_INTERVAL_SECONDS`
  regardless of how long the poll cycle itself took, silently making
  snapshots staler than the configured interval implied. Fixed: waits only
  `max(0, POLL_INTERVAL_SECONDS - cycle_duration)`, with an explicit warning
  logged if a cycle can't keep pace at all.
- **`--rm` gap for filesystem_diff/logs**: originally treated as "always
  safe" post-mortem, but a `--rm` container can be removed within tens of ms
  of `die` firing. Fixed by extending the poller to cover all 4 fields
  (originally only network/process) and unifying `handle_die`'s rescue logic
  across all of them.
- **Evidence didn't record which test `--delay` was used**: fixed by adding
  `get_container_started_at()` / `parse_docker_timestamp()`, capturing
  `container_lifetime_seconds` in every evidence file at kill-time (when the
  container is guaranteed to still exist).
- **Lifetime and snapshot age were timed at the wrong moment (fixed
  2026-09-26).** Both were measured from `time.time()` inside
  `handle_die`, i.e. the `die` event plus handling. On Docker Desktop that
  is ~0.3s after the real exit (§3), so every lifetime and snapshot age was
  ~0.3s too high, shifting the reported rescue threshold. Also, the poller
  stamped all four fields with a single time taken *after* all four
  captures. Fixes:
  - **Death** = `State.FinishedAt`, the runtime's own exit time, correct
    for any cause of death. If a `--rm` container is already removed, it
    falls back to the SIGKILL `kill` event, then to the `die` event
    (labelled as late). `handle_kill` records a SIGKILL that arrives after
    a SIGTERM (`docker stop`) without re-running the capture.
  - **Lifetime** = death − `StartedAt`. Both are on the daemon's clock, so
    no clock mixing is involved.
  - **Snapshot age** = death − snapshot time. Snapshot times are on the
    host clock, and on Docker Desktop the daemon runs in a VM with its own
    clock. So `measure_daemon_clock_offset()` measures the offset
    NTP-style via `/info` SystemTime: the minimum-RTT sample of three,
    with ±RTT/2 as the bound. Measured at ~−2ms ± 4ms, recorded per file.
  - The poller timestamps each field at the *start* of its own capture.
    That makes age an upper bound, never an understatement.
  - `handle_kill` reads `StartedAt` *before* its ~0.3s live-capture
    attempt. Read afterwards, it was lost for every killed `--rm`
    container, because the container was already removed.
  - Each evidence file has a `timing` block with every raw timestamp, which
    source gave the time of death, `exit_to_die_event_seconds` and
    `die_handling_lag_seconds`.
  - **Never use `time.time()` in a handler, or the `die` event's time, as
    the time of death.** Regression tests: `tests/test_timing.py`
    (`python -m unittest discover tests`, no Docker needed).
  - `parse_docker_timestamp` now also handles short fractions (Go drops
    trailing zeros; Python < 3.11 rejects `.23Z`) and numeric UTC offsets.
  - Evidence from the intermediate version of this fix (death = `die`
    event) was archived, then cleared out on 2026-09-27 along with older
    test captures. The dashboard and analysis tool don't read subfolders.
- **GUI: PyInstaller path resolution** — a frozen exe needs two *different*
  base paths: `sys._MEIPASS` for bundled templates/static (unpacked to a temp
  dir), vs. `os.path.dirname(sys.executable)` for the external `evidence/`
  folder (must be found next to wherever the exe actually sits, not inside
  the temp bundle). Conflating these breaks either the packaged build or the
  dev workflow.
- **GUI: one corrupt/empty evidence file must never crash the whole
  dashboard** — `load_evidence_file` catches `JSONDecodeError`/`OSError` per
  file and surfaces it as an "unreadable" row instead of taking down the
  entire list.
- **"No files changed" was recorded as "filesystem evidence lost" (fixed
  2026-09-26).** For an unchanged container, Docker's `diff` returns `None`,
  not `[]`, and `is_failure(None)` is True. So every container that never
  wrote a file reported its filesystem as lost. The rescue tests never hit
  this because they all wrote `/tmp/test.txt`. Fixed:
  `capture_filesystem_diff` returns `[]` for `None`, since errors always
  arrive as exceptions. Packages saved before the fix carry a unique
  signature (filesystem `live_attempt: null`), and the GUI shows them as
  "nothing changed", naming the bug.
- **Evidence files could be half-written or overwritten (fixed 2026-09-26).**
  `save_evidence` used a plain `open("w")`, and the name has only
  1-second resolution. An interrupted write left an empty file (the
  unreadable `testcontainer6_*.json`), and two listeners handling the same
  death in the same second silently overwrote each other (seen for real:
  an old-code listener overwrote the new one's port-tracking evidence).
  Fixed: the file is written in full under a temp name, then hard-linked to
  its final name, which fails rather than overwrite; collisions get `_1`,
  `_2`. **Run only one listener at a time**, and restart it after changing
  `src/`: a running listener keeps the old code.
- **The docker-exec network capture ignored the exit code (fixed 2026-09-26).**
  In an image without the binary, the error text would have been stored as
  the socket table. The exit code is now checked. Images without a shell
  fall back to `cat /proc/net/tcp`, and anything else is recorded as an
  error.
- **Environment setup traps** (Windows/WSL2, not code bugs, but worth knowing
  if rebuilding the dev environment): creating a Python venv on a
  Windows-mounted drive inside WSL2 (`/mnt/d/...`) can silently produce a
  half-built venv (symlinks for `python`/`python3` created, but `activate`/
  `pip` missing) due to unreliable symlink support on DrvFs. Fix: create the
  venv on WSL's native filesystem (e.g. `~/venv`) even if the project code
  itself lives on the mounted drive. Separately, Debian/Ubuntu sometimes ship
  a pip whose vendored dependencies are stripped out (expects system
  packages instead), causing `ModuleNotFoundError: No module named
  'pip._vendor.pyparsing'` inside a fresh venv — fixed by bootstrapping pip
  via the official `https://bootstrap.pypa.io/get-pip.py` instead of relying
  on `ensurepip`'s system-derived copy.

## 6. GUI details

Read-only Flask dashboard over `evidence/*.json` — does **not** need Docker
or the `docker` Python package at all, purely reads JSON off disk.

**Current look (2026-09-27): dark "tactical dashboard"** based on the IBM Carbon Gray 100 theme
(the user picked the IBM entry on getdesign.md). See `DESIGN.md`. Built with it:
- **Sign-in** (`gui/auth.py`): several analyst accounts (admin/analyst). The
  first run shows "create the admin account", and admins manage accounts at
  /users. Passwords are salted scrypt hashes. Sessions are JWT HS256 (PyJWT)
  in an HttpOnly SameSite=Strict cookie that expires after 8 h.
  - Each token carries a password version, so a password change or a
    deleted account ends open sessions at once.
  - Five wrong passwords lock that account for 60 s.
  - A POST carrying another site's Origin gets 403.
  - Accounts live in `config/users.json` (git-ignored); `ECF_USERS_FILE`
    overrides the path, which the tests use.
- **Home page:**
  - six KPI tiles (listener, running now, packages, live evidence saved,
    integrity, last capture);
  - **Running now**: live CPU / memory / network with sparklines, polled
    from `/api/live` every 2 s;
  - **Evidence rescue**: saved/lost by lifetime band;
  - the captured-container log, newest first.
- **Search** in the shell (`/search?q=`) across current and old packages.
  It matches name, container ID, how it ended, a port, or a date; every word
  has to match.
  - **Suggestions (2026-09-27):** after 2 characters, up to 4 drop down
    (`/api/search/suggest`, `search_suggestions()`):
    - matching containers, which open their page;
    - for a single word, matching ports, endings and capture dates (UTC,
      like the search), which open that search.
  - Prefix matches rank first, containers newest first, dates newest
    first. Containers are capped at 3 while a group is available.
  - Outside the name and ID, a word has to *start* with the typed text
    (stricter than the search page).
  - Rows are cached per evidence signature, so typing doesn't re-hash
    every package.
  - Behaves as an ARIA combobox: arrow keys, Enter, Escape.
  - Wide tables scroll inside their panel only when they don't fit, with
    headings static in that case, instead of scrolling the page.
- **Detail page:** adds **Resource use** (CPU, memory and network in/out
  charts on the shared time axis).

Design history: redesigned on 2026-09-26 as a "dispatcher's train graph".
The user found the graphs hard to understand, so the same day it was
simplified to **"Say it, then show it"**: the finding in plain sentences,
and only charts a first-time reader gets. `DESIGN.md` holds the visual system
and `PRODUCT.md` the constraints (offline on any OS, system fonts only, must
print legibly in black and white). One accent colour: blue = saved; hatched
grey = lost; orange only marks the 0.5s poll interval.

- **Hash re-check**: recomputes SHA-256 on every page load rather than
  trusting the stored value; a mismatch is surfaced as an alarm. The UI says
  "matches the stored value", not "verified". Because the hash lives in the
  same file, a match rules out accidental change but not a deliberate
  rewrite.
- **Index** (`index.html`), one column:
  - **Result**: a plain sentence ("Live evidence … was saved for 17 of 21
    containers"), then the lifetime cutoff, shown to the millisecond
    because rounding made it false, plus a "why" sentence.
  - One bar chart beside the result: saved vs lost per lifetime band
    (under 0.5s, 0.5–1s, 1–2s, 2s+).
  - **Containers** list: a lifetime bar per container on one shared scale
    (blue = live evidence saved, hatched = lost, orange tick at 0.5s), and
    Saved/Lost in words per field ("poller copy" / "direct" / "nothing
    changed" underneath). Also listening ports seen, hash, Find box,
    sorting, and sticky headings.
  - A **Current | Old (legacy)** switch keeps pre-fix data separate.
- **Detail** (`detail.html`):
  - **"What happened"**: the container's life as a timed list of plain
    sentences. It covers start, ports opening/closing, the poller's last
    copy, the kill, Docker's late die report, capture attempts, and what
    was lost. Each event shows seconds since start and the UTC clock time.
    Events whose time isn't recorded are listed last with a dash, never
    placed at a guessed time.
  - **"Ports and connections"**: each port or connection with "open from"
    and "open until" as windows, and a bar across the container's life
    (dark = seen open, light = may have opened or closed).
  - **The evidence** (network as parsed ports, raw tables in a disclosure;
    processes; files; logs), with plain "why it was lost" reasons.
  - **Integrity**, with timing and hashes folded into "Technical details".
  - **Download report (.txt)** (`/evidence/<file>/report.txt`): the same
    details as plain text, labelled as a summary; the JSON is the evidence.
  - "How it ended" appears in the list, the detail header and the story.
- "Direct" capture means the kill-trigger capture for NET/PROC, but the die
  handler's *post-mortem* capture for FS/LOG. The evidence JSON labels both
  `live_kill_trigger`; the GUI names them correctly.
- `POLL_INTERVAL_SECONDS` is restated in `gui/app.py` (the GUI can't import
  `src/` without the docker package). Keep it in step with `src/poller.py`.
- **Security**: binds to `127.0.0.1` only, by design — it reads whatever
  Docker daemon is on that specific machine, so there's no meaningful sense
  in which it should be reachable from other machines. The `/evidence/<filename>`
  route explicitly rejects path traversal (`os.path.basename(filename) !=
  filename`) and non-`.json` requests.
- **Packaging**: bundled into a standalone `.exe` via PyInstaller
  (`--onefile --add-data "templates;templates" --add-data "static;static"`)
  so it can be double-clicked with no terminal, no `pip install`. Auto-opens
  the browser on launch when running as the frozen exe; keeps Flask's normal
  debug/reload workflow when run as `python app.py` directly. Full rebuild
  instructions in `gui/BUILD.md`. Set `PORT` to run a dev copy alongside a
  running packaged one (default 5000).

## 7. Setup / run instructions

**Everyday use (2026-09-27: no windows):** double-click `start.vbs`
(Windows), `start.py` (any OS), or `gui/ContainerForensicsGUI.exe`.
Nothing but the browser appears (user request: no CMD windows).
- `start.vbs` runs `venv\Scripts\pythonw.exe gui\app.py --open` hidden.
  The exe is built with `console=False`.
- The dashboard (`--open`/frozen mode, no debug reloader) first looks for
  a running dashboard on ports 5000-5019 via the public `/api/ping`. If it
  finds one, it just opens the browser there and exits. Otherwise it takes
  the first free port (exclusive bind), so an older exe on 5000 doesn't
  clash.
- It starts the listener with `pythonw.exe listener.py --background`
  (`CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB`, so it outlives the
  dashboard). In `--background` mode the listener:
  - logs to `logs/listener.log`;
  - waits for Docker instead of failing;
  - starts Docker Desktop itself once if it can find it.
- **Stopping:** there's no window to close.
  - The header's **Stop** button (`POST /api/listener/stop`) creates
    `evidence/.listener.stop`. The listener's heartbeat thread sees it
    within 2 s, closes Docker's event stream, writes "stopped" and exits
    (hard exit after 5 s if the stream doesn't close; saves are atomic).
  - A stop file older than the listener is ignored and removed at start.
  - **Shut down** (`/shutdown`, a confirm page) stops the dashboard
    (`os._exit` after the response), and the listener too if chosen.
    Both actions are logged with the analyst's username.
- **Logs** (`/logs`): the last 300 lines of `logs/listener.log` and
  `logs/dashboard.log`. `runlog.py` swaps stdout/stderr for a timestamped
  file writer when there is no console, so crash tracebacks land there.
  It rotates to `.log.1` past 2 MB at startup.
- `python gui/app.py` (dev, auto-reload) and `python src/listener.py`
  still print to their terminal as before.

**Listener heartbeat (2026-09-27):** the listener rewrites
`evidence/.listener.json` every 2 s. The dotfile is skipped by the
evidence glob and git-ignored. It holds the state, PID, number of
containers being watched, and evidence saved. Uses:
- The dashboard header shows running / stopped / "not running, last seen
  X ago" (stale after 6 s), rechecking `/api/status` every 3 s.
- The dashboard offers "New evidence: refresh" when the evidence folder
  changes.
- A second listener refuses to start while the heartbeat is fresh
  (`--force` overrides). This prevents the double-capture problem in §5.
- **The dashboard starts the listener itself (2026-09-27).** On launch
  (the `.exe`, `app.py`, or via `start.vbs`) it starts `src/listener.py`
  in the background (no window) if no fresh heartbeat exists. It skips that in the
  debug reloader's child process, and with `--no-listener`. The listener
  always runs with `venv/`'s Python, because the `.exe` doesn't bundle
  the docker package.
- The header offers **Start listener** when it isn't running, via
  `POST /api/listener/start`. Requests carrying another site's Origin
  get 403. A 15 s launch cooldown prevents double starts.
- A dashboard-started listener waits for Docker Desktop instead of
  crashing (heartbeat state `waiting_docker`, shown as "Listener waiting
  for Docker"). This state counts as alive for the single-instance
  guard.

Manual setup, if you need it:

```
cd code
python -m venv venv
venv\Scripts\activate          (Windows)
pip install -r requirements.txt
```

Run the capture pipeline (needs Docker Desktop running):
```
cd src
python listener.py
```
In a second terminal, create and kill a test container to verify:
```
docker run --rm alpine sh -c "echo hello > /tmp/test.txt; sleep 30"
docker ps
docker kill <name>
```
Check `evidence/` for a new JSON file.

Run the GUI (independent of the above, reads `evidence/` directly):
```
cd gui
python app.py
```
Open `http://127.0.0.1:5000`.

Automate a rescue-threshold sweep (run `listener.py` first, in another
window):
```
cd tools
python test_rescue_threshold.py --delay 0.5
python analyze_evidence.py
```

## 8. What's NOT done yet (roadmap)

- **Phase 3 — evaluation harness**: current testing is scripted but manual
  (`tools/test_rescue_threshold.py` run one delay value at a time). A proper
  harness would automate the full sweep, run multiple trials per delay value
  for statistical confidence, and produce charts/tables directly for the
  report.
- **Native Linux + native Docker Engine test** of the `/proc` fast path (see
  §3) — the one empirical question still open. Requires `dockerd` installed
  directly (not via Docker Desktop) on a genuine Linux host, sharing a kernel
  with whatever runs `capture.py`.
- Formal write-up of results for the Proposal / Interim Report / Final
  Report deliverables (structure already exists in the FYP Notion tracker).

## 9. Secondary FYP project (separate, for context only)

Not part of this codebase, but running in parallel as the module's required
secondary/backup topic: **Cloud Network Security Configuration Auditor
(Azure)** — a tool connecting to an Azure subscription via the Azure SDK to
check NSG rules, storage account access, and VNet configuration against known
-risky patterns, producing a plain-language risk report. Uses Azure for
Students ($100 credit, 12 months, no card required). Entirely separate
codebase/chat thread — mentioned here only so a fresh session doesn't
conflate the two.
