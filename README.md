# Forensic Evidence Capture for Ephemeral Containers

Core artifact for the FYP. Watches Docker's event stream and captures a
defined evidence set (process list, network state, filesystem diff, logs)
the moment a container starts dying, before it's gone for good.

## Quick start (after the one-time setup in sections 0 and 1)

The first time you open the dashboard it asks you to **create the admin account**; after that it
asks you to sign in. Admins add other analysts under **Users**. Accounts are stored (as password
hashes) in `config/users.json`, which is never committed.

Double-click **`start.vbs`** (or `gui/ContainerForensicsGUI.exe`). No command windows
open; only your browser does. In the background it:

1. starts the evidence dashboard and opens it in your browser;
2. starts the capture listener, unless one is already running;
3. starts Docker Desktop if it isn't running (the listener waits for it).

Opening it again while it's running just shows the dashboard again. On
Linux/macOS, `venv/bin/python start.py` does the same.

Everything is controlled from the dashboard:
- The header shows whether the listener is running and how many containers
  it's watching, with **Stop** / **Start listener**. It also offers a refresh
  when new evidence arrives.
- **Shut down** (top right) stops the dashboard, and the listener too if you
  choose. Without a window, that's how you close it.
- **Logs** shows what the listener and dashboard would have printed
  (`logs/listener.log`, `logs/dashboard.log`), including any error.

Only one listener can run at a time; a second one refuses to start. For
development, `python gui/app.py` still runs in a terminal with auto-reload
(add `--no-listener` to skip starting the listener), and `python
src/listener.py` prints to its terminal as before.

## 0. Prerequisites — do this first, before any code

You need **Docker Desktop** installed and running on this machine.

1. Download: https://www.docker.com/products/docker-desktop/
2. Install it, then open Docker Desktop and wait for it to say "Running."
3. Verify from a terminal (PowerShell or CMD):
   ```
   docker --version
   docker run hello-world
   ```
   If `hello-world` prints a welcome message, Docker is working. If either
   command fails, fix that before touching this repo — nothing below
   will run without it.

## 1. Set up the Python environment

```
cd code
python -m venv venv
venv\Scripts\activate          (Windows)
pip install -r requirements.txt
```

## 2. Run the listener by hand (development)

The Quick start above does all of this for you. To watch the listener's
output directly instead:

```
cd src
python listener.py
```

Leave it running. In a **second terminal**, create and kill a test
container:

```
docker run --rm alpine sh -c "echo hello > /tmp/test.txt; sleep 30"
```

Let it run a couple seconds, then in a third terminal:

```
docker ps                      (copy the container name or ID)
docker kill <name>
```

Watch the listener's terminal — it should print `[!] DIE detected on
<name> -- capturing post-mortem evidence`, and a new JSON file should appear in
`evidence/`. Open that file and check: does it actually contain the
process list, the filesystem change (the `/tmp/test.txt` you created),
and logs? That's your first real evidence of whether the core idea
works at all.

## 3. What's here

```
code/
├── start.vbs                   -- double-click to start everything (Windows, no windows)
├── start.py                    -- the same on any OS
├── src/                        -- the actual artifact
│   ├── listener.py             -- watches Docker events, triggers capture
│   ├── capture.py              -- the evidence-pulling functions
│   ├── poller.py               -- background proactive snapshotting
│   └── runlog.py               -- logs output to logs/ when there's no window
├── tools/                      -- dev/evaluation utilities, not part of
│   │                              the artifact itself
│   ├── analyze_evidence.py     -- summarizes evidence/ into one table
│   ├── test_rescue_threshold.py -- automates the rescue-threshold sweep
│   └── debug_events.py         -- prints raw Docker events, unfiltered
├── gui/                        -- evidence review dashboard (Phase 4)
│   ├── app.py                  -- Flask app (dev: `python app.py`)
│   ├── auth.py                 -- analyst accounts and sign-in sessions
│   ├── templates/, static/     -- pages, stylesheet, script
│   ├── BUILD.md                -- how to package it as a standalone .exe
│   └── ContainerForensicsGUI.exe -- packaged build (double-click)
├── evidence/                   -- captured evidence lands here as
│                                   timestamped JSON
├── logs/                       -- listener / dashboard output (Logs page)
├── config/                     -- accounts (password hashes), never committed
├── tests/                      -- regression tests, no Docker needed:
│                                   python -m unittest discover tests
└── requirements.txt
```

## 4. What's NOT here yet (see the FYP Notion tracker for the full roadmap)

- The evaluation harness (Phase 3): scripted incidents with known ground
  truth, killed different ways, measuring completeness/speed vs. baseline.
- Confirmation of the `/proc` fast network-capture path on a genuinely
  native Linux + native Docker Engine host (tested and ruled out on
  Windows and on WSL2 + Docker Desktop's backend — both force the slower
  exec fallback, since Docker Desktop isolates containers in its own VM
  regardless of host OS).

## 5. If something breaks

- `docker.errors.DockerException: Error while fetching server API
  version` — Docker Desktop isn't running. Start it and wait for
  "Running" before retrying.
- Evidence file is missing a field / shows `{"error": ...}` — the
  container likely died faster than that particular capture call could
  run. That's not a bug, that's your actual research problem showing up
  in real data. Note when it happens and how often — it's evaluation
  material, not just noise to fix quietly.
