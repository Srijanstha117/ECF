# Forensic Evidence Capture for Ephemeral Containers

Core artifact for the FYP. Watches Docker's event stream and captures a
defined evidence set (process list, network state, filesystem diff, logs)
the moment a container starts dying, before it's gone for good.

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

## 2. Run the listener

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
<name> -- capturing now`, and a new JSON file should appear in
`evidence/`. Open that file and check: does it actually contain the
process list, the filesystem change (the `/tmp/test.txt` you created),
and logs? That's your first real evidence of whether the core idea
works at all.

## 3. What's here

```
code/
├── src/                        -- the actual artifact
│   ├── listener.py             -- watches Docker events, triggers capture
│   ├── capture.py              -- the evidence-pulling functions
│   └── poller.py               -- background proactive snapshotting
├── tools/                      -- dev/evaluation utilities, not part of
│   │                              the artifact itself
│   ├── analyze_evidence.py     -- summarizes evidence/ into one table
│   ├── test_rescue_threshold.py -- automates the rescue-threshold sweep
│   └── debug_events.py         -- prints raw Docker events, unfiltered
├── gui/                        -- evidence review dashboard (Phase 4)
│   ├── app.py                  -- Flask app, run with `python app.py`
│   ├── BUILD.md                -- how to package it as a standalone .exe
│   └── ContainerForensicsGUI.exe -- packaged build (double-click, no
│                                     terminal needed to view evidence)
├── evidence/                   -- captured evidence lands here as
│                                   timestamped JSON
├── tests/                      -- evaluation harness goes here (Phase 3,
│                                   not built yet)
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
