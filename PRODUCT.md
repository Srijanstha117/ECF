# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Framed end user (as positioned in the FYP report):** a DFIR analyst or incident responder reviewing evidence from containers that have already been killed or removed. The containers are gone; the evidence packages are all that is left.
- **Actual users today:** the author, a final-year BSc (Hons) Computer Networking & IT Security student, reviewing capture-test results while running experiments; FYP examiners and supervisor at the viva; readers of the written report via screenshots. Viva/report use and the author's own analysis weigh equally.

## Product Purpose

A read-only local dashboard over the evidence packages (`evidence/*.json`) produced by the capture pipeline (`src/listener.py` + `src/poller.py`). For each dead container it shows:
- what evidence survived;
- which capture path supplied each field (live kill-trigger, poller snapshot, or lost);
- how stale rescued evidence was at the moment of death;
- which ports and connections were open, and when each opened and closed (from the poller's history, as windows);
- whether the package's integrity hash still matches.

Success: a reviewer can tell at a glance what was rescued, what was lost and why, and whether the package has changed since capture.

## Positioning

Evidence from ephemeral containers is gone the moment they die, unless it was captured beforehand. This project's pipeline shows empirically that reactive, event-triggered capture cannot beat SIGKILL, and that continuous polling rescues evidence once a container lives past a measured lifetime threshold. Every field in every package carries its own provenance and staleness. The dashboard exists to make that provenance and timing legible. It is not a generic log or JSON viewer.

## Operating Context

- Runs locally, bound to 127.0.0.1, either as `python gui/app.py` or as a PyInstaller-packaged executable that opens the browser itself.
- Must work fully offline on any OS (Windows, Linux, macOS). No CDN or remote assets; fonts must be bundled with the app or come from system stacks.
- Flask + Jinja templates, one stylesheet, minimal vanilla JS, no build step.
- Reads `evidence/*.json` next to `gui/`; subfolders are ignored (used for archives). The hash is re-verified on every page load.
- Tens of evidence files today; a Phase 3 sweep could produce hundreds.
- Used live during experiments, and projected or screenshotted for the viva and the written report.

## Capabilities and Constraints

- **Read-only.** Never modifies evidence files.
- **Four evidence fields per package:** `network_state`, `process_list`, `filesystem_diff`, `logs`. Each has a `source`:
  - `live_kill_trigger`;
  - `poller_snapshot`, with `snapshot_age_seconds`. This can be negative for filesystem_diff/logs, meaning captured after death;
  - `none -- both ... failed`, carrying `live_attempt` and `snapshot_attempt` errors.
- **`timing` block** (packages captured from 2026-09-26): death-time source (FinishedAt / SIGKILL event / die-event fallback), exit→die event delay, daemon clock offset ± uncertainty, container lifetime. Packages without it are **legacy**: lifetime and ages are overstated by ~0.3s. Legacy data must never be mixed with corrected data in any aggregate or chart.
- **`port_timeline`** (packages from 2026-09-26 ~20:00 on): every port and connection the poller saw, with opened-between and closed-between windows in seconds since start plus raw clock times. Older packages say "not tracked".
- **Plain language first** (user feedback, 2026-09-26: the train-graph charts were "not so understandable"): every view states its finding in words before any chart, and charts are limited to forms a first-time reader gets without explanation.
- **Unreadable files:** empty or corrupt files must appear as visible entries, never crash a view.
- **Security:** path traversal is rejected; only bare `.json` filenames are served.
- **Integrity claim limit:** the stored SHA-256 is recomputed on load, and a mismatch is a finding. The hash sits inside the same file, though, so it catches accidental change, not deliberate tampering. The UI must not overclaim.
- **Terminology:** evidence package, rescued, lost, direct capture (the kill-trigger capture for network/process; the post-mortem die-handler capture for filesystem/logs. The JSON labels both `live_kill_trigger`), poller snapshot, snapshot age, lifetime, legacy.
- **Undecided:** the tool's name. Use a plain working title until one is chosen.

## Evidence on Hand

- Real evidence packages in `code/evidence/`: 18 corrected trials (5 of them `--rm`; the 2 newest also record when the kill-trigger capture started), 14 legacy trials, 1 unreadable 0-byte file.
- Empirical findings and history in `PROJECT_CONTEXT.md` §3 and §5.
- No logo, brand assets, or product name exist. Do not invent them.

## Product Principles

1. **Provenance first.** Every piece of evidence shows where it came from and how old it was at death.
2. **Failure is a finding.** Lost evidence, and why it was lost, is shown plainly, never hidden or softened.
3. **Never overclaim.** Don't overstate integrity, and don't mix incomparable data (legacy vs corrected).
4. **Zero setup.** Works anywhere, offline, from one command or one double-click.
5. **Legible in seconds, dense on demand.** An examiner understands it at a glance; the author can scan hundreds of packages.

## Accessibility & Inclusion

Screenshots end up in a printed report and on a projector, so contrast and text size must survive both.
