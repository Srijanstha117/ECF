---
version: 1
slug: "gui-templates-index-html"
primary_target: "gui/templates/index.html"
related_targets: ["gui/templates/detail.html"]
---

Scope: evidence review dashboard, index (gui/templates/index.html) and container detail (gui/templates/detail.html). Mode: Operate.

Audience and job: the author, reviewing capture tests between runs; examiners at the viva, reading it cold; report readers, via printed screenshots. Framed for a DFIR analyst reviewing evidence from dead containers.

Task: at a glance, how much live evidence was saved, and does it depend on how long the container lived? Then per container: what happened, step by step; which ports were open, and when; what was saved or lost, and why; is the file intact?

Constraints: read-only; offline on any OS; system fonts only; Flask/Jinja plus vanilla JS; legacy and current data never mixed; must print legibly in black and white; plain language before charts (user feedback: the train graph was not understandable).

Direction: "Say it, then show it" (revised 2026-09-26, replacing the Dispatcher's Train Graph).
- Index: a result sentence, bars of saved/lost per lifetime band, and a container list with lifetime bars.
- Detail: a "What happened" timed story, and a ports table with open windows.

Memorable moment: the story line "Docker reported the container as dead, 0.29 s after it actually stopped", sitting right after "Killed with SIGKILL".

Unresolved: tool name (working title); listener running/not-running indicator offered but not built.
