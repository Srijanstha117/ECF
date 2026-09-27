---
name: Ephemeral Container Forensics — Evidence Review
description: A plain-language control screen for dead containers. It says what was saved, what was lost, and when each port was open.
colors:
  saved: "#2451B7"
  saved-soft: "#9DB4E4"
  poll: "#E0590F"
  poll-text: "#A83E00"
  alarm-red: "#B42318"
  alarm-on-plate: "#FF8A80"
  plate-slate: "#17212E"
  plate-text-soft: "#A9B4C2"
  ink: "#1A1F26"
  ink-soft: "#56606C"
  lost: "#6B7480"
  rule: "#CDD3DA"
  hairline: "#E3E7EC"
  sheet: "#FFFFFF"
  ground: "#ECEFF2"
  data-well: "#F6F7F9"
  hot: "#FFF4D6"
  control-edge: "#7D8793"
typography:
  plate-title:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "19px"
    fontWeight: 700
    letterSpacing: "0.02em"
  display:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "30px"
    fontWeight: 700
    lineHeight: 1.1
  figure:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.1
  lede:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "19px"
    fontWeight: 400
    lineHeight: 1.4
  readout:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "17px"
    fontWeight: 700
  title:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "15px"
    fontWeight: 700
    letterSpacing: "0.05em"
  label:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'DIN Condensed', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "12px"
    fontWeight: 600
    letterSpacing: "0.06em"
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  data:
    fontFamily: "ui-monospace, 'Cascadia Mono', 'SF Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace"
    fontSize: "12.5px"
    fontWeight: 400
  symbol:
    fontFamily: "Bahnschrift, 'DIN Alternate', 'Roboto Condensed', 'Arial Narrow', sans-serif"
    fontSize: "10px"
    fontWeight: 700
rounded:
  none: "0px"
  sm: "2px"
  bar-end: "4px"
spacing:
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "24px"
  s6: "32px"
components:
  plate:
    backgroundColor: "{colors.plate-slate}"
    textColor: "{colors.sheet}"
    typography: "{typography.plate-title}"
    padding: "12px 24px"
  sheet:
    backgroundColor: "{colors.sheet}"
    rounded: "{rounded.sm}"
  switch-option:
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "5px 12px"
  switch-option-current:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.sheet}"
  swatch-saved:
    backgroundColor: "{colors.saved}"
    size: "11px"
  swatch-lost:
    backgroundColor: "{colors.sheet}"
    size: "11px"
  filter-input:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "6px 10px"
  list-row-hover:
    backgroundColor: "{colors.hot}"
---

# Design System: Ephemeral Container Forensics — Evidence Review

## Overview

**Creative North Star: "Say it, then show it"**

Each screen leads with the finding in a plain sentence. A chart comes second, and only one a first-time reader understands without a legend lesson: bars for how long things lived, bars for when a port was open. A container's detail page tells its life as a numbered story with times ("Container started", "Port 8080 seen open", "Killed with SIGKILL", "Docker reported it dead 0.29 s later").

History: the first redesign (2026-09-26) was a railway "dispatcher's train graph". The user found it hard to understand, so it was replaced the same day. Its visual materials were kept: the slate header plate, condensed DIN-style caps, tabular figures, light control-screen ground. The graph grammar was not.

It is a working instrument, light enough to project and print. Confirmed rejections from the user: hacker-movie neon on black, generic SaaS admin templates, plain academic printout, and graphs that need decoding.

**Key Characteristics:**
- A plain-language result sentence first, with the numbers in bold figure type.
- One accent colour: blue means saved. Hatched grey means lost. Orange only marks the poller's 0.5 s interval.
- Outcomes written as words ("Saved", "Lost", "nothing changed"); colour and hatching repeat the word, they don't replace it.
- Every time is given in seconds since the container started, with the UTC clock time alongside where it matters.
- Uncertain times are shown as windows ("opened between 0.21 s and 0.71 s"), never as false points.

## Colors

Neutral ground and white sheets; one meaningful colour.

### Primary
- **Saved**: evidence that was saved; lifetime bars of containers whose live evidence survived; the part of a port bar where the port was seen open. **Saved Soft** is its light partner: "partly saved", and the uncertain window at either end of a port bar.

### Secondary
- **Poll**: the poller's 0.5 s interval tick and the plate underline, nothing else. **Poll Text** is its text-safe partner.

### Tertiary
- **Alarm Red**: hash mismatch, unreadable files, and "Lost" live evidence in the detail header. **Alarm on Plate** is its partner on the dark header.

### Neutral
- **Lost**: the stroke and hatching of lost evidence.
- **Plate Slate / Plate Text Soft**: the header plate.
- **Ink / Ink Soft**: text / secondary text and captions.
- **Rule / Hairline**: sheet borders / row dividers and the story's joining line.
- **Sheet / Ground / Data Well**: surfaces / page / the track behind bars and raw machine output.
- **Hot**: list-row hover.
- **Control Edge**: input borders (3.7:1 on white).

### Named Rules
**The One Accent Rule.** Blue is the only colour that carries meaning. It means "saved", everywhere.

**The Word-First Rule.** Every outcome is written in words. Colour, fill and hatching repeat it for scanning and survive black-and-white printing, but nothing depends on them alone.

**The Hatching Rule.** Hatching means "lost" and nothing else.

**The Recorded-Only Rule.** An event is placed in time only when the package records its time. Otherwise it's listed last with a dash and says why.

## Typography

**Label/Title Font:** Bahnschrift at semi-condensed width (Windows), DIN Alternate / DIN Condensed (macOS), falling back to Roboto Condensed / Arial Narrow and then the system sans. No font files are bundled; the app must run offline on any OS.
**Body Font:** the OS UI face (system-ui).
**Data Font:** the OS monospace face (ui-monospace).

### Hierarchy
- **Plate title** (700, 19px, caps): the working title on the header plate.
- **Display** (700, 30px): the container name on a detail page.
- **Lede** (400, 19px, 1.4): the result sentence; its numbers in **Figure** (700, 22px).
- **Figure** (700, 22px): headline numbers (result counts, the detail header's lifetime and outcome).
- **Readout** (700, 17px): figures in the header plate.
- **Title** (700, 15px, caps): sheet and section titles.
- **Body** (400, 14px, 1.5): prose, list cells (13.5px), captions (13px, max 80ch).
- **Label** (600–700, 11.5–12px, caps): table headers, fact labels, chart captions.
- **Data** (400, 12.5px): container names, hashes, IDs, clock times, raw socket tables, logs.
- **Symbol** (700, 10px): sort arrows and the +/− disclosure marker.

### Named Rules
**The Tabular Rule.** Every number that can sit above another number uses tabular figures.

**The Data-Only Mono Rule.** Monospace appears only for machine-produced values.

## Layout

One column (max 1280px), top to bottom:
- **Index:** Result (sentences left, the saved/lost-by-lifetime bars right; stacked below 900px), then the container list.
- **Detail:** header facts, "What happened", "Ports and connections", the evidence, then integrity with technical details folded away.

The container list stays full-width with sticky headings. Below 760px it scrolls sideways inside its own wrapper, never the page. Spacing runs on a 4px base.

## Elevation & Depth

Flat. No shadows. Depth comes from the ground/sheet contrast and 1px rules.

## Shapes

Square corners (2px) on sheets and controls. Bars have 4px rounded data-ends and square baselines. Swatches are 11px squares: solid (saved), light with a blue frame (partly), white with a blue frame (nothing changed), hatched (lost). Story markers are 14px circles; a stop is a square.

## Components

### Header plate
Slate band, white condensed caps title, a 3px orange underline. The right side holds a readout: on the index, containers / hashes matching / unreadable; on a detail page, lived / live evidence / hash.

### Result (index)
One lede sentence ("Live evidence … was saved for **17 of 21** containers"), one sentence giving the lifetime cutoff at full precision (never rounded into a false statement), one muted "why" sentence, and a files-and-logs sentence. Beside them: horizontal bars per lifetime band (under 0.5 s, 0.5–1 s, 1–2 s, 2 s or more). Bar length = number of containers; blue = saved, hatched = lost, 2px gaps between segments; "1 of 5 saved" at the end.

### Container list (index)
- **Row:** container name, then a lifetime bar on one shared scale (blue if live evidence was saved, hatched if lost, with an orange tick at 0.5 s) and the value.
- **Outcome columns:** "Saved/Lost" per field, with "poller copy" / "direct" / "nothing changed" underneath.
- **Other columns:** ports seen (listening ports, connection count, or "not tracked" / "never read"), and hash.
- **Controls:** a Find box with a no-match message, sortable name and lifetime columns, and whole-row click.

### What happened (detail)
A vertical story: time since start (left), a marker on a joining line, the sentence with an optional muted note, and the UTC clock time (right; hidden on phones). Markers:
- blue filled = saved or captured;
- hatched = failed or lost;
- square ink = the stop;
- blue ring = port seen open;
- dashed ring = port closed.

Events without a recorded time come last with a dash.

### Ports and connections (detail)
A summary sentence (counts, number of reads, and when), then a table with columns What / Protocol / Open from / Open until, plus a bar across the container's life. The bar is solid blue where the port was seen open and light blue for the windows where it may have opened or closed. A caption explains the windows.

### Evidence sheets (detail)
A plain title, with the outcome at the right in words plus how and when. Network shows the parsed ports and connections, with the raw tables in a disclosure. Processes and file changes are shown as tables. Lost fields show a two-row "why it was lost" list, with raw errors in disclosures.

### Notices
A 1px alarm-red box with a caps label (UNREADABLE, HASH MISMATCH). No thick side stripes.

## Do's and Don'ts

### Do:
- **Do** write the finding as a sentence before any chart.
- **Do** keep old (legacy) packages out of current results, and label them.
- **Do** show uncertain times as windows, and explain the poll interval once, in a caption.
- **Do** say plainly why evidence was lost, with the raw error available on demand.

### Don't:
- **Don't** use charts that need a legend lesson (the train graph was tried and rejected).
- **Don't** use neon-on-black, glows, or terminal costume (user-rejected).
- **Don't** fall back on card grids or badge-heavy tables (user-rejected generic SaaS).
- **Don't** call a matching hash "verified" without the caveat.
- **Don't** round a threshold into a false statement: the cutoff is shown to the millisecond.
