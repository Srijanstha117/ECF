---
name: DocIt — Evidence Review (tactical dashboard)
description: A dark, Carbon-inspired operations console for container evidence. Live activity and captured evidence on one screen, each finding still said in words.
colors:
  background: "#161616"
  layer-01: "#262626"
  layer-02: "#393939"
  layer-hover-01: "#333333"
  border-subtle: "#393939"
  border-strong: "#6f6f6f"
  text-primary: "#f4f4f4"
  text-secondary: "#c6c6c6"
  text-helper: "#a8a8a8"
  link: "#78a9ff"
  link-hover: "#a6c8ff"
  button-danger: "#da1e28"
  button-primary: "#0f62fe"
  button-primary-hover: "#0050e6"
  focus: "#ffffff"
  support-error: "#fa4d56"
  support-success: "#42be65"
  support-warning: "#f1c21b"
  data-blue: "#4589ff"
  data-blue-soft: "#1c3f7a"
  data-in: "#1192e8"
  data-out: "#ee5396"
  data-lost: "#8d8d8d"
  poll: "#ff832b"
  tag-blue-bg: "#0043ce"
  tag-blue-fg: "#d0e2ff"
  tag-red-bg: "#a2191f"
  tag-red-fg: "#ffd7d9"
  tag-gray-bg: "#525252"
typography:
  display:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "32px"
    fontWeight: 300
    lineHeight: 1.25
  figure:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "32px"
    fontWeight: 300
    lineHeight: 1.2
  heading:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "20px"
    fontWeight: 400
    lineHeight: 1.4
  body:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.43
    letterSpacing: "0.16px"
    fontFeature: "tnum"
  label:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    letterSpacing: "0.32px"
  title:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
  axis:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "11px"
    fontWeight: 400
  symbol:
    fontFamily: "'IBM Plex Sans', system-ui, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    fontSize: "10px"
    fontWeight: 400
  data:
    fontFamily: "'IBM Plex Mono', ui-monospace, 'Cascadia Mono', Menlo, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
rounded:
  none: "0px"
  bar-end: "4px"
  tag: "24px"
spacing:
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "24px"
  s6: "32px"
  s7: "48px"
components:
  shell:
    backgroundColor: "{colors.background}"
    textColor: "{colors.text-primary}"
    typography: "{typography.body}"
    height: "48px"
  tile:
    backgroundColor: "{colors.layer-01}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.none}"
    padding: "16px"
  button-primary:
    backgroundColor: "{colors.button-primary}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.none}"
    padding: "0 48px 0 16px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.button-primary-hover}"
  text-input:
    backgroundColor: "{colors.layer-02}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.none}"
    padding: "0 16px"
    height: "40px"
  tag-saved:
    backgroundColor: "{colors.tag-blue-bg}"
    textColor: "{colors.tag-blue-fg}"
    rounded: "{rounded.tag}"
    height: "24px"
  tag-lost:
    backgroundColor: "{colors.tag-red-bg}"
    textColor: "{colors.tag-red-fg}"
    rounded: "{rounded.tag}"
    height: "24px"
  table-header:
    backgroundColor: "{colors.layer-02}"
    textColor: "{colors.text-primary}"
    height: "48px"
---

# Design System: DocIt — Evidence Review (tactical dashboard)

## Overview

**Creative North Star: "The evidence operations console"**

Chosen by the user on 2026-09-27: a "tactical dashboard", taking its look from the IBM entry on getdesign.md. That reference documents Carbon's light marketing site and notes that the dark Gray 100 theme exists but wasn't extracted, so this system uses **Carbon's published Gray 100 product theme**: dark layered greys, flat 0px corners, 1px hairlines, a single blue for actions, light-weight large figures, and 0.16px body tracking. It is inspired by Carbon, not affiliated with IBM; no IBM names or logos are used.

The console shows live activity and captured evidence on one screen. The home page leads with six KPI tiles, then "Running now" (live CPU / memory / network) beside "Evidence rescue" (saved vs lost by lifetime), then the captured-container log. Each finding is still said in words: outcomes are written ("Saved", "Lost", "Killed", "Stopped, then force-killed"), never left to colour alone.

History: plain light "station sign" → "dispatcher's train graph" (rejected as hard to read) → "say it, then show it" → this dark console (user brief). Print always switches to Carbon's White theme.

**Key Characteristics:**
- A 48px Carbon UI shell holds the name, nav, search, listener status and user.
- KPI tiles sit on a 1px hairline grid; figures in 32px light type.
- Data tables have 48px rows and a #393939 header row. Tags are Carbon pills.
- Blue carries actions (#0f62fe) and "saved" data (#4589ff). Network in/out is cyan/magenta. "Lost" is hatched grey plus a red tag.
- Sharp corners everywhere except tags (Carbon pill) and data bar ends (4px).

## Colors

Dark layered neutrals, with colour reserved for action, status and data.

### Primary
- **Button Primary** (#0f62fe, hover #0050e6): primary buttons, the current-nav underline, and the Start listener button. **Button Danger** (#da1e28) is the hover of Delete. **Link** (#78a9ff, hover #a6c8ff) is for links and ghost buttons.
- **Data Blue** (#4589ff): "saved" bars and CPU/memory lines. Its dark partner **Data Blue Soft** (#1c3f7a) is for "partly saved" and uncertain port windows.

### Secondary
- **Data In / Data Out** (#1192e8 / #ee5396): network received / sent. Validated with the dataviz script against #262626: all checks pass, protan ΔE 13.1.

### Tertiary (status)
- **Support Success** (#42be65): listener running.
- **Support Warning** (#f1c21b): waiting for Docker; KPI tile with lost evidence.
- **Support Error** (#fa4d56): listener off, integrity problems, lost-evidence text.
- **Poll** (#ff832b): the 0.5 s poll-interval tick, nothing else.

### Neutral
Background #161616 → Layer 01 #262626 (tiles, panels) → Layer 02 #393939 (fields, table headers, notifications). Text runs #f4f4f4 / #c6c6c6 / #a8a8a8. Borders are #393939 subtle and #6f6f6f strong (field underlines, chart axes).

### Named Rules
**The Word-First Rule.** Every outcome is written in words. Colour, tag shape and hatching repeat it; nothing depends on colour alone.

**The Hatching Rule.** Hatching means "lost" and nothing else.

**The Recorded-Only Rule.** Only recorded times are drawn. An unrecorded time is said in words.

## Typography

**Font:** IBM Plex Sans / Plex Mono if installed; otherwise the system UI face and ui-monospace. The Carbon reference's fallback is Helvetica Neue / Arial. No font files are bundled, because the app runs offline on any OS and the user chose system fonts.

**Character:** light 300-weight large figures, and a calm 14px body with Carbon's 0.16px tracking.

### Hierarchy
- **Display** (300, 32px): page titles, the container name, KPI figures.
- **Heading** (400, 20px): panel and section titles.
- **Body** (400, 14px, 0.16px): everything else; the lede is 20px 300.
- **Label** (400, 12px, 0.32px): KPI labels, field labels, captions, helper text.
- **Title** (600, 16px): evidence field titles on the detail page.
- **Axis** (400, 11px): chart tick labels.
- **Symbol** (10px): sort arrows only.
- **Data** (mono, 12.5px): container names, IDs, hashes, clock times, raw tables.

### Named Rules
**The Sentence-Case Rule.** Carbon doesn't use all-caps tracked labels; all labels are sentence case.

## Layout

Max width 1584px (Carbon's max grid). The home page runs top to bottom:
1. page head with the Current / Old switch;
2. six KPI tiles (3 below 1200px, 2 on phones);
3. a two-column row (stacked below 1100px);
4. the full-width container log.

Tables scroll sideways inside their panel below 1100px, never the page. Sticky table headings sit under the 48px shell. Spacing is Carbon's 4px base: 4 / 8 / 12 / 16 / 24 / 32 / 48.

## Elevation & Depth

Flat. No shadows. Depth is layering: #161616 → #262626 → #393939. KPI tiles in a warning or alarm state get a 3px inset top rule.

## Shapes

0px corners on the shell, tiles, fields, buttons, tables and notifications. Tags are 24px pills (Carbon). Bars have 4px rounded data ends. Inline notifications carry Carbon's 3px left status rule.

## Components

- **Shell:** 48px. Nav items get a 3px blue underline when current. The search field is #262626 with a 1px #6f6f6f underline. Listener status is a dot plus words; a blue Start listener button appears when it's off, and a ghost "Stop" link-button while it runs. Right of the user: Sign out and "Shut down" (the app has no window, so this is how it closes). Nav: Dashboard, Logs, Users (admin).
- **Search suggestions:** a #393939 menu under the search field, at least 24rem wide, with at most 4 rows: a kind label (Container / Port / Ended / Date, 12px helper), the label in mono with the typed part in bold white, and a helper detail line. The active row is #474747 with a 2px white inset left rule.
- **KPI tile:** label (12px), figure (32px light), sub-line (12px helper). The listener tile updates live.
- **Running now:** live table (container, CPU meter + % + 30-sample sparkline, memory meter vs limit, network ↓/↑ rates). Updated every 2 s from the listener's heartbeat.
- **Evidence rescue:** a lede sentence, then saved/lost bars per lifetime band with counts at the bar ends.
- **Container log:** 48px rows, newest first, sortable. Columns: name + ID, captured, lifetime bar, how it ended, live evidence and files & logs as tags, peak CPU · memory, ports, hash.
- **Resource charts (detail):** small multiples of CPU, memory and network in/out on a shared "seconds since start" axis, with a dashed stop line and 3 y ticks per chart. Legend only on the two-series network chart.
- **Forms:** 40px fields (#393939) with a 1px underline and a 2px white inset focus ring. Primary button: 48px, 0px corners, asymmetric padding.
- **Tags:** saved (blue-70 bg / blue-10 text), lost (red-70 / red-10), neutral (gray-70).
- **Notifications:** #393939 with a 3px left rule (info blue, success green, error red).

## Do's and Don'ts

### Do:
- **Do** keep corners at 0px (tags and bar ends excepted).
- **Do** write every outcome as a word or tag, and keep "lost" hatched.
- **Do** keep old (legacy) packages separate from current ones.
- **Do** switch to the light Carbon White tokens for print.

### Don't:
- **Don't** use IBM's name, logo or "Carbon" as product branding. This is inspired-by.
- **Don't** add shadows, gradients or glows (and no hacker-movie neon: user-rejected).
- **Don't** use more than one hue per chart series; single-series charts need no legend.
- **Don't** call a matching hash "verified" without the same-file caveat.
