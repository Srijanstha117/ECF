# Building the standalone evidence viewer (no terminal needed to run it)

This packages `gui/app.py` into a single `.exe` that a marker/supervisor can
double-click. It opens a browser window automatically — no Python, no `pip
install`, no terminal on their end.

Note this only bundles the GUI (`gui/app.py`), which is read-only over
`evidence/*.json` files and doesn't need the `docker` package. On launch
it starts the capture listener (`src/listener.py`) in the background with
the project's own `venv` Python, so the venv must exist next to it (see
the README). Without it, the dashboard still opens and says why the
listener couldn't start (Logs page).

## One-time setup

In the same venv you already use for this project:

```
pip install pyinstaller
```

## Build

From `code/gui/`:

```
cd gui
pyinstaller --onefile --name DocIt --add-data "templates;templates" --add-data "static;static" app.py
```

(The `;` between source and destination in `--add-data` is Windows-specific
syntax — don't swap it for `:`, that's the Mac/Linux form.)

This creates `gui/dist/DocIt.exe`.

## Place it correctly

Copy `DocIt.exe` out of `dist/` and into `gui/` itself,
alongside `app.py`:

```
code/
  evidence/
  src/
  gui/
    app.py
    DocIt.exe                   <- built exe goes here
    templates/
    static/
```

It has to sit in `gui/`, not `code/` or anywhere else — it looks for
`evidence/` one level up from wherever it's actually running, matching where
`app.py` looks in dev.

## Run it

Double-click `DocIt.exe`. No window opens (the spec
has `console=False`); your browser opens to the dashboard, and the
listener is started in the background. Stop it with **Shut down** in the
dashboard. Output goes to `logs/dashboard.log`, shown on the Logs page.
Opening it a second time just opens the browser on the running one.

## Rebuilding after code changes

Any time you edit `app.py`, the templates, or the CSS, you need to rerun the
`pyinstaller` command above and re-copy the new exe — it's a snapshot, not
a live link to the source files.
