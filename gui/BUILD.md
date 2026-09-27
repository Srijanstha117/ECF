# Building the standalone evidence viewer (no terminal needed to run it)

This packages `gui/app.py` into a single `.exe` that a marker/supervisor can
double-click. It opens a browser window automatically — no Python, no `pip
install`, no terminal on their end.

Note this only bundles the GUI (`gui/app.py`), which is read-only over
`evidence/*.json` files. It does not need Docker or the `docker` Python
package at all — `listener.py` still has to be run the normal way (in a
terminal, with Docker running) to actually *produce* evidence files. This
just makes *reviewing* the results double-click-simple.

## One-time setup

In the same venv you already use for this project:

```
pip install pyinstaller
```

## Build

From `code/gui/`:

```
cd gui
pyinstaller --onefile --name ContainerForensicsGUI --add-data "templates;templates" --add-data "static;static" app.py
```

(The `;` between source and destination in `--add-data` is Windows-specific
syntax — don't swap it for `:`, that's the Mac/Linux form.)

This creates `gui/dist/ContainerForensicsGUI.exe`.

## Place it correctly

Copy `ContainerForensicsGUI.exe` out of `dist/` and into `gui/` itself,
alongside `app.py`:

```
code/
  evidence/
  src/
  gui/
    app.py
    ContainerForensicsGUI.exe   <- built exe goes here
    templates/
    static/
```

It has to sit in `gui/`, not `code/` or anywhere else — it looks for
`evidence/` one level up from wherever it's actually running, matching where
`app.py` looks in dev.

## Run it

Double-click `ContainerForensicsGUI.exe`. A console window opens briefly
(that's normal — it's the server running), then your browser opens
automatically to the dashboard. Closing the console window stops it.

## Rebuilding after code changes

Any time you edit `app.py`, the templates, or the CSS, you need to rerun the
`pyinstaller` command above and re-copy the new exe — it's a snapshot, not
a live link to the source files.
