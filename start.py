r"""
start.py -- opens DocIt in the background, with no windows (any OS).

On Windows, double-clicking start.vbs does the same thing.

Runs the dashboard (gui/app.py --open) in the background and returns at
once. The dashboard opens your browser, starts the capture listener, and
starts Docker Desktop if it isn't running. Opened twice, it just shows
the one that's already running. Stop everything with "Shut down" in the
dashboard; what would have been printed is on its Logs page (logs/*.log).

Run with:  venv/bin/python start.py   (or venv\Scripts\python.exe start.py)
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    python = sys.executable
    command = [python, os.path.join(ROOT, "gui", "app.py"), "--open"]
    kwargs = {"cwd": ROOT, "stdin": subprocess.DEVNULL,
              "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        # pythonw.exe is the same Python without a console window.
        windowless = os.path.join(os.path.dirname(python), "pythonw.exe")
        if os.path.isfile(windowless):
            command[0] = windowless
        flags = subprocess.CREATE_NO_WINDOW
        try:
            subprocess.Popen(command, creationflags=flags | subprocess.CREATE_BREAKAWAY_FROM_JOB, **kwargs)
        except OSError:
            subprocess.Popen(command, creationflags=flags, **kwargs)
    else:
        subprocess.Popen(command, start_new_session=True, **kwargs)
    print("DocIt is starting in the background -- your browser will open in a moment.")
    print("Stop it with Shut down in the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
