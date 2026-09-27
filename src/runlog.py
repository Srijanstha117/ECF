"""
runlog.py -- where print() goes when there's no console window.

Started windowless (pythonw, or the packaged exe), a process has no
stdout/stderr, so anything it prints -- including a crash traceback --
would vanish. This sends both to logs/<name>.log instead, one timestamped
line at a time. The dashboard shows these files on its Logs page.

(Keep src/runlog.py and gui/runlog.py identical: the packaged dashboard
can't import src/.)
"""

import datetime
import os
import sys

MAX_BYTES = 2 * 1024 * 1024  # past this, the log is rotated to <name>.log.1 at startup


class _TimestampedWriter:
    encoding = "utf-8"
    errors = "replace"

    def __init__(self, stream):
        self._stream = stream
        self._at_line_start = True

    def write(self, text):
        # Text only. Libraries (click, used by Flask's startup banner) probe
        # with write(b"") and switch to bytes if it doesn't raise.
        if not isinstance(text, str):
            raise TypeError(f"write() argument must be str, not {type(text).__name__}")
        for part in text.splitlines(keepends=True):
            if self._at_line_start and part.strip():
                self._stream.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S  "))
            self._stream.write(part)
            self._at_line_start = part.endswith("\n")
        self._stream.flush()
        return len(text)

    def flush(self):
        self._stream.flush()

    def isatty(self):
        return False

    def writable(self):
        return True


def log_to_file_if_windowless(logs_dir, name):
    """Redirect stdout/stderr to logs/<name>.log when there's no console.
    Returns the log path, or None when output stays on the console."""
    if sys.stdout is not None and sys.stderr is not None and "--background" not in sys.argv:
        return None
    os.makedirs(logs_dir, exist_ok=True)
    path = os.path.join(logs_dir, f"{name}.log")
    try:
        if os.path.getsize(path) > MAX_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass
    writer = _TimestampedWriter(open(path, "a", encoding="utf-8", buffering=1))
    sys.stdout = sys.stderr = writer
    return path
