import sys, os, traceback, ctypes
from pathlib import Path

LOG_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LocalRedaction" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "worker.log"

# With --noconsole, sys.stdout / sys.stderr are None. Redirect them to a file.
if sys.stdout is None:
    sys.stdout = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
if sys.stderr is None:
    sys.stderr = open(LOG_FILE, "a", encoding="utf-8", buffering=1)

def _show_fatal(title: str, msg: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0x10)  # MB_ICONERROR
    except Exception:
        pass

def _excepthook(t, v, tb):
    text = "".join(traceback.format_exception(t, v, tb))
    sys.stderr.write(text)
    sys.stderr.flush()
    _show_fatal(
        "LocalRedaction worker crashed",
        f"{v}\n\nFull log:\n{LOG_FILE}",
    )

sys.excepthook = _excepthook