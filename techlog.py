"""Central logging for Tech Monitoring — writes to tech.log."""

import logging
import os
import sys
import threading

_lock = threading.Lock()
_initialized = False


def log_file_path():
    explicit = os.environ.get("LOG_FILE", "").strip()
    if explicit:
        return explicit
    db_file = os.environ.get("DB_FILE", "uptime.db")
    base = os.path.dirname(os.path.abspath(db_file))
    if not base:
        base = os.path.join(os.getcwd(), "data")
    return os.path.join(base, "tech.log")


def setup_logging():
    global _initialized
    with _lock:
        if _initialized:
            return logging.getLogger("tech")
        path = log_file_path()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

        root = logging.getLogger("tech")
        root.setLevel(logging.DEBUG)
        root.handlers.clear()
        root.propagate = False

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)

        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)
        root.addHandler(sh)

        _initialized = True
        root.info("Logging started → %s", path)
        return root


def get_logger(module="app"):
    if not _initialized:
        setup_logging()
    return logging.getLogger(f"tech.{module}")
