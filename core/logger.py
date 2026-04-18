import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-18s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _resolve_log_dir() -> Path:
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent.parent
    log_dir = base / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def get_logger(name: str = "sentinel") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    log_path = _resolve_log_dir() / "sentinel_audit.log"

    file_handler = RotatingFileHandler(
        log_path, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger.debug("Logger initialized (pid=%s, path=%s)", os.getpid(), log_path)
    return logger
