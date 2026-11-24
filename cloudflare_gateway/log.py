"""Tiny logger used when this patch tree is tested standalone."""
from __future__ import annotations

import sys


def info(msg: str) -> None:
    print(f"INFO {msg}")


def warn(msg: str) -> None:
    print(f"WARN {msg}")


def fatal(msg: str) -> None:
    print(f"FATAL {msg}", file=sys.stderr)
    raise SystemExit(1)
