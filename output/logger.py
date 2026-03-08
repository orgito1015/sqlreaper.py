"""Terminal and file logging utilities for SQLReaper."""
from __future__ import annotations

import datetime
import os
from typing import Optional

from core.config import ScanConfig


def make_outdir(url: str, base_dir: str = "") -> str:
    """Create a timestamped output directory for the scan.

    Args:
        url: Target URL (used to derive directory name).
        base_dir: Optional custom base directory.

    Returns:
        Path to the created output directory.
    """
    safe = url.replace("https://", "").replace("http://", "")
    safe = safe.replace("/", "_").replace(":", "_")
    safe = "".join(c for c in safe if c.isalnum() or c in "_-")[:50]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    parent = base_dir if base_dir else "sqlreaper_results"
    d = os.path.join(parent, f"{safe}_{ts}")
    os.makedirs(d, exist_ok=True)
    return d


def write_session_header(logfile: str, cfg: ScanConfig, total: int) -> None:
    """Write the session header to the log file.

    Args:
        logfile: Path to the log file.
        cfg: Resolved scan configuration.
        total: Total number of modules to run.
    """
    with open(logfile, "w") as lf:
        lf.write("SQLReaper — Session Log\n")
        lf.write(f"Target  : {cfg.url}\n")
        lf.write(f"Post    : {cfg.data or 'N/A'}\n")
        lf.write(f"Cookie  : {cfg.cookie or 'N/A'}\n")
        lf.write(f"DB      : {cfg.database or 'N/A'}\n")
        lf.write(
            f"Config  : risk={cfg.risk}  level={cfg.level}  threads={cfg.threads}\n"
        )
        lf.write(f"Modules : {total}\n")
        lf.write(f"Started : {datetime.datetime.now()}\n")
        lf.write(f"{'=' * 66}\n")


def write_resume_header(logfile: str) -> None:
    """Append a RESUMED SESSION marker to the log file.

    Args:
        logfile: Path to the existing log file.
    """
    with open(logfile, "a") as lf:
        lf.write(f"\n{'=' * 66}\nRESUMED SESSION: {datetime.datetime.now()}\n{'=' * 66}\n")
