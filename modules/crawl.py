"""Crawl module for SQLReaper — 2 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import MAGENTA


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return crawl command definitions.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts.
    """
    b = base_flags(cfg)
    lv = f"--level={cfg.level}"
    return [
        {
            "label": "Crawl Site (depth 3)",
            "tag": "CRAWL",
            "tag_color": MAGENTA,
            "cmd": ["sqlmap"] + b + ["--crawl=3", "--smart"],
        },
        {
            "label": "Auto-detect & Attack Forms",
            "tag": "CRAWL",
            "tag_color": MAGENTA,
            "cmd": ["sqlmap"] + b + ["--forms", "--smart", lv],
        },
    ]
