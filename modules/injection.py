"""Injection module for SQLReaper — 6 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import RED


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return injection command definitions.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts.
    """
    b = base_flags(cfg)
    lv = f"--level={cfg.level}"
    rk = f"--risk={cfg.risk}"
    return [
        {
            "label": "Full Scan — All Techniques (BEUSTQ)",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + [lv, rk, "--technique=BEUSTQ"],
        },
        {
            "label": "Boolean-based Blind",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + ["--technique=B", lv],
        },
        {
            "label": "Time-based Blind (5s timeout)",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + ["--technique=T", lv, "--time-sec=5"],
        },
        {
            "label": "Error-based Injection",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + ["--technique=E", lv],
        },
        {
            "label": "UNION-based Injection",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + ["--technique=U", "--union-cols=1-25"],
        },
        {
            "label": "Stacked Queries",
            "tag": "INJECT",
            "tag_color": RED,
            "cmd": ["sqlmap"] + b + ["--technique=S", lv, rk],
        },
    ]
