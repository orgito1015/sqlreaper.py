"""Reconnaissance module for SQLReaper — 5 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import CYAN


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return recon command definitions.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts.
    """
    b = base_flags(cfg)
    lv = f"--level={cfg.level}"
    return [
        {
            "label": "Quick Smart Detection",
            "tag": "RECON",
            "tag_color": CYAN,
            "cmd": ["sqlmap"] + b + ["--smart", "--fingerprint"],
        },
        {
            "label": "Detect DBMS & Server Version",
            "tag": "RECON",
            "tag_color": CYAN,
            "cmd": ["sqlmap"] + b + ["--fingerprint", lv],
        },
        {
            "label": "Parse & Analyze Errors",
            "tag": "RECON",
            "tag_color": CYAN,
            "cmd": ["sqlmap"] + b + ["--parse-errors"],
        },
        {
            "label": "Get Current Database & User",
            "tag": "RECON",
            "tag_color": CYAN,
            "cmd": ["sqlmap"] + b + ["--current-db", "--current-user"],
        },
        {
            "label": "Check DBA Privileges",
            "tag": "RECON",
            "tag_color": CYAN,
            "cmd": ["sqlmap"] + b + ["--is-dba"],
        },
    ]
