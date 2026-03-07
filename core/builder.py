"""SQLMap command builder for SQLReaper."""
from __future__ import annotations

from typing import Dict, List

from core.config import ScanConfig


def base_flags(cfg: ScanConfig) -> List[str]:
    """Build the common SQLMap flags shared across all commands.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of common sqlmap flag strings.
    """
    flags: List[str] = ["-u", cfg.url, "--batch", f"--threads={cfg.threads}"]
    if cfg.data:
        flags += ["--data", cfg.data]
    if cfg.cookie:
        flags += ["--cookie", cfg.cookie]
    if cfg.tor:
        flags += ["--tor", "--tor-type=SOCKS5"]
    return flags


def build_all_commands(cfg: ScanConfig) -> List[Dict]:
    """Build the full list of command definitions for all enabled modules.

    Args:
        cfg: Resolved scan configuration.

    Returns:
        List of command definition dicts with keys: label, tag, tag_color, cmd.
    """
    from modules import recon, injection, dump, bypass, crawl, os_access

    module_map = {
        "recon": recon.get_commands,
        "injection": injection.get_commands,
        "dump": dump.get_commands,
        "bypass": bypass.get_commands,
        "crawl": crawl.get_commands,
        "os": os_access.get_commands,
    }

    commands: List[Dict] = []
    for mod_name in cfg.modules:
        fn = module_map.get(mod_name)
        if fn:
            commands.extend(fn(cfg))
    return commands
