"""Configuration loader and profile merger for SQLReaper."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "default.yaml")

ALL_MODULES = ["recon", "injection", "dump", "bypass", "crawl", "os"]


@dataclass
class ScanConfig:
    """Holds the fully-resolved scan configuration.

    Attributes:
        url: Target URL.
        data: Optional POST body.
        cookie: Optional session cookie.
        database: Optional target database name.
        level: SQLMap level (1-5).
        risk: SQLMap risk (1-3).
        threads: Number of threads (1-10).
        modules: List of module names to run.
        tamper: Optional tamper script string.
        delay: Delay between requests in seconds.
        tor: Whether to route through Tor.
        output: Output directory path.
        resume: Path to a previous session directory.
        report: Whether to generate reports.
        no_color: Whether to disable ANSI colors.
        quiet: Whether to suppress sqlmap output.
        parallel: Whether to run modules in parallel.
        notify: Whether to send desktop notifications.
    """

    url: str = ""
    data: str = ""
    cookie: str = ""
    database: str = ""
    level: int = 3
    risk: int = 1
    threads: int = 4
    modules: List[str] = field(default_factory=lambda: list(ALL_MODULES))
    tamper: str = ""
    delay: int = 0
    tor: bool = False
    output: str = ""
    resume: str = ""
    report: bool = False
    no_color: bool = False
    quiet: bool = False
    parallel: bool = False
    notify: bool = False


def load_yaml() -> Dict[str, Any]:
    """Load the default.yaml configuration file.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
    """
    path = os.path.abspath(CONFIG_PATH)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r") as fh:
        return yaml.safe_load(fh) or {}


def get_profile(name: str) -> Dict[str, Any]:
    """Retrieve a named scan profile from default.yaml.

    Args:
        name: Profile name (quick, full, stealth, waf).

    Returns:
        Profile dictionary.

    Raises:
        ValueError: If the profile name is not found.
    """
    data = load_yaml()
    profiles = data.get("profiles", {})
    if name not in profiles:
        valid = list(profiles.keys())
        raise ValueError(f"Unknown profile {name!r}. Valid profiles: {valid}")
    return profiles[name]


def build_config(args: Any) -> ScanConfig:
    """Build a ScanConfig from parsed argparse arguments, merging any profile.

    CLI flags always take priority over profile values.

    Args:
        args: argparse.Namespace from the CLI parser.

    Returns:
        Fully resolved ScanConfig instance.
    """
    cfg = ScanConfig()

    # Apply profile first (lower priority)
    if hasattr(args, "profile") and args.profile:
        profile = get_profile(args.profile)
        cfg.level = profile.get("level", cfg.level)
        cfg.risk = profile.get("risk", cfg.risk)
        cfg.threads = profile.get("threads", cfg.threads)
        cfg.delay = profile.get("delay", cfg.delay)
        cfg.tamper = profile.get("tamper", cfg.tamper)
        mods = profile.get("modules", ALL_MODULES)
        cfg.modules = ALL_MODULES if mods == "all" else list(mods)

    # CLI flags override profile
    if hasattr(args, "url") and args.url:
        cfg.url = args.url
    if hasattr(args, "data") and args.data:
        cfg.data = args.data
    if hasattr(args, "cookie") and args.cookie:
        cfg.cookie = args.cookie
    if hasattr(args, "database") and args.database:
        cfg.database = args.database
    if hasattr(args, "level") and args.level is not None:
        cfg.level = args.level
    if hasattr(args, "risk") and args.risk is not None:
        cfg.risk = args.risk
    if hasattr(args, "threads") and args.threads is not None:
        cfg.threads = args.threads
    if hasattr(args, "tor") and args.tor:
        cfg.tor = args.tor
    if hasattr(args, "output") and args.output:
        cfg.output = args.output
    if hasattr(args, "resume") and args.resume:
        cfg.resume = args.resume
    if hasattr(args, "report") and args.report:
        cfg.report = args.report
    if hasattr(args, "no_color") and args.no_color:
        cfg.no_color = args.no_color
    if hasattr(args, "quiet") and args.quiet:
        cfg.quiet = args.quiet
    if hasattr(args, "parallel") and args.parallel:
        cfg.parallel = args.parallel
    if hasattr(args, "notify") and args.notify:
        cfg.notify = args.notify

    # Modules flag
    if hasattr(args, "modules") and args.modules:
        cfg.modules = [m.strip() for m in args.modules.split(",")]
    elif hasattr(args, "all") and args.all:
        cfg.modules = list(ALL_MODULES)

    return cfg
