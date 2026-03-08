#!/usr/bin/env python3
"""SQLReaper — Automated SQL Injection Tool.

Precision. Speed. Depth.

Usage:
    python3 sqlreaper.py -u "https://target.com/page.php?id=1"
    python3 sqlreaper.py -u "https://target.com" --level 3 --risk 2 --all
    python3 sqlreaper.py -u "https://target.com" --modules recon,dump,bypass
    python3 sqlreaper.py -u "https://target.com" --profile stealth --tor
    python3 sqlreaper.py -u "https://target.com" --output ./my_results --report
    python3 sqlreaper.py --resume ./sqlreaper_results/previous_session/
"""
from __future__ import annotations

import argparse
import datetime
import os
import subprocess
import sys

# Ensure repo root is on sys.path for package imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.builder import build_all_commands
from core.config import build_config
from core.runner import load_session, run_all, save_session
from output.logger import make_outdir, write_resume_header, write_session_header
from output.reporter import generate_all
from utils.banner import (
    CYAN,
    GREEN,
    RED,
    RESET,
    WHITE,
    YELLOW,
    print_banner,
)
from utils.validator import validate_url


def build_parser() -> argparse.ArgumentParser:
    """Build the SQLReaper argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="sqlreaper",
        description="SQLReaper — Automated SQL Injection   powered by Pr0f3550r1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Target URL (required unless --resume)")
    parser.add_argument("-d", "--data", default="", help="POST body data")
    parser.add_argument("-c", "--cookie", default="", help="Session cookie string")
    parser.add_argument("-D", "--database", default="", help="Target database name")
    parser.add_argument("--level", type=int, default=None, help="SQLMap level 1-5 (default: 3)")
    parser.add_argument("--risk", type=int, default=None, help="SQLMap risk 1-3 (default: 1)")
    parser.add_argument("--threads", type=int, default=None, help="Threads 1-10 (default: 4)")
    parser.add_argument(
        "--modules",
        default=None,
        help="Comma-separated modules: recon,injection,dump,bypass,crawl,os",
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "full", "stealth", "waf"],
        default=None,
        help="Preset profile: quick, full, stealth, waf",
    )
    parser.add_argument("--all", action="store_true", help="Run all modules (default)")
    parser.add_argument("--tor", action="store_true", help="Route through Tor (SOCKS5)")
    parser.add_argument("--output", default="", help="Custom output directory path")
    parser.add_argument("--resume", default="", help="Resume from a previous session directory")
    parser.add_argument(
        "--report", action="store_true", help="Generate HTML + JSON + TXT report after scan"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="Hide sqlmap output")
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run independent modules concurrently",
    )
    parser.add_argument(
        "--notify", action="store_true", help="Send desktop notification on completion"
    )
    return parser


def check_sqlmap() -> None:
    """Verify that sqlmap is installed and available in PATH.

    Raises:
        SystemExit: If sqlmap is not found.
    """
    import shutil
    if not shutil.which("sqlmap"):
        print(f"{RED}[!] sqlmap not found. Install it: sudo apt install sqlmap{RESET}")
        sys.exit(1)


def send_notification(title: str, message: str) -> None:
    """Send a desktop notification using plyer or notify-send.

    Args:
        title: Notification title.
        message: Notification body text.
    """
    try:
        from plyer import notification

        notification.notify(title=title, message=message, timeout=10)
    except Exception:
        try:
            subprocess.run(["notify-send", title, message], check=False)
        except Exception:
            pass


def print_summary(
    outdir: str,
    logfile: str,
    results: list,
    no_color: bool = False,
) -> None:
    """Print a session summary to the terminal.

    Args:
        outdir: Output directory path.
        logfile: Path to results log.
        results: List of module result dicts.
        no_color: Whether to disable ANSI colors.
    """
    ok = sum(1 for r in results if r["outcome"] in ("ok", "vulnerable"))
    skipped = sum(1 for r in results if r["outcome"] == "skip")
    failed = sum(1 for r in results if r["outcome"] == "fail")
    total = len(results)

    g = GREEN if not no_color else ""
    w = WHITE if not no_color else ""
    y = YELLOW if not no_color else ""
    r = RED if not no_color else ""
    c = CYAN if not no_color else ""
    rs = RESET if not no_color else ""

    print(f"\n{g}{'═' * 66}")
    print(f"  {w}SESSION COMPLETE")
    print(f"{g}{'═' * 66}")
    print(f"  {g}✓  Completed : {w}{ok}/{total}")
    print(f"  {y}⊘  Skipped   : {w}{skipped}")
    print(f"  {r}✗  Failed    : {w}{failed}")
    print(f"\n  {c}Results folder : {w}{outdir}/")
    print(f"  {c}Full log       : {w}{logfile}")
    print(f"\n{g}{'═' * 66}{rs}\n")


def main() -> None:
    """Main entry point for SQLReaper."""
    parser = build_parser()
    args = parser.parse_args()

    no_color = getattr(args, "no_color", False)

    print_banner(no_color=no_color)

    print(
        f"{YELLOW}  ⚠  LEGAL WARNING: Use only on systems you own or have explicit written\n"
        f"     authorization to test. Unauthorized use is illegal.{RESET}\n"
    )

    # Handle --resume
    resume_results = None
    if args.resume:
        session_file = os.path.join(args.resume, "session.json")
        logfile = os.path.join(args.resume, "results.log")
        try:
            session = load_session(session_file)
            resume_results = session.get("results", [])
            write_resume_header(logfile)
            print(f"{GREEN}[✓] Resuming session from: {args.resume}{RESET}")
        except FileNotFoundError as exc:
            print(f"{RED}[!] {exc}{RESET}")
            sys.exit(1)

        # Try to extract the original URL from the session log
        if not args.url:
            try:
                with open(logfile, "r", errors="replace") as _lf:
                    for _line in _lf:
                        if _line.startswith("Target  :"):
                            args.url = _line.split(":", 1)[1].strip()
                            break
            except OSError:
                pass
            if not args.url:
                args.url = "unknown"
        cfg = build_config(args)
        outdir = args.resume
    else:
        if not args.url:
            parser.error("argument -u/--url is required unless --resume is used")

        try:
            validate_url(args.url)
        except ValueError as exc:
            print(f"{RED}[!] Invalid URL: {exc}{RESET}")
            sys.exit(1)

        cfg = build_config(args)
        outdir = make_outdir(cfg.url, cfg.output or "sqlreaper_results")
        logfile = os.path.join(outdir, "results.log")

    check_sqlmap()

    commands = build_all_commands(cfg)
    total = len(commands)
    session_file = os.path.join(outdir, "session.json")

    if not args.resume:
        write_session_header(logfile, cfg, total)

    g = GREEN if not no_color else ""
    w = WHITE if not no_color else ""
    y = YELLOW if not no_color else ""
    rs = RESET if not no_color else ""

    print(f"\n{g}  [✓] {total} modules queued")
    print(f"  [✓] Saving output to : {w}{outdir}/{g}")
    print(f"  [✓] Live log         : {w}{logfile}{g}")
    print(f"\n{y}  Ctrl+C once  →  skip current module")
    print(f"  Ctrl+C twice →  quit entirely{rs}\n")

    results = run_all(
        commands=commands,
        logfile=logfile,
        session_file=session_file,
        quiet=cfg.quiet,
        resume_results=resume_results,
    )

    print_summary(outdir, logfile, results, no_color=no_color)

    if cfg.report:
        report_files = generate_all(outdir, cfg, results, logfile)
        print(f"{g}  [✓] Reports generated:{rs}")
        for rf in report_files:
            print(f"      {rf}")

    if cfg.notify:
        ok = sum(1 for r in results if r["outcome"] in ("ok", "vulnerable"))
        send_notification(
            "SQLReaper",
            f"Scan complete — {ok}/{total} modules OK. Results in {outdir}",
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Session terminated by user.{RESET}\n")
        sys.exit(0)
