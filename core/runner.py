"""Subprocess execution engine for SQLReaper."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import datetime
from typing import Dict, List, Optional

from utils.banner import (
    GREEN, YELLOW, RED, CYAN, WHITE, DIM_GREEN, RESET, DIM
)


def progress_bar(step: int, total: int, width: int = 30) -> str:
    """Render a simple text progress bar.

    Args:
        step: Current step number.
        total: Total number of steps.
        width: Width of the bar in characters.

    Returns:
        Formatted progress bar string.
    """
    filled = int(width * step / total)
    bar = GREEN + "█" * filled + DIM + "░" * (width - filled) + RESET
    pct = int(100 * step / total)
    return f"[{bar}{GREEN}] {WHITE}{pct}%{RESET}"


def step_header(step: int, total: int, label: str, tag: str, tag_color: str) -> None:
    """Print a formatted section header for a module.

    Args:
        step: Current module index.
        total: Total number of modules.
        label: Human-readable module label.
        tag: Short tag (e.g. RECON, INJECT).
        tag_color: ANSI color string for the tag.
    """
    print(f"\n{GREEN}{'═' * 66}")
    print(f"  {tag_color}[{tag}]{WHITE}  {label}")
    print(f"  {DIM}Module {step}/{total}  {RESET}{progress_bar(step, total)}")
    print(f"{GREEN}{'═' * 66}{RESET}\n")


def highlight_line(line: str) -> str:
    """Apply color highlighting to notable sqlmap output lines.

    Args:
        line: A single line of sqlmap stdout.

    Returns:
        The line with ANSI color codes applied if a keyword matched.
    """
    if "is vulnerable" in line:
        return f"{RED}{line}{RESET}"
    if "available databases" in line:
        return f"{YELLOW}{line}{RESET}"
    if "fetched data logged" in line:
        return f"{GREEN}{line}{RESET}"
    return line


def run_module(
    label: str,
    cmd: List[str],
    logfile: str,
    step: int,
    total: int,
    tag: str = "RUN",
    tag_color: str = CYAN,
    quiet: bool = False,
) -> str:
    """Execute a single sqlmap command and stream its output.

    Args:
        label: Human-readable label for this module.
        cmd: Command list to pass to subprocess.Popen.
        logfile: Path to the log file.
        step: Current module index (1-based).
        total: Total number of modules.
        tag: Short category tag string.
        tag_color: ANSI color for the tag.
        quiet: If True, suppress sqlmap stdout to terminal.

    Returns:
        Outcome string: 'ok', 'skip', or 'fail'.
    """
    step_header(step, total, label, tag, tag_color)
    print(f"{DIM}  $ {' '.join(cmd)}{RESET}\n")

    with open(logfile, "a") as lf:
        lf.write(f"\n{'=' * 66}\n[{step}/{total}] {label}\n")
        lf.write(f"CMD: {' '.join(cmd)}\n")
        lf.write(f"TIME: {datetime.datetime.now()}\n{'=' * 66}\n")

    outcome = "ok"
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        with open(logfile, "a") as lf:
            for line in proc.stdout:
                if not quiet:
                    sys.stdout.write(highlight_line(line))
                    sys.stdout.flush()
                lf.write(line)
                # Detect vulnerability finding
                if "is vulnerable" in line:
                    outcome = "vulnerable"
        proc.wait()
        if outcome != "vulnerable":
            outcome = "ok" if proc.returncode == 0 else "fail"
        status = (
            f"{GREEN}[✓] Module complete{RESET}"
            if proc.returncode == 0
            else f"{YELLOW}[~] Finished (exit code {proc.returncode}){RESET}"
        )
    except KeyboardInterrupt:
        try:
            proc.kill()
        except Exception:
            pass
        print(f"\n{YELLOW}[!] Module skipped — moving to next...{RESET}")
        status = f"{YELLOW}[!] Skipped by user{RESET}"
        outcome = "skip"
        time.sleep(0.8)
    except Exception as e:
        status = f"{RED}[✗] Error: {e}{RESET}"
        outcome = "fail"

    duration = round(time.time() - start, 1)
    with open(logfile, "a") as lf:
        lf.write(f"\nRESULT: {outcome}  DURATION: {duration}s\n")
    print(f"\n  {status}\n")
    time.sleep(0.3)
    return outcome


def save_session(
    session_file: str,
    modules: List[Dict],
    results: List[Dict],
) -> None:
    """Persist session state to a JSON file for resume support.

    Args:
        session_file: Path to write the session JSON.
        modules: List of module definition dicts.
        results: List of result dicts (label, outcome, duration).
    """
    data = {"modules": modules, "results": results}
    with open(session_file, "w") as fh:
        json.dump(data, fh, indent=2)


def load_session(session_file: str) -> Dict:
    """Load a previously saved session JSON.

    Args:
        session_file: Path to the session JSON file.

    Returns:
        Session data dict.

    Raises:
        FileNotFoundError: If the session file does not exist.
    """
    if not os.path.exists(session_file):
        raise FileNotFoundError(f"Session file not found: {session_file}")
    with open(session_file, "r") as fh:
        return json.load(fh)


def run_all(
    commands: List[Dict],
    logfile: str,
    session_file: str,
    quiet: bool = False,
    resume_results: Optional[List[Dict]] = None,
) -> List[Dict]:
    """Execute all queued commands sequentially.

    Args:
        commands: List of command definition dicts.
        logfile: Path to the results log file.
        session_file: Path to session.json for state persistence.
        quiet: Whether to suppress sqlmap output.
        resume_results: Pre-existing results from a resumed session.

    Returns:
        List of result dicts (label, tag, outcome, duration_seconds).
    """
    total = len(commands)
    results: List[Dict] = resume_results or []
    completed_labels = {r["label"] for r in results if r["outcome"] in ("ok", "skip", "vulnerable")}

    _last_ctrlc: float = 0.0

    for i, cmd_def in enumerate(commands, 1):
        label = cmd_def["label"]
        if label in completed_labels:
            print(f"{YELLOW}  [↩] Skipping (already done): {label}{RESET}")
            continue

        start = time.time()
        try:
            outcome = run_module(
                label=label,
                cmd=cmd_def["cmd"],
                logfile=logfile,
                step=i,
                total=total,
                tag=cmd_def.get("tag", "RUN"),
                tag_color=cmd_def.get("tag_color", CYAN),
                quiet=quiet,
            )
        except KeyboardInterrupt:
            now = time.time()
            if now - _last_ctrlc < 1.0:
                print(f"\n{RED}[!] Second Ctrl+C — exiting session.{RESET}\n")
                save_session(session_file, commands, results)
                sys.exit(0)
            _last_ctrlc = now
            outcome = "skip"

        duration = round(time.time() - start, 1)
        results.append({
            "id": i,
            "label": label,
            "tag": cmd_def.get("tag", "RUN"),
            "outcome": outcome,
            "duration_seconds": duration,
        })
        save_session(session_file, [{"label": c["label"], "tag": c.get("tag", "")} for c in commands], results)

    return results
