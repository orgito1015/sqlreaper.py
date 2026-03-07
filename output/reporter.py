"""Report generator for SQLReaper — HTML, JSON, and TXT formats."""
from __future__ import annotations

import datetime
import json
import os
import re
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from core.config import ScanConfig


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_DB_PATTERN = re.compile(r"\[\*\]\s+(\w+)")
_TABLE_PATTERN = re.compile(r"\|\s+([\w]+)\s+\|")
_USER_PATTERN = re.compile(r"\[\*\]\s+([\w@%]+)\s*$")
_HASH_PATTERN = re.compile(r"(\w+):\s*(\*[A-F0-9]{40})")
_VULN_PATTERN = re.compile(r"parameter '(.+?)' is vulnerable")
_FILE_PATTERN = re.compile(r"fetched data logged to text files under '(.+?)'")


def _parse_findings(logfile: str) -> Dict:
    """Parse sqlmap log output to extract key findings.

    Args:
        logfile: Path to the results.log file.

    Returns:
        Findings dict with keys: vulnerable_params, databases, tables,
        users, password_hashes, files_read.
    """
    findings: Dict = {
        "vulnerable_params": [],
        "databases": [],
        "tables": [],
        "users": [],
        "password_hashes": [],
        "files_read": [],
    }
    if not os.path.exists(logfile):
        return findings

    with open(logfile, "r", errors="replace") as fh:
        content = fh.read()

    for m in _VULN_PATTERN.finditer(content):
        p = m.group(1)
        if p not in findings["vulnerable_params"]:
            findings["vulnerable_params"].append(p)

    for m in _HASH_PATTERN.finditer(content):
        h = f"{m.group(1)}:{m.group(2)}"
        if h not in findings["password_hashes"]:
            findings["password_hashes"].append(h)

    return findings


def generate_json(
    outdir: str,
    cfg: ScanConfig,
    results: List[Dict],
    logfile: str,
) -> str:
    """Generate a JSON report file.

    Args:
        outdir: Output directory path.
        cfg: Resolved scan configuration.
        results: List of module result dicts.
        logfile: Path to results.log for findings parsing.

    Returns:
        Path to the generated report.json file.
    """
    findings = _parse_findings(logfile)
    total = len(results)
    completed = sum(1 for r in results if r["outcome"] in ("ok", "vulnerable"))
    skipped = sum(1 for r in results if r["outcome"] == "skip")
    failed = sum(1 for r in results if r["outcome"] == "fail")

    report = {
        "tool": "SQLReaper",
        "version": "2.0",
        "target": cfg.url,
        "timestamp": datetime.datetime.now().isoformat(),
        "config": {
            "level": cfg.level,
            "risk": cfg.risk,
            "threads": cfg.threads,
        },
        "summary": {
            "total": total,
            "completed": completed,
            "skipped": skipped,
            "failed": failed,
        },
        "findings": findings,
        "modules": results,
    }

    path = os.path.join(outdir, "report.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    return path


def generate_txt(
    outdir: str,
    cfg: ScanConfig,
    results: List[Dict],
    logfile: str,
) -> str:
    """Generate a plain-text report file.

    Args:
        outdir: Output directory path.
        cfg: Resolved scan configuration.
        results: List of module result dicts.
        logfile: Path to results.log for findings parsing.

    Returns:
        Path to the generated report.txt file.
    """
    findings = _parse_findings(logfile)
    total = len(results)
    completed = sum(1 for r in results if r["outcome"] in ("ok", "vulnerable"))
    skipped = sum(1 for r in results if r["outcome"] == "skip")
    failed = sum(1 for r in results if r["outcome"] == "fail")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "SQLReaper — Scan Report",
        "=======================",
        f"Target  : {cfg.url}",
        f"Date    : {now}",
        f"Modules : {total} total | {completed} ok | {skipped} skipped | {failed} failed",
        "",
        "FINDINGS",
        "--------",
        f"Databases  : {', '.join(findings['databases']) or 'N/A'}",
        f"Tables     : {', '.join(findings['tables']) or 'N/A'}",
        f"Users      : {', '.join(findings['users']) or 'N/A'}",
        f"Hashes     : {', '.join(findings['password_hashes']) or 'N/A'}",
        "",
        "MODULE RESULTS",
        "--------------",
    ]
    for r in results:
        outcome = r["outcome"].upper()
        tag = r.get("tag", "")
        label = r.get("label", "")
        duration = r.get("duration_seconds", 0)
        idx = r.get("id", 0)
        lines.append(f"[{idx:02d}] {outcome:<8s} [{tag}]  {label:<40s}  ({duration}s)")

    path = os.path.join(outdir, "report.txt")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def generate_html(
    outdir: str,
    cfg: ScanConfig,
    results: List[Dict],
    logfile: str,
) -> str:
    """Generate an HTML report file using a Jinja2 template.

    Args:
        outdir: Output directory path.
        cfg: Resolved scan configuration.
        results: List of module result dicts.
        logfile: Path to results.log for findings parsing and raw log.

    Returns:
        Path to the generated report.html file.
    """
    findings = _parse_findings(logfile)
    total = len(results)
    completed = sum(1 for r in results if r["outcome"] in ("ok", "vulnerable"))
    skipped = sum(1 for r in results if r["outcome"] == "skip")
    failed = sum(1 for r in results if r["outcome"] == "fail")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    raw_log = ""
    if os.path.exists(logfile):
        with open(logfile, "r", errors="replace") as fh:
            raw_log = fh.read()

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template("report.html")

    html = template.render(
        target=cfg.url,
        timestamp=now,
        total=total,
        completed=completed,
        skipped=skipped,
        failed=failed,
        findings=findings,
        results=results,
        raw_log=raw_log,
    )

    path = os.path.join(outdir, "report.html")
    with open(path, "w") as fh:
        fh.write(html)
    return path


def generate_all(outdir: str, cfg: ScanConfig, results: List[Dict], logfile: str) -> List[str]:
    """Generate all three report formats (JSON, TXT, HTML).

    Args:
        outdir: Output directory path.
        cfg: Resolved scan configuration.
        results: List of module result dicts.
        logfile: Path to results.log.

    Returns:
        List of paths to generated report files.
    """
    return [
        generate_json(outdir, cfg, results, logfile),
        generate_txt(outdir, cfg, results, logfile),
        generate_html(outdir, cfg, results, logfile),
    ]
