"""Tests for SQLReaper report findings parsing."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from output.reporter import _parse_findings


def _write_log(tmp_path, body):
    logfile = tmp_path / "results.log"
    logfile.write_text(body, encoding="utf-8")
    return str(logfile)


def _block(step, total, label, cmd, body, outcome="ok"):
    return (
        f"\n{'=' * 66}\n[{step}/{total}] {label}\n"
        f"CMD: {cmd}\n"
        f"TIME: 2024-01-01 00:00:00\n{'=' * 66}\n"
        f"{body}\n"
        f"RESULT: {outcome}  DURATION: 1.0s\n"
    )


def test_missing_logfile_returns_empty_findings(tmp_path):
    findings = _parse_findings(str(tmp_path / "nope.log"))
    assert findings["databases"] == []
    assert findings["tables"] == []
    assert findings["users"] == []
    assert findings["password_hashes"] == []
    assert findings["files_read"] == []


def test_databases_are_extracted_from_dbs_command(tmp_path):
    body = _block(
        1, 1, "Enumerate All Databases",
        "sqlmap -u http://x/ --batch --dbs",
        "available databases [2]:\n[*] information_schema\n[*] acuart",
    )
    logfile = _write_log(tmp_path, body)
    findings = _parse_findings(logfile)
    assert findings["databases"] == ["information_schema", "acuart"]


def test_tables_are_extracted_from_tables_command(tmp_path):
    body = _block(
        1, 1, "Enumerate Tables",
        "sqlmap -u http://x/ --batch -D acuart --tables",
        "Database: acuart\n[2 tables]\n+---------+\n| artists |\n| carts   |\n+---------+",
    )
    logfile = _write_log(tmp_path, body)
    findings = _parse_findings(logfile)
    assert findings["tables"] == ["artists", "carts"]


def test_users_are_extracted_from_users_command(tmp_path):
    body = _block(
        1, 1, "Extract DB Users",
        "sqlmap -u http://x/ --batch --users",
        "database management system users [1]:\n[*] 'root'@'localhost'",
    )
    logfile = _write_log(tmp_path, body)
    findings = _parse_findings(logfile)
    assert findings["users"] == ["'root'@'localhost'"]


def test_databases_and_users_are_not_cross_contaminated(tmp_path):
    """Both --dbs and --users output uses the same '[*] item' bullet format;
    the extractor must key off the command, not just the bullet marker."""
    body = _block(
        1, 1, "Enumerate All Databases",
        "sqlmap -u http://x/ --batch --dbs",
        "available databases [1]:\n[*] acuart",
    ) + _block(
        2, 1, "Extract DB Users",
        "sqlmap -u http://x/ --batch --users",
        "database management system users [1]:\n[*] 'root'@'localhost'",
    )
    logfile = _write_log(tmp_path, body)
    findings = _parse_findings(logfile)
    assert findings["databases"] == ["acuart"]
    assert findings["users"] == ["'root'@'localhost'"]


def test_files_read_only_recorded_on_success(tmp_path):
    ok_body = _block(
        1, 2, "Read File: /etc/passwd",
        "sqlmap -u http://x/ --batch --file-read=/etc/passwd",
        "the remote file '/etc/passwd' was downloaded",
        outcome="ok",
    )
    fail_body = _block(
        2, 2, "Read File: /etc/shadow",
        "sqlmap -u http://x/ --batch --file-read=/etc/shadow",
        "access denied",
        outcome="fail",
    )
    logfile = _write_log(tmp_path, ok_body + fail_body)
    findings = _parse_findings(logfile)
    assert findings["files_read"] == ["/etc/passwd"]


def test_password_hashes_extracted(tmp_path):
    body = _block(
        1, 1, "Extract DB Password Hashes",
        "sqlmap -u http://x/ --batch --passwords",
        "admin:*ABCDEF0123456789ABCDEF0123456789ABCDEF01",
    )
    logfile = _write_log(tmp_path, body)
    findings = _parse_findings(logfile)
    assert findings["password_hashes"] == ["admin:*ABCDEF0123456789ABCDEF0123456789ABCDEF01"]
