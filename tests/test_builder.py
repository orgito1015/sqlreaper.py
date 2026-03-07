"""Tests for SQLReaper command builders."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.config import ScanConfig, ALL_MODULES
from core.builder import build_all_commands, base_flags


@pytest.fixture
def basic_cfg():
    cfg = ScanConfig()
    cfg.url = "http://testphp.vulnweb.com/artists.php?artist=1"
    cfg.level = 3
    cfg.risk = 1
    cfg.threads = 4
    cfg.modules = list(ALL_MODULES)
    return cfg


@pytest.fixture
def cfg_with_data_cookie():
    cfg = ScanConfig()
    cfg.url = "http://testphp.vulnweb.com/login.php"
    cfg.data = "uname=admin&pass=test"
    cfg.cookie = "PHPSESSID=abc123"
    cfg.level = 3
    cfg.risk = 1
    cfg.threads = 4
    cfg.modules = list(ALL_MODULES)
    return cfg


@pytest.fixture
def cfg_with_db():
    cfg = ScanConfig()
    cfg.url = "http://testphp.vulnweb.com/artists.php?artist=1"
    cfg.database = "acuart"
    cfg.level = 3
    cfg.risk = 1
    cfg.threads = 4
    cfg.modules = list(ALL_MODULES)
    return cfg


def test_build_all_commands_non_empty(basic_cfg):
    """All modules together should produce 28 commands (5+6+7+6+2+2)."""
    cmds = build_all_commands(basic_cfg)
    assert len(cmds) > 0


def test_build_all_commands_count(basic_cfg):
    """Full module list should produce exactly 28 commands."""
    cmds = build_all_commands(basic_cfg)
    assert len(cmds) == 28


def test_each_module_non_empty(basic_cfg):
    """Each module should produce at least 1 command."""
    from modules import recon, injection, dump, bypass, crawl, os_access
    for mod in [recon, injection, dump, bypass, crawl, os_access]:
        cmds = mod.get_commands(basic_cfg)
        assert len(cmds) > 0


def test_url_in_base_flags(basic_cfg):
    """Base flags must include -u and the target URL."""
    flags = base_flags(basic_cfg)
    assert "-u" in flags
    assert basic_cfg.url in flags


def test_batch_in_base_flags(basic_cfg):
    """Base flags must include --batch."""
    flags = base_flags(basic_cfg)
    assert "--batch" in flags


def test_threads_in_base_flags(basic_cfg):
    """Base flags must include --threads."""
    flags = base_flags(basic_cfg)
    assert any("--threads" in f for f in flags)


def test_data_injected_when_set(cfg_with_data_cookie):
    """--data flag should be present in base flags when cfg.data is set."""
    flags = base_flags(cfg_with_data_cookie)
    assert "--data" in flags
    assert cfg_with_data_cookie.data in flags


def test_cookie_injected_when_set(cfg_with_data_cookie):
    """--cookie flag should be present in base flags when cfg.cookie is set."""
    flags = base_flags(cfg_with_data_cookie)
    assert "--cookie" in flags
    assert cfg_with_data_cookie.cookie in flags


def test_data_absent_when_not_set(basic_cfg):
    """--data flag should not appear when cfg.data is empty."""
    flags = base_flags(basic_cfg)
    assert "--data" not in flags


def test_cookie_absent_when_not_set(basic_cfg):
    """--cookie flag should not appear when cfg.cookie is empty."""
    flags = base_flags(basic_cfg)
    assert "--cookie" not in flags


def test_database_in_dump_commands(cfg_with_db):
    """Dump module commands should include -D <dbname> when database is set."""
    from modules.dump import get_commands
    cmds = get_commands(cfg_with_db)
    # Commands that use db flag: Enumerate Tables, Columns, Dump All
    db_cmds = [c for c in cmds if "-D" in c["cmd"]]
    assert len(db_cmds) > 0
    for c in db_cmds:
        idx = c["cmd"].index("-D")
        assert c["cmd"][idx + 1] == cfg_with_db.database


def test_database_absent_when_not_set(basic_cfg):
    """Dump module commands should not include -D when database is not set."""
    from modules.dump import get_commands
    cmds = get_commands(basic_cfg)
    for c in cmds:
        assert "-D" not in c["cmd"]


def test_command_dicts_have_required_keys(basic_cfg):
    """Each command dict must have label, tag, tag_color, and cmd keys."""
    cmds = build_all_commands(basic_cfg)
    for c in cmds:
        assert "label" in c
        assert "tag" in c
        assert "tag_color" in c
        assert "cmd" in c
