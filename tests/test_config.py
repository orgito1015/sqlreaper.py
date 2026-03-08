"""Tests for SQLReaper configuration loader and profile merger."""
from __future__ import annotations

import sys
import os
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.config import load_yaml, get_profile, build_config, ALL_MODULES, ScanConfig


REQUIRED_KEYS = {"level", "risk", "modules", "threads"}


class TestLoadYaml:
    def test_loads_without_error(self):
        data = load_yaml()
        assert isinstance(data, dict)

    def test_has_profiles_key(self):
        data = load_yaml()
        assert "profiles" in data

    def test_profiles_is_dict(self):
        data = load_yaml()
        assert isinstance(data["profiles"], dict)


class TestGetProfile:
    def test_quick_profile_exists(self):
        p = get_profile("quick")
        assert isinstance(p, dict)

    def test_full_profile_exists(self):
        p = get_profile("full")
        assert isinstance(p, dict)

    def test_stealth_profile_exists(self):
        p = get_profile("stealth")
        assert isinstance(p, dict)

    def test_waf_profile_exists(self):
        p = get_profile("waf")
        assert isinstance(p, dict)

    def test_quick_has_required_keys(self):
        p = get_profile("quick")
        assert REQUIRED_KEYS.issubset(p.keys())

    def test_full_has_required_keys(self):
        p = get_profile("full")
        assert REQUIRED_KEYS.issubset(p.keys())

    def test_stealth_has_required_keys(self):
        p = get_profile("stealth")
        assert REQUIRED_KEYS.issubset(p.keys())

    def test_waf_has_required_keys(self):
        p = get_profile("waf")
        assert REQUIRED_KEYS.issubset(p.keys())

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile("nonexistent")


class TestBuildConfig:
    def _make_args(self, **kwargs):
        """Create a minimal argparse.Namespace for testing."""
        defaults = {
            "url": "http://example.com/page.php?id=1",
            "data": None,
            "cookie": None,
            "database": None,
            "level": None,
            "risk": None,
            "threads": None,
            "modules": None,
            "profile": None,
            "all": False,
            "tor": False,
            "output": None,
            "resume": None,
            "report": False,
            "no_color": False,
            "quiet": False,
            "parallel": False,
            "notify": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_url_is_set(self):
        args = self._make_args(url="http://target.com/q?id=1")
        cfg = build_config(args)
        assert cfg.url == "http://target.com/q?id=1"

    def test_default_level_is_3(self):
        args = self._make_args()
        cfg = build_config(args)
        assert cfg.level == 3

    def test_default_risk_is_1(self):
        args = self._make_args()
        cfg = build_config(args)
        assert cfg.risk == 1

    def test_cli_level_overrides_profile(self):
        args = self._make_args(profile="quick", level=5)
        cfg = build_config(args)
        assert cfg.level == 5

    def test_cli_risk_overrides_profile(self):
        args = self._make_args(profile="full", risk=1)
        cfg = build_config(args)
        assert cfg.risk == 1

    def test_cli_threads_overrides_profile(self):
        args = self._make_args(profile="stealth", threads=6)
        cfg = build_config(args)
        assert cfg.threads == 6

    def test_profile_quick_sets_level_1(self):
        args = self._make_args(profile="quick")
        cfg = build_config(args)
        assert cfg.level == 1

    def test_profile_full_sets_level_5(self):
        args = self._make_args(profile="full")
        cfg = build_config(args)
        assert cfg.level == 5

    def test_modules_flag_parsed(self):
        args = self._make_args(modules="recon,dump")
        cfg = build_config(args)
        assert cfg.modules == ["recon", "dump"]

    def test_all_flag_sets_all_modules(self):
        args = self._make_args(**{"all": True})
        cfg = build_config(args)
        assert cfg.modules == list(ALL_MODULES)

    def test_tor_flag_set(self):
        args = self._make_args(tor=True)
        cfg = build_config(args)
        assert cfg.tor is True
