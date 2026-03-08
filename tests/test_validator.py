"""Tests for SQLReaper input validators."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from utils.validator import validate_url, clamp_level, clamp_risk, clamp_threads


class TestValidateUrl:
    def test_valid_http_url(self):
        url = "http://testphp.vulnweb.com/artists.php?artist=1"
        assert validate_url(url) == url

    def test_valid_https_url(self):
        url = "https://example.com/page.php?id=1"
        assert validate_url(url) == url

    def test_missing_scheme_raises(self):
        with pytest.raises(ValueError, match="http"):
            validate_url("testphp.vulnweb.com/artists.php")

    def test_ftp_scheme_raises(self):
        with pytest.raises(ValueError):
            validate_url("ftp://testphp.vulnweb.com/")

    def test_empty_url_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url("   ")

    def test_strips_whitespace(self):
        url = "  http://example.com/  "
        result = validate_url(url)
        assert not result.startswith(" ")
        assert not result.endswith(" ")


class TestClampLevel:
    def test_valid_level_1(self):
        assert clamp_level(1) == 1

    def test_valid_level_5(self):
        assert clamp_level(5) == 5

    def test_level_too_low_clamps_to_1(self):
        assert clamp_level(0) == 1

    def test_level_too_high_clamps_to_5(self):
        assert clamp_level(10) == 5

    def test_level_string_input(self):
        assert clamp_level("3") == 3

    def test_level_invalid_string_defaults_to_3(self):
        assert clamp_level("abc") == 3

    def test_level_none_defaults_to_3(self):
        assert clamp_level(None) == 3


class TestClampRisk:
    def test_valid_risk_1(self):
        assert clamp_risk(1) == 1

    def test_valid_risk_3(self):
        assert clamp_risk(3) == 3

    def test_risk_too_low_clamps_to_1(self):
        assert clamp_risk(0) == 1

    def test_risk_too_high_clamps_to_3(self):
        assert clamp_risk(99) == 3

    def test_risk_string_input(self):
        assert clamp_risk("2") == 2

    def test_risk_invalid_string_defaults_to_1(self):
        assert clamp_risk("bad") == 1


class TestClampThreads:
    def test_valid_threads(self):
        assert clamp_threads(4) == 4

    def test_threads_too_low_clamps_to_1(self):
        assert clamp_threads(0) == 1

    def test_threads_too_high_clamps_to_10(self):
        assert clamp_threads(100) == 10

    def test_threads_string_input(self):
        assert clamp_threads("8") == 8

    def test_threads_invalid_string_defaults_to_4(self):
        assert clamp_threads("x") == 4
