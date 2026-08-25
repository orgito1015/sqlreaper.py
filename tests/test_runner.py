"""Tests for SQLReaper's subprocess runner, focused on Ctrl+C handling."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.runner import is_double_ctrlc


def test_second_press_within_threshold_quits():
    assert is_double_ctrlc(now=10.5, last=10.0) is True


def test_second_press_outside_threshold_does_not_quit():
    assert is_double_ctrlc(now=12.5, last=10.0) is False


def test_first_press_ever_does_not_quit():
    """last=0.0 is the sentinel used before any Ctrl+C has been seen."""
    assert is_double_ctrlc(now=1000.0, last=0.0) is False


def test_custom_threshold_respected():
    assert is_double_ctrlc(now=10.4, last=10.0, threshold=0.3) is False
    assert is_double_ctrlc(now=10.2, last=10.0, threshold=0.3) is True
