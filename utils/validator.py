"""Input validation utilities for SQLReaper."""
from __future__ import annotations

from urllib.parse import urlparse


def validate_url(url: str) -> str:
    """Validate and return a normalized URL.

    Args:
        url: The URL string to validate.

    Returns:
        The validated URL string.

    Raises:
        ValueError: If the URL is empty or missing a scheme.
    """
    if not url or not url.strip():
        raise ValueError("URL must not be empty.")
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must start with http:// or https://, got: {url!r}")
    return url.strip()


def clamp_level(value: int | str) -> int:
    """Clamp a level value to the valid sqlmap range [1, 5].

    Args:
        value: The level value (int or str).

    Returns:
        Clamped integer between 1 and 5; defaults to 3 on parse error.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 3
    return max(1, min(5, v))


def clamp_risk(value: int | str) -> int:
    """Clamp a risk value to the valid sqlmap range [1, 3].

    Args:
        value: The risk value (int or str).

    Returns:
        Clamped integer between 1 and 3; defaults to 1 on parse error.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 1
    return max(1, min(3, v))


def clamp_threads(value: int | str) -> int:
    """Clamp a threads value to the valid range [1, 10].

    Args:
        value: The threads value (int or str).

    Returns:
        Clamped integer between 1 and 10; defaults to 4 on parse error.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 4
    return max(1, min(10, v))
