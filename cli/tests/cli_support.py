"""Helpers shared by the CLI tests (see the root pytest ``pythonpath``)."""

from __future__ import annotations

from typing import Any

SECRET_VALUE = b"ghp_s3cr3t-T0KEN/with+base64?chars=="
UPSTREAM_URL = "https://api.github.com/user"


def add_github_secret(stack: Any, name: str = "github") -> str:
    """Seal SECRET_VALUE for api.github.com via the CLI; returns its id."""
    code, out, err = stack.cli(
        "secret",
        "add",
        name,
        "--host",
        "api.github.com",
        "--method",
        "GET",
        "--method",
        "POST",
        stdin=SECRET_VALUE + b"\n",
    )
    assert code == 0, err
    return out.split()[0]


def create_key(stack: Any, secret: str) -> str:
    """Create an API key for ``secret`` via the CLI; returns the raw key."""
    code, out, err = stack.cli("key", "create", "agent", "--secret", secret)
    assert code == 0, err
    return out.strip()
