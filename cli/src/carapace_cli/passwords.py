"""The server's account password rules, checked before a password is sent.

The CLI does not depend on the server package, so the rules are mirrored
from ``server/src/carapace_server/auth/schemas.py``; a test pins the two
together. Checking here lets a prompt ask again instead of the server
rejecting the signup after the deploy.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from carapace_cli.errors import CarapaceError

PASSWORD_MIN_CHARS = 12
PASSWORD_MAX_CHARS = 128
PASSWORD_RULES = (
    (r"[A-Z]", "an uppercase letter"),
    (r"[a-z]", "a lowercase letter"),
    (r"\d", "a digit"),
    (r"[^A-Za-z0-9]", "a special character"),
)
MAX_PASSWORD_ATTEMPTS = 3


class WeakPasswordError(CarapaceError):
    """A new account password breaks the server's rules."""


def password_problem(value: str) -> str | None:
    """What is wrong with ``value`` as a new password, or None.

    The message names the rules only, never the value.
    """
    if not PASSWORD_MIN_CHARS <= len(value) <= PASSWORD_MAX_CHARS:
        return (
            f"the account password must be {PASSWORD_MIN_CHARS} to "
            f"{PASSWORD_MAX_CHARS} characters"
        )
    missing = [
        label for pattern, label in PASSWORD_RULES if not re.search(pattern, value)
    ]
    if missing:
        return f"the account password must contain {', '.join(missing)}"
    return None


def check_password(value: str) -> str:
    """``value`` if it meets the rules.

    Raises:
        WeakPasswordError: It does not.
    """
    problem = password_problem(value)
    if problem is not None:
        raise WeakPasswordError(problem)
    return value


def ask_new_password(
    prompt: Callable[[], str],
    say: Callable[[str], None],
    *,
    attempts: int = MAX_PASSWORD_ATTEMPTS,
) -> str:
    """Prompt until a password meets the rules, ``attempts`` times at most.

    Raises:
        WeakPasswordError: Every attempt broke a rule.
    """
    for _ in range(attempts):
        value = prompt()
        problem = password_problem(value)
        if problem is None:
            return value
        say(f"  {problem}")
    raise WeakPasswordError(f"no valid account password after {attempts} attempts")
