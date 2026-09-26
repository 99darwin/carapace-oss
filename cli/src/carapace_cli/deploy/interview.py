"""Questions with flag fallbacks for ``carapace deploy`` and ``destroy``.

Every question has a flag. A value from its flag is validated and used
without asking. Otherwise the question is asked, but only when the
interview is interactive. A non-interactive interview (``--non-interactive``,
or stdin not a terminal) takes the default when there is one and raises
:class:`MissingInputError` naming the flag when there is not, so a script
never hangs waiting for input.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TextIO

from carapace_cli.errors import CarapaceError

MAX_ATTEMPTS = 3
YES_ANSWERS = frozenset({"y", "yes"})
NO_ANSWERS = frozenset({"n", "no", ""})

Validator = Callable[[str], str]


class MissingInputError(CarapaceError):
    """A required value has no flag and the interview cannot ask for it."""


class InvalidInputError(CarapaceError):
    """A value failed validation."""


def _identity(value: str) -> str:
    return value


@dataclass
class Interview:
    """Asks questions on ``stream_out`` and reads answers from ``stream_in``."""

    interactive: bool
    assume_yes: bool = False
    stream_in: TextIO | None = None
    stream_out: TextIO | None = None

    @classmethod
    def from_args(cls, *, non_interactive: bool, assume_yes: bool) -> Interview:
        return cls(
            interactive=not non_interactive and sys.stdin.isatty(),
            assume_yes=assume_yes,
        )

    @property
    def _in(self) -> TextIO:
        return self.stream_in or sys.stdin

    @property
    def _out(self) -> TextIO:
        return self.stream_out or sys.stderr

    def say(self, message: str) -> None:
        print(message, file=self._out)

    def _read_line(self, prompt: str) -> str:
        self._out.write(prompt)
        self._out.flush()
        line = self._in.readline()
        if not line:
            raise MissingInputError("input ended before the question was answered")
        return line.strip()

    @staticmethod
    def _checked(flag: str, value: str, validate: Validator) -> str:
        try:
            return validate(value)
        except InvalidInputError as exc:
            raise InvalidInputError(f"{flag}: {exc}") from None

    def ask(
        self,
        question: str,
        *,
        flag: str,
        value: str | None,
        default: str | None = None,
        validate: Validator = _identity,
    ) -> str:
        """The flag's value, else an answer, else ``default``.

        Raises:
            InvalidInputError: The flag's value, or every answer, is invalid.
            MissingInputError: Non-interactive, no flag and no default.
        """
        if value is not None:
            return self._checked(flag, value, validate)
        if not self.interactive:
            if default is None:
                raise MissingInputError(f"{flag} is required in non-interactive mode")
            return self._checked(flag, default, validate)
        suffix = f" [{default}]" if default else ""
        for _ in range(MAX_ATTEMPTS):
            answer = self._read_line(f"{question}{suffix}: ") or (default or "")
            try:
                return validate(answer)
            except InvalidInputError as exc:
                self.say(f"  {exc}")
        raise InvalidInputError(f"no valid answer for {flag}")

    def choose(
        self,
        question: str,
        *,
        flag: str,
        value: str | None,
        options: Sequence[tuple[str, str]],
        default: str | None = None,
        validate: Validator = _identity,
    ) -> str:
        """Like :meth:`ask`, but lists ``(value, label)`` options by number.

        The answer may be the option's number or any value ``validate``
        accepts, so an unlisted value can still be typed.
        """
        if value is not None or not self.interactive or not options:
            return self.ask(
                question, flag=flag, value=value, default=default, validate=validate
            )
        self.say(question)
        for number, (option, label) in enumerate(options, start=1):
            marker = " (default)" if option == default else ""
            self.say(f"  {number:>2}. {option}  {label}{marker}".rstrip())

        def by_number(answer: str) -> str:
            if answer.isdigit():
                index = int(answer) - 1
                if not 0 <= index < len(options):
                    raise InvalidInputError(f"pick 1-{len(options)}")
                return validate(options[index][0])
            return validate(answer)

        return self.ask(
            "Number or value",
            flag=flag,
            value=None,
            default=default,
            validate=by_number,
        )

    def confirm(self, question: str, *, flag: str = "--yes") -> bool:
        """True on ``--yes`` or an explicit yes. Never defaults to yes.

        Raises:
            MissingInputError: Non-interactive without ``--yes``.
        """
        if self.assume_yes:
            return True
        if not self.interactive:
            raise MissingInputError(f"pass {flag} to confirm in non-interactive mode")
        answer = self._read_line(f"{question} [y/N]: ").lower()
        return answer in YES_ANSWERS

    def confirm_typed(
        self, question: str, *, expected: str, flag: str, value: str | None
    ) -> bool:
        """True only if ``expected`` is typed back, or passed as ``flag``.

        For irreversible actions: ``--yes`` alone is never enough.
        """
        if value is not None:
            return value == expected
        if not self.interactive:
            raise MissingInputError(
                f"pass {flag} {expected} to confirm in non-interactive mode"
            )
        return self._read_line(f"{question}: ") == expected
