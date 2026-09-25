"""Injection policy v1: what a secret may be used for.

The policy is stored in cleartext next to the sealed secret and bound into the
envelope AAD, so the enclave can trust it once the envelope opens. Validation
here is strict: a policy either means exactly one thing or is rejected.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from carapace_enclave.egress.hostname import HostnameError, normalize_hostname

SECRET_PLACEHOLDER = "{secret}"  # noqa: S105 - a template marker
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_TIMEOUT_S = 120

# RFC 9110 token characters for header and parameter names.
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_QUERY_NAME = re.compile(r"^[A-Za-z0-9._~-]+$")
# Visible ASCII plus space/tab; no CR, LF, NUL or other controls.
_HEADER_VALUE = re.compile(r"^[\t\x20-\x7e]*$")

# Headers the injector may never target: framing, routing and hop-by-hop.
FORBIDDEN_INJECTION_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "accept-encoding",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    }
)


def is_token(name: str) -> bool:
    """True if ``name`` is a valid RFC 9110 token (header field name)."""
    return bool(_TOKEN.match(name))


Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
Port = Annotated[int, Field(ge=1, le=65535)]

_STRICT = ConfigDict(extra="forbid", strict=True, frozen=True)


class HostRule(BaseModel):
    """``exact`` matches one hostname; ``suffix`` matches strict subdomains.

    A suffix rule ``.github.com`` matches ``api.github.com`` but neither
    ``github.com`` (add an exact rule for the apex) nor ``evilgithub.com``.
    """

    model_config = _STRICT

    match: Literal["exact", "suffix"]
    value: str

    @model_validator(mode="after")
    def _check_value(self) -> Self:
        if "*" in self.value:
            raise ValueError("wildcards are not supported")
        host = self.value
        if self.match == "suffix":
            if not host.startswith("."):
                raise ValueError("suffix rules must start with '.'")
            host = host[1:]
            if host.count(".") < 1:
                raise ValueError("suffix rules need at least two labels")
        try:
            normalized = normalize_hostname(host)
        except HostnameError as exc:
            raise ValueError(str(exc)) from exc
        if normalized != host:
            raise ValueError(f"host must be written in normalized form: {normalized}")
        return self

    def matches(self, hostname: str) -> bool:
        """``hostname`` must already be normalized."""
        if self.match == "exact":
            return hostname == self.value
        return hostname.endswith(self.value) and len(hostname) > len(self.value)


class Injection(BaseModel):
    """Where the secret goes.

    - ``header``: header ``name`` set to ``template`` with ``{secret}`` filled.
    - ``query``: query parameter ``name`` set to the filled ``template``.
    - ``basic_auth``: ``Authorization: Basic base64(template)``; the template
      is ``user:password`` with ``{secret}`` in either part.
    """

    model_config = _STRICT

    kind: Literal["header", "query", "basic_auth"]
    name: str | None = None
    template: str = Field(max_length=1024)

    @field_validator("template")
    @classmethod
    def _check_template(cls, template: str) -> str:
        if template.count(SECRET_PLACEHOLDER) != 1:
            raise ValueError("template must contain {secret} exactly once")
        if not _HEADER_VALUE.match(template):
            raise ValueError("template contains forbidden characters")
        return template

    @model_validator(mode="after")
    def _check_name(self) -> Self:
        if self.kind == "basic_auth":
            if self.name is not None:
                raise ValueError("basic_auth takes no name")
            if ":" not in self.template:
                raise ValueError("basic_auth template must be user:password")
            return self
        if not self.name:
            raise ValueError(f"{self.kind} injection requires a name")
        if self.kind == "header":
            if not is_token(self.name):
                raise ValueError("invalid header name")
            lowered = self.name.lower()
            if lowered in FORBIDDEN_INJECTION_HEADERS or lowered.startswith("proxy-"):
                raise ValueError(f"header {self.name!r} cannot be an injection target")
        elif not _QUERY_NAME.match(self.name):
            raise ValueError("invalid query parameter name")
        return self

    @property
    def header_name(self) -> str | None:
        """Lowercased header this injection sets, if any."""
        if self.kind == "header":
            return (self.name or "").lower()
        if self.kind == "basic_auth":
            return "authorization"
        return None


class Limits(BaseModel):
    model_config = _STRICT

    req_bytes: int = Field(default=1024 * 1024, ge=0, le=MAX_BODY_BYTES)
    resp_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=MAX_RESPONSE_BYTES)
    rpm: int = Field(default=60, ge=1, le=10_000)
    timeout_s: int = Field(default=30, ge=1, le=MAX_TIMEOUT_S)


class InjectionPolicy(BaseModel):
    model_config = _STRICT

    v: Literal[1]
    hosts: list[HostRule] = Field(min_length=1, max_length=32)
    schemes: list[Literal["https"]] = Field(default=["https"], min_length=1)
    methods: list[Method] = Field(min_length=1)
    ports: list[Port] = Field(default=[443], min_length=1, max_length=16)
    inject: Injection
    limits: Limits = Field(default_factory=Limits)

    @field_validator("v", mode="before")
    @classmethod
    def _reject_bool_version(cls, v: object) -> object:
        # bool is an int subclass; ``True`` must not pass as version 1.
        if isinstance(v, bool):
            raise ValueError("v must be the integer 1")
        return v

    def allows_host(self, hostname: str) -> bool:
        return any(rule.matches(hostname) for rule in self.hosts)
