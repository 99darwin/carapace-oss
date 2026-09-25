"""Tests for the injection policy model and hostname normalization."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from carapace_enclave.egress.hostname import HostnameError, normalize_hostname
from carapace_enclave.egress.policy import HostRule, Injection

from .conftest import make_policy


class TestNormalizeHostname:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("api.github.com", "api.github.com"),
            ("API.GitHub.COM", "api.github.com"),
            ("api.github.com.", "api.github.com"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("BÜCHER.example", "xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert normalize_hostname(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            ".",
            "a..b",
            "api.github.com..",
            "-bad.example",
            "bad-.example",
            "under_score.example",
            "a" * 64 + ".example",
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "xn--zz.example",
            "exa mple.com",
        ],
    )
    def test_rejects(self, raw: str) -> None:
        with pytest.raises(HostnameError):
            normalize_hostname(raw)


class TestHostRule:
    def test_suffix_matching_is_label_aligned(self) -> None:
        rule = HostRule(match="suffix", value=".github.com")
        assert rule.matches("api.github.com")
        assert rule.matches("a.b.github.com")
        assert not rule.matches("github.com")
        assert not rule.matches("evilgithub.com")
        assert not rule.matches("api.github.com.evil.test")

    def test_exact_matching(self) -> None:
        rule = HostRule(match="exact", value="api.github.com")
        assert rule.matches("api.github.com")
        assert not rule.matches("x.api.github.com")

    @pytest.mark.parametrize(
        ("match", "value"),
        [
            ("suffix", "github.com"),  # missing leading dot
            ("suffix", ".com"),  # single label: effectively wildcard-all
            ("suffix", "."),
            ("exact", "*"),
            ("suffix", ".*.github.com"),
            ("exact", "API.github.com"),  # must be normalized
            ("exact", "api.github.com."),
            ("exact", "bücher.example"),  # must be the A-label
            ("exact", "10.0.0.1"),
            ("exact", ""),
            ("regex", "api.github.com"),
        ],
    )
    def test_rejects(self, match: str, value: str) -> None:
        with pytest.raises(ValidationError):
            HostRule.model_validate({"match": match, "value": value})


class TestInjection:
    @pytest.mark.parametrize(
        "data",
        [
            {"kind": "header", "name": "Authorization", "template": "Bearer {secret}"},
            {"kind": "header", "name": "X-Api-Key", "template": "{secret}"},
            {"kind": "query", "name": "api_key", "template": "{secret}"},
            {"kind": "basic_auth", "template": "user:{secret}"},
            {"kind": "basic_auth", "template": "{secret}:x"},
        ],
    )
    def test_accepts(self, data: dict[str, Any]) -> None:
        Injection.model_validate(data)

    @pytest.mark.parametrize(
        "data",
        [
            {"kind": "header", "name": "Host", "template": "{secret}"},
            {"kind": "header", "name": "host", "template": "{secret}"},
            {"kind": "header", "name": "Proxy-Authorization", "template": "{secret}"},
            {"kind": "header", "name": "Content-Length", "template": "{secret}"},
            {"kind": "header", "name": "Transfer-Encoding", "template": "{secret}"},
            {"kind": "header", "name": "Bad Name", "template": "{secret}"},
            {"kind": "header", "name": "X:Y", "template": "{secret}"},
            {"kind": "header", "template": "{secret}"},
            {"kind": "header", "name": "X-Key", "template": "no placeholder"},
            {"kind": "header", "name": "X-Key", "template": "{secret}{secret}"},
            {"kind": "header", "name": "X-Key", "template": "{secret}\r\nX-Evil: 1"},
            {"kind": "query", "name": "a&b", "template": "{secret}"},
            {"kind": "query", "template": "{secret}"},
            {"kind": "basic_auth", "name": "Authorization", "template": "u:{secret}"},
            {"kind": "basic_auth", "template": "{secret}"},
            {"kind": "cookie", "name": "sid", "template": "{secret}"},
        ],
    )
    def test_rejects(self, data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            Injection.model_validate(data)


class TestInjectionPolicy:
    def test_valid_policy(self) -> None:
        policy = make_policy()
        assert policy.allows_host("api.github.com")
        assert policy.allows_host("x.example.com")
        assert not policy.allows_host("example.com")

    def test_defaults(self) -> None:
        policy = make_policy(schemes=["https"], ports=[443])
        assert policy.limits.timeout_s == 5

    @pytest.mark.parametrize(
        "overrides",
        [
            {"v": 2},
            {"v": True},
            {"v": "1"},
            {"hosts": []},
            {"schemes": ["http"]},
            {"schemes": []},
            {"methods": ["get"]},
            {"methods": ["CONNECT"]},
            {"methods": ["TRACE"]},
            {"methods": []},
            {"ports": [0]},
            {"ports": [65536]},
            {"ports": ["443"]},
            {"limits": {"timeout_s": 1.5}},
            {"limits": {"resp_bytes": 10**9}},
            {"limits": {"timeout_s": 3600}},
            {"unknown": 1},
        ],
    )
    def test_rejects(self, overrides: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            make_policy(**overrides)

    def test_policy_is_immutable(self) -> None:
        policy = make_policy()
        with pytest.raises(ValidationError):
            policy.methods = ["DELETE"]  # type: ignore[misc]
