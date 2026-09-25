"""RateLimiter and DekCache: bounds, expiry and wiping."""

from __future__ import annotations

import pytest

from carapace_enclave import dek_cache as dek_cache_module
from carapace_enclave.dek_cache import DEK_TTL_SECONDS, DekCache
from carapace_enclave.ratelimit import RateLimiter


class FakeMonotonic:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


KEY_A = (b"pk", "a", 1, b"sig-a")
KEY_B = (b"pk", "b", 1, b"sig-b")


def test_rate_limiter_counts_per_key_and_window() -> None:
    clock = FakeMonotonic()
    limiter = RateLimiter(window=60, monotonic=clock)
    assert [limiter.acquire("a", 2) for _ in range(3)] == [True, True, False]
    assert limiter.acquire("b", 2)
    clock.now += 60
    assert limiter.acquire("a", 2)


def test_rate_limiter_refusals_do_not_consume() -> None:
    clock = FakeMonotonic()
    limiter = RateLimiter(window=10, monotonic=clock)
    assert limiter.acquire("a", 1)
    clock.now += 5
    assert not limiter.acquire("a", 1)
    clock.now += 5
    assert limiter.acquire("a", 1)


def test_rate_limiter_zero_limit_refuses() -> None:
    assert not RateLimiter().acquire("a", 0)


def test_rate_limiter_is_bounded_in_keys() -> None:
    limiter = RateLimiter(max_keys=2, monotonic=FakeMonotonic())
    assert limiter.acquire("a", 1)
    assert limiter.acquire("b", 1)
    assert limiter.acquire("c", 1)  # evicts "a", the least recently used
    assert limiter.acquire("a", 1)
    assert not limiter.acquire("c", 1)


@pytest.mark.parametrize("kwargs", [{"window": 0}, {"max_keys": 0}])
def test_rate_limiter_rejects_bad_config(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        RateLimiter(**kwargs)


def test_dek_cache_returns_copies() -> None:
    cache = DekCache()
    cache.put(KEY_A, b"k" * 32)
    first = cache.get(KEY_A)
    assert first == b"k" * 32
    assert cache.get(KEY_B) is None


def test_dek_cache_expires_and_wipes(monkeypatch: pytest.MonkeyPatch) -> None:
    wiped: list[bytearray] = []
    real = dek_cache_module.secure_zero

    def spy(buffer: bytearray) -> None:
        real(buffer)
        wiped.append(buffer)

    monkeypatch.setattr(dek_cache_module, "secure_zero", spy)
    clock = FakeMonotonic()
    cache = DekCache(monotonic=clock)
    cache.put(KEY_A, b"k" * 32)
    clock.now += DEK_TTL_SECONDS
    assert cache.get(KEY_A) is None
    assert wiped == [bytearray(32)]
    assert len(cache) == 0


def test_dek_cache_evicts_least_recent_and_wipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wiped: list[bytearray] = []
    monkeypatch.setattr(dek_cache_module, "secure_zero", wiped.append)
    cache = DekCache(max_entries=1, monotonic=FakeMonotonic())
    cache.put(KEY_A, b"a" * 32)
    cache.put(KEY_B, b"b" * 32)
    assert cache.get(KEY_A) is None
    assert cache.get(KEY_B) == b"b" * 32
    assert wiped == [bytearray(b"a" * 32)]


def test_dek_cache_replacing_wipes_old_value() -> None:
    cache = DekCache(monotonic=FakeMonotonic())
    cache.put(KEY_A, b"a" * 32)
    cache.put(KEY_A, b"b" * 32)
    assert cache.get(KEY_A) == b"b" * 32
    assert len(cache) == 1


def test_dek_cache_clear() -> None:
    cache = DekCache()
    cache.put(KEY_A, b"a" * 32)
    cache.clear()
    assert len(cache) == 0


@pytest.mark.parametrize(
    "kwargs", [{"ttl": 0}, {"ttl": DEK_TTL_SECONDS + 1}, {"max_entries": 0}]
)
def test_dek_cache_rejects_bad_config(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        DekCache(**kwargs)
