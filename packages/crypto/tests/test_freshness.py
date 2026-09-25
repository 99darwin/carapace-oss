"""Tests for the per-boot monotonic cache."""

from __future__ import annotations

import pytest

from carapace_crypto.freshness import MonotonicCache, StaleError


def test_increasing_and_equal_values_are_accepted() -> None:
    cache = MonotonicCache()
    cache.observe("grant", "key-1", 10)
    cache.observe("grant", "key-1", 10)
    cache.observe("grant", "key-1", 11)
    assert len(cache) == 1


def test_lower_value_is_stale() -> None:
    cache = MonotonicCache()
    cache.observe("envelope", "secret-1", 5)
    with pytest.raises(StaleError):
        cache.observe("envelope", "secret-1", 4)
    # The maximum is kept after a rejected observation.
    cache.observe("envelope", "secret-1", 5)


def test_namespaces_and_keys_are_independent() -> None:
    cache = MonotonicCache()
    cache.observe("grant", "k", 100)
    cache.observe("envelope", "k", 1)
    cache.observe("grant", "other", 1)
    assert len(cache) == 3


def test_eviction_is_least_recently_used() -> None:
    cache = MonotonicCache(max_entries=2)
    cache.observe("n", "a", 5)
    cache.observe("n", "b", 5)
    cache.observe("n", "a", 5)  # refresh a
    cache.observe("n", "c", 5)  # evicts b
    assert len(cache) == 2
    with pytest.raises(StaleError):
        cache.observe("n", "a", 4)  # a survived
    cache.observe("n", "b", 1)  # b forgotten, so not stale


def test_rejects_non_positive_capacity() -> None:
    with pytest.raises(ValueError):
        MonotonicCache(max_entries=0)
