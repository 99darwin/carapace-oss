"""Tests for the per-boot monotonic cache."""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

import pytest

from carapace_crypto import freshness
from carapace_crypto.freshness import MonotonicCache, StaleError

OWNER = b"\x01" * 16
OTHER = b"\x02" * 16
THIRD = b"\x03" * 16


class TestMonotonic:
    def test_increasing_and_equal_values_are_accepted(self) -> None:
        cache = MonotonicCache()
        cache.observe(OWNER, "grant", "k", 1)
        cache.observe(OWNER, "grant", "k", 5)
        cache.observe(OWNER, "grant", "k", 5)

    def test_lower_value_is_stale(self) -> None:
        cache = MonotonicCache()
        cache.observe(OWNER, "grant", "k", 5)
        with pytest.raises(StaleError):
            cache.observe(OWNER, "grant", "k", 4)

    def test_namespaces_keys_and_owners_are_independent(self) -> None:
        cache = MonotonicCache()
        cache.observe(OWNER, "grant", "k", 5)
        cache.observe(OWNER, "envelope", "k", 1)
        cache.observe(OWNER, "grant", "j", 1)
        cache.observe(OTHER, "grant", "k", 1)
        assert len(cache) == 4


class TestTenantIsolation:
    def test_another_owner_cannot_plant_a_value_under_my_secret_id(self) -> None:
        cache = MonotonicCache()
        cache.observe(OTHER, "envelope", "s", 2**53 - 1)
        cache.observe(OWNER, "envelope", "s", 7)

    def test_another_owner_cannot_evict_my_entries(self) -> None:
        cache = MonotonicCache(max_entries_per_owner=2)
        cache.observe(OWNER, "envelope", "s", 4)
        for i in range(100):
            cache.observe(OTHER, "envelope", f"flood-{i}", 1)
        with pytest.raises(StaleError):
            cache.observe(OWNER, "envelope", "s", 3)


class TestEviction:
    def test_least_recently_used_entry_within_owner_is_evicted(self) -> None:
        cache = MonotonicCache(max_entries_per_owner=2)
        cache.observe(OWNER, "n", "a", 5)
        cache.observe(OWNER, "n", "b", 5)
        cache.observe(OWNER, "n", "a", 5)  # refresh "a"; "b" is now oldest
        cache.observe(OWNER, "n", "c", 5)  # evicts "b"
        assert len(cache) == 2
        cache.observe(OWNER, "n", "b", 1)  # forgotten, so accepted; evicts "a"
        with pytest.raises(StaleError):
            cache.observe(OWNER, "n", "c", 1)

    def test_least_recently_used_owner_is_evicted(self) -> None:
        cache = MonotonicCache(max_owners=2)
        cache.observe(OTHER, "n", "a", 5)
        cache.observe(OWNER, "n", "a", 5)
        cache.observe(THIRD, "n", "a", 5)  # evicts OTHER
        cache.observe(OTHER, "n", "a", 1)  # forgotten, so accepted; evicts OWNER
        with pytest.raises(StaleError):
            cache.observe(THIRD, "n", "a", 1)

    @pytest.mark.parametrize(
        "bounds", [{"max_owners": 0}, {"max_entries_per_owner": 0}]
    )
    def test_rejects_non_positive_bounds(self, bounds: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            MonotonicCache(**bounds)


class TestConcurrency:
    def test_interleaved_observers_cannot_lower_a_recorded_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force the classic lost update: the "low" observer reads the slot,
        # pauses, and the "high" observer writes 10 in the meantime. Without
        # the lock "low" then overwrites 10 with 5 and a rollback to 9 passes.
        low_has_read = threading.Event()
        high_done = threading.Event()

        class PausingDict(OrderedDict):  # type: ignore[type-arg]
            def get(self, key: Any, default: Any = None) -> Any:
                result = super().get(key, default)
                if isinstance(key, tuple) and threading.current_thread().name == "low":
                    low_has_read.set()
                    high_done.wait(timeout=0.5)
                return result

        monkeypatch.setattr(freshness, "OrderedDict", PausingDict)
        cache = MonotonicCache()

        def observe_high() -> None:
            cache.observe(OWNER, "envelope", "s", 10)
            high_done.set()

        low = threading.Thread(
            target=cache.observe, args=(OWNER, "envelope", "s", 5), name="low"
        )
        high = threading.Thread(target=observe_high, name="high")
        low.start()
        assert low_has_read.wait(timeout=5)
        high.start()
        low.join(timeout=5)
        high.join(timeout=5)
        with pytest.raises(StaleError):
            cache.observe(OWNER, "envelope", "s", 9)


class TestValueType:
    @pytest.mark.parametrize("value", [float("nan"), 1.5, True, "5", None])
    def test_non_int_values_are_refused(self, value: Any) -> None:
        cache = MonotonicCache()
        with pytest.raises(TypeError):
            cache.observe(OWNER, "grant", "k", value)
        assert len(cache) == 0
