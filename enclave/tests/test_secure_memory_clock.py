"""secure_memory wiping and the attestation-floored clock."""

import pytest

from carapace_enclave.clock import TrustedClock
from carapace_enclave.secure_memory import secure_zero, wiped


def test_secure_zero_bytearray() -> None:
    buffer = bytearray(b"top-secret-value")
    secure_zero(buffer)
    assert buffer == bytearray(len(b"top-secret-value"))


def test_secure_zero_memoryview_slice_only() -> None:
    buffer = bytearray(b"keep|wipe")
    secure_zero(memoryview(buffer)[5:])
    assert buffer == b"keep|\x00\x00\x00\x00"


def test_secure_zero_leaves_buffer_resizable() -> None:
    buffer = bytearray(b"abc")
    secure_zero(buffer)
    buffer.extend(b"d")  # would raise BufferError if the export leaked
    assert buffer == b"\x00\x00\x00d"


def test_secure_zero_empty_is_noop() -> None:
    secure_zero(bytearray())


@pytest.mark.parametrize("value", [b"immutable", "text", memoryview(b"readonly")])
def test_secure_zero_refuses_immutable(value: object) -> None:
    with pytest.raises(TypeError):
        secure_zero(value)  # type: ignore[arg-type]


def test_wiped_clears_on_error() -> None:
    buffer = bytearray(b"secret")
    with pytest.raises(RuntimeError), wiped(buffer):
        raise RuntimeError("boom")
    assert buffer == bytearray(6)


def test_clock_uses_attested_floor() -> None:
    clock = TrustedClock(wall=lambda: 1_000.0)
    assert clock.now() == 1_000
    clock.observe_attested(5_000)
    assert clock.now() == 5_000


def test_clock_never_goes_back() -> None:
    wall = [2_000.0]
    clock = TrustedClock(wall=lambda: wall[0])
    assert clock.now() == 2_000
    wall[0] = 100.0  # operator sets the guest clock back
    assert clock.now() == 2_000
    clock.observe_attested(1_500)  # an older token cannot lower it either
    assert clock.now() == 2_000


def test_clock_rejects_non_int_iat() -> None:
    clock = TrustedClock()
    with pytest.raises(TypeError):
        clock.observe_attested(True)
