"""``python -m carapace_server``: the container entrypoint."""

import pytest

from carapace_server.__main__ import DEFAULT_PORT, PortError, listen_port


@pytest.mark.parametrize("environ", [{}, {"PORT": ""}])
def test_default_port_when_unset(environ: dict[str, str]) -> None:
    assert listen_port(environ) == DEFAULT_PORT


@pytest.mark.parametrize(("raw", "port"), [("8080", 8080), ("1", 1), ("65535", 65535)])
def test_port_from_environment(raw: str, port: int) -> None:
    assert listen_port({"PORT": raw}) == port


@pytest.mark.parametrize(
    "raw", ["0", "65536", "99999", "-1", "80a", " 8080", "8080 ", "٨٠٨٠", "0x50"]
)
def test_invalid_port_is_refused(raw: str) -> None:
    with pytest.raises(PortError):
        listen_port({"PORT": raw})
