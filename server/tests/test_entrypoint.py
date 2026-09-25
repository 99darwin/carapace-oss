"""``python -m carapace_server``: the container entrypoint."""

import pytest

from carapace_server import __main__ as entrypoint
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


def test_uvicorn_proxy_header_handling_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """The app's trusted-hop middleware is the only reader of X-Forwarded-For."""
    calls: list[dict] = []
    monkeypatch.setattr(entrypoint.uvicorn, "run", lambda *a, **kw: calls.append(kw))
    monkeypatch.setenv("PORT", "9000")
    entrypoint.main()
    assert len(calls) == 1
    assert calls[0]["proxy_headers"] is False
    assert calls[0]["port"] == 9000
    assert calls[0]["server_header"] is False
