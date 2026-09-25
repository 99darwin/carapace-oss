"""Local state: 0600 atomic files, the owner key store, URLs, redaction."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from carapace_cli.errors import CarapaceError, OwnerKeyError, StorageError
from carapace_cli.files import read_private, write_private
from carapace_cli.ownerkey_store import (
    is_passphrase_protected,
    load_owner_key,
    save_owner_key,
)
from carapace_cli.session import Session
from carapace_cli.urls import normalize_base_url
from carapace_crypto import OwnerKey, b64_encode_std

FAST_SCRYPT_N = 2**10
PASSPHRASE = "a long enough passphrase"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# -- files -------------------------------------------------------------------------


def test_write_private_is_0600_in_a_0700_dir(tmp_path) -> None:
    path = tmp_path / "config" / "file"
    write_private(path, b"data")
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700
    assert read_private(path) == b"data"


def test_write_private_replaces_atomically(tmp_path) -> None:
    directory = tmp_path / "config"
    path = directory / "file"
    write_private(path, b"one")
    write_private(path, b"two")
    assert read_private(path) == b"two"
    assert [p.name for p in directory.iterdir()] == ["file"]


def test_write_private_leaves_no_temp_file_on_failure(tmp_path) -> None:
    directory = tmp_path / "config"
    with pytest.raises(TypeError):
        write_private(directory / "file", "not bytes")  # type: ignore[arg-type]
    assert list(directory.iterdir()) == []


def test_read_private_refuses_group_readable_file(tmp_path) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"data")
    path.chmod(0o644)
    with pytest.raises(StorageError, match="chmod 600"):
        read_private(path)


def test_read_private_refuses_symlink(tmp_path) -> None:
    target = tmp_path / "target"
    write_private(target, b"data")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(StorageError):
        read_private(link)


def test_shared_config_dir_is_refused(tmp_path) -> None:
    directory = tmp_path / "config"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    with pytest.raises(StorageError, match="chmod 700"):
        write_private(directory / "file", b"data")


# -- owner key ---------------------------------------------------------------------


def test_owner_key_round_trip_unencrypted(tmp_path) -> None:
    key = OwnerKey.generate()
    path = tmp_path / "config" / "owner-key.json"
    save_owner_key(path, key)
    assert _mode(path) == 0o600
    assert not is_passphrase_protected(path)
    assert load_owner_key(path).public_key == key.public_key


def test_owner_key_round_trip_with_passphrase(tmp_path) -> None:
    key = OwnerKey.generate()
    path = tmp_path / "config" / "owner-key.json"
    save_owner_key(path, key, passphrase=PASSPHRASE, scrypt_n=FAST_SCRYPT_N)
    assert is_passphrase_protected(path)
    assert key.seed not in path.read_bytes()
    loaded = load_owner_key(path, passphrase=lambda: PASSPHRASE)
    assert loaded.public_key == key.public_key


def test_owner_key_wrong_passphrase_is_refused(tmp_path) -> None:
    path = tmp_path / "config" / "owner-key.json"
    save_owner_key(
        path, OwnerKey.generate(), passphrase=PASSPHRASE, scrypt_n=FAST_SCRYPT_N
    )
    with pytest.raises(OwnerKeyError) as info:
        load_owner_key(path, passphrase=lambda: "wrong passphrase!")
    assert PASSPHRASE not in str(info.value)
    with pytest.raises(OwnerKeyError, match="passphrase-protected"):
        load_owner_key(path)


def test_owner_key_is_never_overwritten(tmp_path) -> None:
    path = tmp_path / "config" / "owner-key.json"
    save_owner_key(path, OwnerKey.generate())
    with pytest.raises(OwnerKeyError, match="refusing to overwrite"):
        save_owner_key(path, OwnerKey.generate())


def test_short_passphrase_is_refused(tmp_path) -> None:
    with pytest.raises(OwnerKeyError, match="at least"):
        save_owner_key(tmp_path / "k.json", OwnerKey.generate(), passphrase="short")


def test_owner_key_with_swapped_public_key_is_refused(tmp_path) -> None:
    path = tmp_path / "config" / "owner-key.json"
    save_owner_key(path, OwnerKey.generate())
    record = json.loads(path.read_text())
    record["public_key"] = b64_encode_std(OwnerKey.generate().public_key)
    write_private(path, json.dumps(record).encode())
    with pytest.raises(OwnerKeyError, match="mismatch"):
        load_owner_key(path)


# -- URLs, policies, input -----------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "allow_http", "expected"),
    [
        ("https://carapace.example.com/", False, "https://carapace.example.com"),
        ("http://127.0.0.1:8000", True, "http://127.0.0.1:8000"),
        ("http://localhost:8000", True, "http://localhost:8000"),
    ],
)
def test_url_normalization(url, allow_http, expected) -> None:
    assert (
        normalize_base_url(url, what="server", allow_loopback_http=allow_http)
        == expected
    )


@pytest.mark.parametrize(
    ("url", "allow_http"),
    [
        ("http://carapace.example.com", True),
        ("http://127.0.0.1:8000", False),
        ("https://user:pass@carapace.example.com", False),
        ("https://carapace.example.com/?q=1", False),
        ("ftp://carapace.example.com", True),
    ],
)
def test_bad_urls_are_refused(url, allow_http) -> None:
    with pytest.raises(CarapaceError):
        normalize_base_url(url, what="server", allow_loopback_http=allow_http)


# -- redaction and permissions ---------------------------------------------------


def test_session_repr_hides_tokens() -> None:
    session = Session(
        server_url="https://s", user_id="u", access_token="AT", refresh_token="RT"
    )
    assert "AT" not in repr(session)
    assert "RT" not in repr(session)


def test_umask_does_not_widen_permissions(tmp_path) -> None:
    previous = os.umask(0)
    try:
        path = tmp_path / "config" / "file"
        write_private(path, b"data")
    finally:
        os.umask(previous)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700
