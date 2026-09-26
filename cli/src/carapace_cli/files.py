"""Private local files: config directory, atomic 0600 writes, safe reads.

Everything the CLI stores (owner key, session tokens, enclave pin) lives in
one directory, by default ``$XDG_CONFIG_HOME/carapace`` (``~/.config/carapace``),
overridable with ``CARAPACE_CONFIG_DIR``. The directory is created 0700 and
files are written 0600 via a temporary file in the same directory, fsync and
rename, so a crash never leaves a half-written key. Reads refuse files that
group or others can access, as ssh does.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from carapace_cli.errors import StorageError

CONFIG_DIR_ENV = "CARAPACE_CONFIG_DIR"
APP_DIR_NAME = "carapace"
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
# Largest file the CLI ever reads back; its own files are a few KiB.
MAX_FILE_BYTES = 1024 * 1024
_GROUP_OTHER_BITS = stat.S_IRWXG | stat.S_IRWXO


def default_config_dir() -> Path:
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / APP_DIR_NAME


def ensure_private_dir(directory: Path) -> Path:
    """Create ``directory`` 0700 if needed; refuse one others can access."""
    directory.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
    mode = directory.stat().st_mode
    if mode & _GROUP_OTHER_BITS:
        raise StorageError(
            f"{directory} is accessible by other users; run: chmod 700 {directory}"
        )
    return directory


def write_private(path: Path, data: bytes | bytearray) -> None:
    """Atomically replace ``path`` with ``data``, mode 0600."""
    directory = ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.")
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise
    _fsync_dir(directory)


def read_private(path: Path) -> bytes:
    """Read a file that must be private to the current user.

    Raises:
        StorageError: Missing, not a regular file, too large, or readable
            by group/others.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise StorageError(f"{path} does not exist") from None
    except OSError as exc:
        raise StorageError(f"cannot open {path}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise StorageError(f"{path} is not a regular file")
        if info.st_mode & _GROUP_OTHER_BITS:
            raise StorageError(
                f"{path} is accessible by other users; run: chmod 600 {path}"
            )
        if info.st_uid != os.getuid():
            raise StorageError(f"{path} is owned by another user")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise StorageError(f"{path} is too large")
    return data


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    write_private(path, json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def read_private_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_private(path))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise StorageError(f"{path} is not valid JSON") from None
    if not isinstance(value, dict):
        raise StorageError(f"{path} must hold a JSON object")
    return value


FileIdentity = tuple[int, int]


def regular_file_identity(path: Path) -> FileIdentity | None:
    """``(device, inode)`` of ``path`` if it is a regular file, not a link.

    None for anything else, including a symlink (never followed).

    Raises:
        FileNotFoundError: Nothing is at ``path``.
    """
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def remove_private(path: Path, *, identity: FileIdentity) -> None:
    """Unlink ``path`` only if it is still the regular file ``identity``.

    Raises:
        StorageError: ``path`` was replaced (by a symlink or another file)
            since ``identity`` was taken.
    """
    try:
        current = regular_file_identity(path)
    except FileNotFoundError:
        return
    if current != identity:
        raise StorageError(f"{path} changed while it was being removed; kept it")
    path.unlink()
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:
        pass  # Some filesystems cannot fsync directories; the rename stands.
    finally:
        os.close(fd)
