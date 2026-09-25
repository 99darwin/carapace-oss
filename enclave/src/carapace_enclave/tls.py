"""A server TLS context from in-memory PEM, without touching disk.

``ssl.SSLContext.load_cert_chain`` only takes paths. The key and certificate
go through anonymous pipes instead, read back via ``/dev/fd/N``, so the key
exists only in process and kernel memory. The key PEM copy is wiped
afterwards; OpenSSL keeps its own parsed copy for the life of the context.
"""

from __future__ import annotations

import os
import ssl

from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.secure_memory import secure_zero

# A pipe holds at least 4 KiB before a write blocks (64 KiB on Linux); an
# EC key plus one certificate is far below that, and the write must never
# block because nothing reads until it completes.
MAX_PIPE_PAYLOAD = 4096


class TlsSetupError(Exception):
    """The boot key could not be loaded into a TLS context."""


def server_ssl_context(identity: BootIdentity) -> ssl.SSLContext:
    """TLS 1.2+ server context for the boot's TLS key and certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    key_pem = identity.tls_key_pem()
    cert_pem = bytearray(identity.tls_cert_pem.encode("ascii"))
    # OpenSSL reads the certificate and the key in two passes, so each
    # needs its own pipe; a pipe can be read only once.
    cert_fd = key_fd = None
    try:
        cert_fd = _filled_pipe(cert_pem)
        key_fd = _filled_pipe(key_pem)
        context.load_cert_chain(f"/dev/fd/{cert_fd}", f"/dev/fd/{key_fd}")
    except (ssl.SSLError, OSError) as exc:
        raise TlsSetupError(f"TLS key load failed: {type(exc).__name__}") from None
    finally:
        secure_zero(key_pem)
        for fd in (cert_fd, key_fd):
            if fd is not None:
                os.close(fd)
    return context


def _filled_pipe(data: bytearray) -> int:
    """A pipe's read end, already holding all of ``data`` and then EOF."""
    if len(data) > MAX_PIPE_PAYLOAD:
        raise TlsSetupError("TLS key or certificate too large for a pipe")
    read_fd, write_fd = os.pipe()
    try:
        with memoryview(data) as view:
            written = 0
            while written < len(view):
                written += os.write(write_fd, view[written:])
    except OSError:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    return read_fd
