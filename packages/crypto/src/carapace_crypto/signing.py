"""Ed25519 signing and verification.

Provides key generation, signing, and verification using Ed25519.
Used for signing action receipts to create tamper-evident audit trails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Type aliases for clarity
PublicKey = bytes
Signature = bytes


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Ed25519 key pair for signing receipts.

    The private key is used to sign messages inside the enclave.
    The public key can be shared for verification.

    Example:
        >>> keypair = KeyPair.generate()
        >>> signature = keypair.sign(b"hello world")
        >>> KeyPair.verify(keypair.public_key_bytes, signature, b"hello world")
        True
    """

    _private_key: Ed25519PrivateKey  # gitleaks:allow (type annotation)
    _public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> Self:
        """Generate a new Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(_private_key=private_key, _public_key=public_key)

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> Self:
        """Reconstruct key pair from private key bytes.

        Args:
            private_bytes: 32-byte Ed25519 private key seed.

        Returns:
            KeyPair with the reconstructed keys.

        Raises:
            ValueError: If the bytes are invalid.
        """
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        # Try loading as raw seed first (32 bytes)
        if len(private_bytes) == 32:
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            # Try loading as DER format
            private_key = load_der_private_key(private_bytes, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Invalid key type")

        return cls(_private_key=private_key, _public_key=private_key.public_key())

    @property
    def public_key_bytes(self) -> PublicKey:
        """Get the public key as raw bytes (32 bytes)."""
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def private_key_bytes(self) -> bytes:
        """Get the private key seed as raw bytes (32 bytes).

        SECURITY: Handle with care. This should only be used for
        secure storage/transmission, never logged or exposed.
        """
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def sign(self, message: bytes) -> Signature:
        """Sign a message with the private key.

        Args:
            message: The message to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        return self._private_key.sign(message)

    @staticmethod
    def verify(public_key: PublicKey, signature: Signature, message: bytes) -> bool:
        """Verify a signature against a public key.

        This is a static method so verification can happen without
        the private key (e.g., by a client checking a receipt).

        Args:
            public_key: 32-byte Ed25519 public key.
            signature: 64-byte signature to verify.
            message: The original message that was signed.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def __repr__(self) -> str:
        """Safe repr that doesn't expose private key."""
        pub_hex = self.public_key_bytes.hex()[:16]
        return f"KeyPair(public_key={pub_hex}...)"
