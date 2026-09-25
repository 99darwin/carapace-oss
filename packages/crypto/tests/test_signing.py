"""Tests for Ed25519 signing."""

from carapace_crypto.signing import KeyPair


class TestKeyPair:
    """Tests for KeyPair class."""

    def test_generate_creates_valid_keypair(self):
        """Generate should create a valid keypair."""
        keypair = KeyPair.generate()
        assert keypair.public_key_bytes is not None
        assert len(keypair.public_key_bytes) == 32

    def test_sign_produces_valid_signature(self):
        """Sign should produce a valid 64-byte signature."""
        keypair = KeyPair.generate()
        message = b"test message"

        signature = keypair.sign(message)

        assert len(signature) == 64
        assert KeyPair.verify(keypair.public_key_bytes, signature, message)

    def test_verify_valid_signature(self):
        """Verify should return True for valid signatures."""
        keypair = KeyPair.generate()
        message = b"hello world"
        signature = keypair.sign(message)

        assert KeyPair.verify(keypair.public_key_bytes, signature, message) is True

    def test_verify_invalid_signature(self):
        """Verify should return False for invalid signatures."""
        keypair = KeyPair.generate()
        message = b"hello world"
        signature = keypair.sign(message)

        # Wrong message
        assert KeyPair.verify(keypair.public_key_bytes, signature, b"wrong") is False

        # Tampered signature
        tampered = bytes([signature[0] ^ 0xFF]) + signature[1:]
        assert KeyPair.verify(keypair.public_key_bytes, tampered, message) is False

    def test_verify_wrong_public_key(self):
        """Verify should return False for wrong public key."""
        keypair1 = KeyPair.generate()
        keypair2 = KeyPair.generate()
        message = b"hello"
        signature = keypair1.sign(message)

        assert KeyPair.verify(keypair2.public_key_bytes, signature, message) is False

    def test_from_private_bytes_roundtrip(self):
        """Should reconstruct keypair from private bytes."""
        original = KeyPair.generate()
        private_bytes = original.private_key_bytes

        restored = KeyPair.from_private_bytes(private_bytes)

        assert restored.public_key_bytes == original.public_key_bytes
        # Verify signing still works
        message = b"test"
        sig = restored.sign(message)
        assert KeyPair.verify(restored.public_key_bytes, sig, message)

    def test_different_keypairs_have_different_keys(self):
        """Each generated keypair should be unique."""
        keypair1 = KeyPair.generate()
        keypair2 = KeyPair.generate()

        assert keypair1.public_key_bytes != keypair2.public_key_bytes

    def test_repr_does_not_expose_private_key(self):
        """Repr should not expose the private key."""
        keypair = KeyPair.generate()
        repr_str = repr(keypair)

        # Should contain truncated public key
        assert "public_key=" in repr_str
        assert "..." in repr_str
        # Should NOT contain full private key bytes
        private_hex = keypair.private_key_bytes.hex()
        assert private_hex not in repr_str

    def test_sign_empty_message(self):
        """Should handle empty messages."""
        keypair = KeyPair.generate()
        message = b""

        signature = keypair.sign(message)
        assert KeyPair.verify(keypair.public_key_bytes, signature, message)

    def test_sign_large_message(self):
        """Should handle large messages."""
        keypair = KeyPair.generate()
        message = b"x" * 1_000_000  # 1MB

        signature = keypair.sign(message)
        assert KeyPair.verify(keypair.public_key_bytes, signature, message)
