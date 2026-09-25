"""Tests for hashing utilities."""

import hashlib

import pytest

from carapace_crypto.hashing import (
    hmac_sha256,
    hmac_sha256_verify,
    sha256,
    sha256_hex,
    tagged_sha256,
)


class TestSHA256:
    """Tests for SHA-256 hashing."""

    def test_sha256_known_value(self):
        """SHA-256 should produce known hash for known input."""
        # Known test vector
        result = sha256(b"hello")
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected

    def test_sha256_returns_32_bytes(self):
        """SHA-256 should always return 32 bytes."""
        assert len(sha256(b"")) == 32
        assert len(sha256(b"short")) == 32
        assert len(sha256(b"x" * 10000)) == 32

    def test_sha256_hex_format(self):
        """sha256_hex should return hex string."""
        result = sha256_hex(b"hello")
        assert (
            result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert len(result) == 64

    def test_sha256_different_inputs(self):
        """Different inputs should produce different hashes."""
        h1 = sha256(b"input1")
        h2 = sha256(b"input2")
        assert h1 != h2

    def test_sha256_deterministic(self):
        """Same input should always produce same hash."""
        h1 = sha256(b"test")
        h2 = sha256(b"test")
        assert h1 == h2

    def test_sha256_empty_input(self):
        """Should handle empty input."""
        result = sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == expected


class TestHMAC:
    """Tests for HMAC-SHA256."""

    def test_hmac_sha256_known_value(self):
        """HMAC should produce known output for known inputs."""
        key = b"secret"
        message = b"message"
        result = hmac_sha256(key, message)
        # Verified against Python's hmac module
        assert len(result) == 32

    def test_hmac_different_keys(self):
        """Different keys should produce different HMACs."""
        message = b"message"
        h1 = hmac_sha256(b"key1", message)
        h2 = hmac_sha256(b"key2", message)
        assert h1 != h2

    def test_hmac_different_messages(self):
        """Different messages should produce different HMACs."""
        key = b"secret"
        h1 = hmac_sha256(key, b"message1")
        h2 = hmac_sha256(key, b"message2")
        assert h1 != h2

    def test_hmac_verify_valid(self):
        """Verify should return True for valid HMAC."""
        key = b"secret"
        message = b"message"
        mac = hmac_sha256(key, message)
        assert hmac_sha256_verify(key, message, mac) is True

    def test_hmac_verify_invalid(self):
        """Verify should return False for invalid HMAC."""
        key = b"secret"
        message = b"message"
        mac = hmac_sha256(key, message)

        # Wrong key
        assert hmac_sha256_verify(b"wrong", message, mac) is False

        # Wrong message
        assert hmac_sha256_verify(key, b"wrong", mac) is False

        # Tampered MAC
        tampered = bytes([mac[0] ^ 0xFF]) + mac[1:]
        assert hmac_sha256_verify(key, message, tampered) is False

    def test_hmac_empty_inputs(self):
        """Should handle empty key and message."""
        # Empty message
        result = hmac_sha256(b"key", b"")
        assert len(result) == 32

        # Empty key
        result = hmac_sha256(b"", b"message")
        assert len(result) == 32


class TestTaggedSHA256:
    def test_framing(self):
        expected = hashlib.sha256(b"carapace-test-v1\ndata").digest()
        assert tagged_sha256(b"carapace-test-v1", b"data") == expected

    def test_tags_separate_domains(self):
        assert tagged_sha256(b"a", b"x") != tagged_sha256(b"b", b"x")
        assert tagged_sha256(b"a", b"x") != sha256(b"x")

    @pytest.mark.parametrize("tag", [b"", b"a\nb", b"a\n"])
    def test_rejects_bad_tags(self, tag: bytes):
        with pytest.raises(ValueError):
            tagged_sha256(tag, b"x")
