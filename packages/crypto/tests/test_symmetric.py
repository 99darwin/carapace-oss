"""Tests for symmetric encryption."""

import pytest
from cryptography.exceptions import InvalidTag

from carapace_crypto.symmetric import (
    KEY_SIZE,
    NONCE_SIZE,
    EncryptedData,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_key,
)


class TestGenerateKey:
    """Tests for key generation."""

    def test_key_length(self):
        """Generated key should be correct length."""
        key = generate_key()
        assert len(key) == KEY_SIZE

    def test_keys_are_unique(self):
        """Each generated key should be unique."""
        keys = [generate_key() for _ in range(100)]
        assert len(set(keys)) == 100


class TestEncryptDecrypt:
    """Tests for AES-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt correctly."""
        key = generate_key()
        plaintext = b"Hello, World!"

        encrypted = encrypt_aes_gcm(key, plaintext)
        decrypted = decrypt_aes_gcm(key, encrypted)

        assert decrypted == plaintext

    def test_encrypted_data_contains_nonce(self):
        """Encrypted result should contain nonce."""
        key = generate_key()
        encrypted = encrypt_aes_gcm(key, b"test")

        assert len(encrypted.nonce) == NONCE_SIZE
        assert len(encrypted.ciphertext) > 0

    def test_different_nonces_each_time(self):
        """Each encryption should use different nonce."""
        key = generate_key()
        plaintext = b"same message"

        e1 = encrypt_aes_gcm(key, plaintext)
        e2 = encrypt_aes_gcm(key, plaintext)

        assert e1.nonce != e2.nonce
        assert e1.ciphertext != e2.ciphertext  # Different due to nonce

    def test_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        key1 = generate_key()
        key2 = generate_key()
        plaintext = b"secret"

        encrypted = encrypt_aes_gcm(key1, plaintext)

        with pytest.raises(InvalidTag):
            decrypt_aes_gcm(key2, encrypted)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail authentication."""
        key = generate_key()
        encrypted = encrypt_aes_gcm(key, b"secret")

        # Tamper with ciphertext
        tampered = EncryptedData(
            nonce=encrypted.nonce,
            ciphertext=bytes([encrypted.ciphertext[0] ^ 0xFF])
            + encrypted.ciphertext[1:],
        )

        with pytest.raises(InvalidTag):
            decrypt_aes_gcm(key, tampered)

    def test_tampered_nonce_fails(self):
        """Tampered nonce should fail decryption."""
        key = generate_key()
        encrypted = encrypt_aes_gcm(key, b"secret")

        tampered = EncryptedData(
            nonce=bytes([encrypted.nonce[0] ^ 0xFF]) + encrypted.nonce[1:],
            ciphertext=encrypted.ciphertext,
        )

        with pytest.raises(InvalidTag):
            decrypt_aes_gcm(key, tampered)

    def test_associated_data(self):
        """AAD should be authenticated but not encrypted."""
        key = generate_key()
        plaintext = b"secret"
        aad = b"context data"

        encrypted = encrypt_aes_gcm(key, plaintext, aad)
        decrypted = decrypt_aes_gcm(key, encrypted, aad)

        assert decrypted == plaintext

    def test_wrong_associated_data_fails(self):
        """Wrong AAD should fail authentication."""
        key = generate_key()
        plaintext = b"secret"

        encrypted = encrypt_aes_gcm(key, plaintext, b"correct aad")

        with pytest.raises(InvalidTag):
            decrypt_aes_gcm(key, encrypted, b"wrong aad")

    def test_missing_associated_data_fails(self):
        """Missing AAD when required should fail."""
        key = generate_key()
        encrypted = encrypt_aes_gcm(key, b"secret", b"required aad")

        with pytest.raises(InvalidTag):
            decrypt_aes_gcm(key, encrypted)  # No AAD provided

    def test_empty_plaintext(self):
        """Should handle empty plaintext."""
        key = generate_key()
        encrypted = encrypt_aes_gcm(key, b"")
        decrypted = decrypt_aes_gcm(key, encrypted)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Should handle large plaintext."""
        key = generate_key()
        plaintext = b"x" * 1_000_000  # 1MB

        encrypted = encrypt_aes_gcm(key, plaintext)
        decrypted = decrypt_aes_gcm(key, encrypted)

        assert decrypted == plaintext

    def test_invalid_key_size(self):
        """Should reject invalid key sizes."""
        with pytest.raises(ValueError):
            encrypt_aes_gcm(b"short", b"plaintext")

        with pytest.raises(ValueError):
            encrypt_aes_gcm(b"x" * 64, b"plaintext")


class TestEncryptedData:
    """Tests for EncryptedData serialization."""

    def test_to_bytes_roundtrip(self):
        """Should serialize and deserialize correctly."""
        original = EncryptedData(
            nonce=b"x" * NONCE_SIZE,
            ciphertext=b"encrypted data here",
        )

        serialized = original.to_bytes()
        restored = EncryptedData.from_bytes(serialized)

        assert restored.nonce == original.nonce
        assert restored.ciphertext == original.ciphertext

    def test_from_bytes_too_short(self):
        """Should reject data shorter than nonce."""
        with pytest.raises(ValueError):
            EncryptedData.from_bytes(b"short")
