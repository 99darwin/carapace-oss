"""Tests for encoding utilities."""

import pytest

from carapace_crypto.encoding import (
    b64_decode,
    b64_decode_strict,
    b64_encode,
    b64_encode_std,
    hex_decode,
    hex_encode,
)


class TestBase64:
    """Tests for base64 encoding/decoding."""

    def test_encode_simple(self):
        """Should encode to URL-safe base64 without padding."""
        assert b64_encode(b"hello") == "aGVsbG8"
        assert b64_encode(b"hello world") == "aGVsbG8gd29ybGQ"

    def test_decode_simple(self):
        """Should decode URL-safe base64."""
        assert b64_decode("aGVsbG8") == b"hello"
        assert b64_decode("aGVsbG8gd29ybGQ") == b"hello world"

    def test_roundtrip(self):
        """Encode then decode should return original."""
        test_data = [b"", b"a", b"ab", b"abc", b"abcd", b"\x00\xff\x80"]
        for data in test_data:
            assert b64_decode(b64_encode(data)) == data

    def test_decode_with_padding(self):
        """Should accept correct padding or none, and nothing else."""
        assert b64_decode("aGVsbG8") == b"hello"
        assert b64_decode("aGVsbG8=") == b"hello"
        with pytest.raises(ValueError):
            b64_decode("aGVsbG8==")

    @pytest.mark.parametrize(
        "encoded",
        [
            "aGVsbG9",  # non-canonical trailing bits
            "YWJj=",  # padding where none is due
            "aGVsbG8==",  # too much padding
            "aGVsb",  # length 1 mod 4
            "aGV!sbG8",  # non-alphabet character
            "aGVsbG8\n",
            "+/8",  # standard alphabet
            "aGVs bG8",
            "=",
        ],
    )
    def test_decode_rejects_non_canonical(self, encoded: str):
        with pytest.raises(ValueError):
            b64_decode(encoded)

    def test_url_safe_characters(self):
        """Should use URL-safe alphabet (- and _ instead of + and /)."""
        # Data that would produce + and / in standard base64
        data = b"\xfb\xff\xfe"
        encoded = b64_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded
        # Should use - and _ instead
        assert b64_decode(encoded) == data

    def test_binary_data(self):
        """Should handle arbitrary binary data."""
        data = bytes(range(256))
        assert b64_decode(b64_encode(data)) == data

    def test_empty_input(self):
        """Should handle empty input."""
        assert b64_encode(b"") == ""
        assert b64_decode("") == b""


class TestHex:
    """Tests for hex encoding/decoding."""

    def test_encode_simple(self):
        """Should encode to lowercase hex."""
        assert hex_encode(b"\x00") == "00"
        assert hex_encode(b"\xff") == "ff"
        assert hex_encode(b"\x00\xff") == "00ff"
        assert hex_encode(b"hello") == "68656c6c6f"

    def test_decode_simple(self):
        """Should decode hex string."""
        assert hex_decode("00") == b"\x00"
        assert hex_decode("ff") == b"\xff"
        assert hex_decode("68656c6c6f") == b"hello"

    def test_roundtrip(self):
        """Encode then decode should return original."""
        test_data = [b"", b"\x00", b"\xff", b"hello", bytes(range(256))]
        for data in test_data:
            assert hex_decode(hex_encode(data)) == data

    def test_decode_case_insensitive(self):
        """Should decode both upper and lower case hex."""
        assert hex_decode("FF") == b"\xff"
        assert hex_decode("ff") == b"\xff"
        assert hex_decode("Ff") == b"\xff"

    def test_decode_invalid_hex(self):
        """Should raise on invalid hex."""
        with pytest.raises(ValueError):
            hex_decode("gg")
        with pytest.raises(ValueError):
            hex_decode("0")  # Odd length

    def test_empty_input(self):
        """Should handle empty input."""
        assert hex_encode(b"") == ""
        assert hex_decode("") == b""

    def test_encode_always_lowercase(self):
        """Encoded output should always be lowercase."""
        data = bytes(range(256))
        encoded = hex_encode(data)
        assert encoded == encoded.lower()


class TestStandardBase64:
    """Tests for the padded standard-alphabet decoder used by signed objects."""

    def test_round_trip(self):
        for data in [b"", b"a", b"ab", b"abc", b"\xfb\xff\xfe", bytes(range(256))]:
            encoded = b64_encode_std(data)
            assert b64_decode_strict(encoded) == data

    def test_known_values(self):
        assert b64_encode_std(b"\xfb\xff\xfe") == "+//+"
        assert b64_decode_strict("aGVsbG8=") == b"hello"

    @pytest.mark.parametrize(
        "encoded",
        [
            "aGVsbG8",  # unpadded
            "aGVsbG8==",
            "aGVsbG9=",  # non-canonical trailing bits
            "-__-",  # URL-safe alphabet
            "aGVs\nbG8=",
            "aGV!sbG8=",
            " aGVsbG8=",
            "aGVsbG8= ",
        ],
    )
    def test_rejects_non_canonical(self, encoded: str):
        with pytest.raises(ValueError):
            b64_decode_strict(encoded)

    @pytest.mark.parametrize("value", [None, 5, b"aGVsbG8=", ["aGVsbG8="]])
    def test_rejects_non_strings(self, value: object):
        with pytest.raises(ValueError, match="field"):
            b64_decode_strict(value, name="field")
