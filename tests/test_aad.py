"""
Unit Test untuk Penyusunan dan Parsing AAD Kanonikal.
"""

import pytest
from src.messaging.aad import build_canonical_aad, parse_canonical_aad


class TestCanonicalAAD:
    def test_build_aad_standard(self):
        aad = build_canonical_aad("alice", "bob", 1)
        assert aad == b"alice:bob:1"

    def test_build_and_parse_roundtrip(self):
        sender = "alice_crypto"
        receiver = "bob_researcher"
        counter = 42

        aad_bytes = build_canonical_aad(sender, receiver, counter)
        s, r, c = parse_canonical_aad(aad_bytes)

        assert s == sender
        assert r == receiver
        assert c == counter

    def test_empty_sender_or_receiver_rejection(self):
        with pytest.raises(ValueError, match="Field sender tidak boleh kosong"):
            build_canonical_aad("", "bob", 1)

        with pytest.raises(ValueError, match="Field receiver tidak boleh kosong"):
            build_canonical_aad("alice", "   ", 1)

    def test_negative_counter_rejection(self):
        with pytest.raises(ValueError, match="Nilai counter tidak boleh negatif"):
            build_canonical_aad("alice", "bob", -1)

    def test_parse_invalid_aad_format(self):
        with pytest.raises(ValueError, match="Gagal mem-parse data AAD"):
            parse_canonical_aad(b"alice:bob")  # Hanya 2 elemen

        with pytest.raises(ValueError, match="Gagal mem-parse data AAD"):
            parse_canonical_aad(b"alice:bob:not_a_number")
