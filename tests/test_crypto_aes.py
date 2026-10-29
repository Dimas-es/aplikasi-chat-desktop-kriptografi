"""
Unit Test dan Validasi NIST Known Answer Tests (KAT) untuk Modul AES-256-GCM.
"""

import pytest
from src.crypto.aes_gcm import (
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AuthenticationError,
)


class TestAESGCMCorrectness:
    def test_key_and_nonce_generation(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        assert len(key) == 32
        assert len(nonce) == 12
        # Memastikan tidak konstan (CSPRNG)
        assert key != generate_aes_key()
        assert nonce != generate_nonce()

    def test_encrypt_decrypt_short_message(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Halo Bob, ini pesan rahasia tugas kriptografi!"
        aad = b"alice:bob:1"

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=aad)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 16
        assert ciphertext != plaintext

        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=aad)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode_and_emojis(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        original_text = "Pesan rahasia dengan emoji 🔐🚀✨ dan karakter khusus: äöüß!"
        plaintext = original_text.encode("utf-8")
        aad = b"alice:bob:2"

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=aad)
        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=aad)
        assert decrypted.decode("utf-8") == original_text

    def test_encrypt_decrypt_large_payload(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        # 100 KB payload
        plaintext = b"A" * (100 * 1024)
        aad = b"alice:bob:3"

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=aad)
        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=aad)
        assert decrypted == plaintext


class TestNISTKnownAnswerTests:
    """
    Validasi resmi Known Answer Test (KAT) dari NIST Special Publication 800-38D.
    Memastikan implementasi kita menghasilkan ciphertext dan tag yang 100% identik dengan standar NIST.
    """

    def test_nist_sp800_38d_case_13_empty_plaintext(self):
        # NIST Test Case 13 (AES-256 GCM, empty PT, empty AAD)
        key = bytes.fromhex("00" * 32)
        nonce = bytes.fromhex("00" * 12)
        plaintext = b""
        expected_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=None)
        assert ciphertext == b""
        assert tag == expected_tag

        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=None)
        assert decrypted == plaintext

    def test_nist_sp800_38d_case_14_zeros(self):
        # NIST Test Case 14 (AES-256 GCM, 16-byte zero PT, empty AAD)
        key = bytes.fromhex("00" * 32)
        nonce = bytes.fromhex("00" * 12)
        plaintext = bytes.fromhex("00" * 16)
        expected_ciphertext = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
        expected_tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=None)
        assert ciphertext == expected_ciphertext
        assert tag == expected_tag

        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=None)
        assert decrypted == plaintext

    def test_nist_sp800_38d_case_16_with_aad(self):
        # NIST Test Case 16 (AES-256 GCM, 64-byte PT, 20-byte AAD)
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        expected_ciphertext = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        )
        expected_tag = bytes.fromhex("2df7cd675b4f09163b41ebf980a7f638")

        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=aad)
        assert ciphertext == expected_ciphertext
        assert tag == expected_tag

        decrypted = decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=aad)
        assert decrypted == plaintext


class TestAESGCMNegativeAndTampering:
    @pytest.fixture
    def setup_data(self):
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Pesan penting yang tidak boleh dimanipulasi!"
        aad = b"alice:bob:4"
        ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce, associated_data=aad)
        return key, nonce, plaintext, aad, ciphertext, tag

    def test_flip_one_byte_in_ciphertext(self, setup_data):
        key, nonce, _, aad, ciphertext, tag = setup_data
        # Ubah byte pertama dari ciphertext
        corrupted_ct = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(corrupted_ct, tag, key, nonce, associated_data=aad)

    def test_flip_one_byte_in_tag(self, setup_data):
        key, nonce, _, aad, ciphertext, tag = setup_data
        # Ubah byte terakhir dari tag
        corrupted_tag = tag[:-1] + bytes([tag[-1] ^ 0xFF])

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, corrupted_tag, key, nonce, associated_data=aad)

    def test_flip_one_byte_in_nonce(self, setup_data):
        key, nonce, _, aad, ciphertext, tag = setup_data
        corrupted_nonce = bytes([nonce[0] ^ 0x55]) + nonce[1:]

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, tag, key, corrupted_nonce, associated_data=aad)

    def test_tamper_aad_metadata(self, setup_data):
        key, nonce, _, _, ciphertext, tag = setup_data
        # Penyerang memalsukan AAD (misal mengganti counter dari 4 ke 5)
        fake_aad = b"alice:bob:5"

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=fake_aad)

    def test_tamper_sender_in_aad(self, setup_data):
        key, nonce, _, _, ciphertext, tag = setup_data
        # Penyerang memalsukan pengirim (misal mengganti alice dengan eve)
        fake_aad = b"eve:bob:4"

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, tag, key, nonce, associated_data=fake_aad)

    def test_wrong_key(self, setup_data):
        _, nonce, _, aad, ciphertext, tag = setup_data
        wrong_key = generate_aes_key()

        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, tag, wrong_key, nonce, associated_data=aad)

    def test_invalid_parameter_lengths(self):
        valid_key = generate_aes_key()
        valid_nonce = generate_nonce()

        # Kunci tidak 32 byte
        with pytest.raises(ValueError):
            encrypt_aes_gcm(b"test", b"short_key", valid_nonce)

        # Nonce tidak 12 byte
        with pytest.raises(ValueError):
            encrypt_aes_gcm(b"test", valid_key, b"nonce_8b")

        # Tag tidak 16 byte
        with pytest.raises(ValueError):
            decrypt_aes_gcm(b"ct", b"short_tag", valid_key, valid_nonce)
