"""
Unit Test untuk Modul Derivasi Kunci Passphrase (PBKDF2) dan Proteksi Private Key.
"""

import os
import pytest
from src.crypto.kdf import (
    derive_key_from_passphrase,
    encrypt_private_key,
    decrypt_private_key,
    InvalidPassphraseError,
)
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key, unwrap_key
from src.crypto.aes_gcm import generate_aes_key


class TestKDFAndPrivateKeyProtection:
    def test_derive_key_properties(self):
        salt = os.urandom(16)
        passphrase = "password_rahasia_alice_123!"

        key1 = derive_key_from_passphrase(passphrase, salt)
        key2 = derive_key_from_passphrase(passphrase, salt)
        # Sifat deterministik (passphrase + salt sama -> kunci sama)
        assert key1 == key2
        assert len(key1) == 32

        # Salt berbeda -> kunci berbeda
        diff_salt = os.urandom(16)
        assert derive_key_from_passphrase(passphrase, diff_salt) != key1

        # Passphrase berbeda -> kunci berbeda
        assert derive_key_from_passphrase("passphrase_lain", salt) != key1

    def test_encrypt_and_decrypt_private_key(self):
        priv, pub = generate_rsa_keypair(key_size=2048)
        passphrase = "kunci_akses_keystore_bob#2026"

        encrypted_blob, salt = encrypt_private_key(priv, passphrase)
        assert len(salt) == 16
        assert len(encrypted_blob) > 1000  # Private key 2048-bit terenkripsi

        # Dekripsi dengan passphrase yang benar
        recovered_priv = decrypt_private_key(encrypted_blob, salt, passphrase)
        assert recovered_priv.key_size == 2048

        # Uji fungsionalitas: kunci yang dipulihkan harus bisa membuka pesan yang dibungkus oleh public key aslinya
        test_aes_key = generate_aes_key()
        wrapped = wrap_key(test_aes_key, pub)
        unwrapped = unwrap_key(wrapped, recovered_priv)
        assert unwrapped == test_aes_key

    def test_wrong_passphrase_rejection(self):
        priv, _ = generate_rsa_keypair(key_size=2048)
        passphrase = "passphrase_asli"
        wrong_passphrase = "passphrase_salah"

        encrypted_blob, salt = encrypt_private_key(priv, passphrase)

        with pytest.raises(InvalidPassphraseError):
            decrypt_private_key(encrypted_blob, salt, wrong_passphrase)

    def test_tampered_encrypted_blob_rejection(self):
        priv, _ = generate_rsa_keypair(key_size=2048)
        passphrase = "passphrase_asli"

        encrypted_blob, salt = encrypt_private_key(priv, passphrase)
        # Manipulasi 1 byte di dalam blob terenkripsi
        corrupted_blob = bytearray(encrypted_blob)
        corrupted_blob[20] ^= 0x55
        corrupted_bytes = bytes(corrupted_blob)

        with pytest.raises(InvalidPassphraseError):
            decrypt_private_key(corrupted_bytes, salt, passphrase)
