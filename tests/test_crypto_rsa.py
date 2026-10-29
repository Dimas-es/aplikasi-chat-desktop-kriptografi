"""
Unit Test dan Pengujian Batas Matematis untuk Modul RSA-OAEP SHA-256.
"""

import pytest
from src.crypto.rsa_oaep import (
    generate_rsa_keypair,
    wrap_key,
    unwrap_key,
    calculate_max_oaep_payload,
    public_key_to_pem,
    pem_to_public_key,
    private_key_to_pem,
    pem_to_private_key,
    KeyUnwrapError,
    PayloadTooLargeError,
)
from src.crypto.aes_gcm import generate_aes_key


@pytest.fixture(scope="module")
def rsa_keys():
    # Generate 2048-bit key pair
    priv, pub = generate_rsa_keypair(key_size=2048)
    return priv, pub


class TestRSAOAEPKeyWrapping:

    def test_key_sizes(self, rsa_keys):
        priv, pub = rsa_keys
        assert priv.key_size == 2048
        assert pub.key_size == 2048

    def test_wrap_and_unwrap_aes_key(self, rsa_keys):
        priv, pub = rsa_keys
        aes_key = generate_aes_key()  # 32 byte

        wrapped = wrap_key(aes_key, pub)
        # Panjang wrapped key RSA-2048 harus tepat 256 byte (2048 bit)
        assert len(wrapped) == 256
        assert wrapped != aes_key

        unwrapped = unwrap_key(wrapped, priv)
        assert unwrapped == aes_key

    def test_oaep_randomized_ciphertext(self, rsa_keys):
        _, pub = rsa_keys
        aes_key = generate_aes_key()

        # OAEP menggunakan seed acak per enkripsi, sehingga 2 kali wrap dengan kunci yang sama menghasilkan ciphertext berbeda
        wrapped_1 = wrap_key(aes_key, pub)
        wrapped_2 = wrap_key(aes_key, pub)
        assert wrapped_1 != wrapped_2

    def test_max_payload_limit(self, rsa_keys):
        priv, pub = rsa_keys
        max_len = calculate_max_oaep_payload(2048)
        assert max_len == 190  # 256 - 2(32) - 2 = 190 byte

        # 190 byte harus berhasil di-wrap dan di-unwrap
        boundary_payload = b"X" * 190
        wrapped = wrap_key(boundary_payload, pub)
        unwrapped = unwrap_key(wrapped, priv)
        assert unwrapped == boundary_payload

        # 191 byte harus gagal melempar PayloadTooLargeError
        overflow_payload = b"X" * 191
        with pytest.raises(PayloadTooLargeError):
            wrap_key(overflow_payload, pub)

    def test_wrong_private_key_fails(self, rsa_keys):
        _, bob_pub = rsa_keys
        eve_priv, _ = generate_rsa_keypair(key_size=2048)
        aes_key = generate_aes_key()

        # Alice membungkus kunci untuk Bob
        wrapped_for_bob = wrap_key(aes_key, bob_pub)

        # Eve mencoba membuka dengan private key miliknya
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped_for_bob, eve_priv)

    def test_corrupted_wrapped_key_fails(self, rsa_keys):
        bob_priv, bob_pub = rsa_keys
        aes_key = generate_aes_key()
        wrapped = wrap_key(aes_key, bob_pub)

        # Ubah 1 byte pada ciphertext wrapped_key
        corrupted = bytearray(wrapped)
        corrupted[10] ^= 0xAA
        corrupted_bytes = bytes(corrupted)

        with pytest.raises(KeyUnwrapError):
            unwrap_key(corrupted_bytes, bob_priv)

    def test_pem_serialization_roundtrip(self, rsa_keys):
        priv, pub = rsa_keys

        # Public key PEM
        pub_pem = public_key_to_pem(pub)
        assert b"BEGIN PUBLIC KEY" in pub_pem
        reloaded_pub = pem_to_public_key(pub_pem)
        assert reloaded_pub.key_size == 2048

        # Private key PEM (unencrypted)
        priv_pem = private_key_to_pem(priv, password=None)
        assert b"BEGIN PRIVATE KEY" in priv_pem
        reloaded_priv = pem_to_private_key(priv_pem, password=None)
        assert reloaded_priv.key_size == 2048

        # Test wrap/unwrap dengan reloaded keys
        key = generate_aes_key()
        wrapped = wrap_key(key, reloaded_pub)
        assert unwrap_key(wrapped, reloaded_priv) == key
