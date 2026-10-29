"""
Integration Test untuk Alur Lengkap Enkripsi Hybrid (AES-256-GCM + RSA-OAEP SHA-256).
"""

import pytest
from src.crypto.aes_gcm import (
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AuthenticationError,
)
from src.crypto.rsa_oaep import (
    generate_rsa_keypair,
    wrap_key,
    unwrap_key,
    KeyUnwrapError,
)


@pytest.fixture(scope="module")
def participants():
    alice_priv, alice_pub = generate_rsa_keypair(key_size=2048)
    bob_priv, bob_pub = generate_rsa_keypair(key_size=2048)
    return {
        "alice_priv": alice_priv,
        "alice_pub": alice_pub,
        "bob_priv": bob_priv,
        "bob_pub": bob_pub,
    }


class TestHybridEncryptionFlow:

    def test_complete_hybrid_send_and_receive(self, participants):
        bob_pub = participants["bob_pub"]
        bob_priv = participants["bob_priv"]

        # 1. Alice menyusun pesan dan metadata
        pesan_asli = "Pertemuan rahasia besok pukul 09:00 WIB di Lab Kriptografi! 📍🔐"
        plaintext = pesan_asli.encode("utf-8")
        counter = 1
        aad = f"alice:bob:{counter}".encode("utf-8")

        # 2. Alice membangkitkan K_AES dan Nonce segar
        k_aes = generate_aes_key()
        nonce = generate_nonce()

        # 3. Alice mengenkripsi muatan dengan AES-256-GCM
        ciphertext, tag = encrypt_aes_gcm(plaintext, k_aes, nonce, associated_data=aad)

        # 4. Alice membungkus K_AES dengan RSA-OAEP menggunakan Public Key Bob
        wrapped_key = wrap_key(k_aes, bob_pub)

        # --- Transmisi Paket di Jaringan (Ciphertext Only) ---
        assert wrapped_key != k_aes
        assert ciphertext != plaintext

        # 5. Bob menerima paket: Bob membuka kunci K_AES dengan Private Key miliknya
        recovered_k_aes = unwrap_key(wrapped_key, bob_priv)
        assert recovered_k_aes == k_aes

        # 6. Bob merekonstruksi AAD dan memverifikasi integritas serta mendekripsi isi pesan
        reconstructed_aad = f"alice:bob:{counter}".encode("utf-8")
        decrypted_bytes = decrypt_aes_gcm(ciphertext, tag, recovered_k_aes, nonce, associated_data=reconstructed_aad)

        # 7. Bob mendapatkan plaintext 100% identik
        assert decrypted_bytes.decode("utf-8") == pesan_asli

    def test_hybrid_flow_with_eavesdropper_eve_private_key(self, participants):
        bob_pub = participants["bob_pub"]
        eve_priv, _ = generate_rsa_keypair(key_size=2048)

        # Alice kirim pesan ke Bob
        plaintext = b"Pesan rahasia untuk Bob saja"
        aad = b"alice:bob:2"
        k_aes = generate_aes_key()
        nonce = generate_nonce()
        ciphertext, tag = encrypt_aes_gcm(plaintext, k_aes, nonce, associated_data=aad)
        wrapped_key = wrap_key(k_aes, bob_pub)

        # Eve menyadap dan mencoba mendekripsi wrapped_key dengan private key Eve
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped_key, eve_priv)

    def test_hybrid_flow_with_tampered_aad(self, participants):
        bob_pub = participants["bob_pub"]
        bob_priv = participants["bob_priv"]

        plaintext = b"Pesan transfer donasi Rp 1.000.000"
        aad_asli = b"alice:bob:3"
        k_aes = generate_aes_key()
        nonce = generate_nonce()
        ciphertext, tag = encrypt_aes_gcm(plaintext, k_aes, nonce, associated_data=aad_asli)
        wrapped_key = wrap_key(k_aes, bob_pub)

        recovered_k_aes = unwrap_key(wrapped_key, bob_priv)

        # Penyerang mengubah metadata counter di transit (dari 3 menjadi 4)
        aad_palsu = b"alice:bob:4"
        with pytest.raises(AuthenticationError):
            decrypt_aes_gcm(ciphertext, tag, recovered_k_aes, nonce, associated_data=aad_palsu)
