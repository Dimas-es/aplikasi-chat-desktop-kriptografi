"""
Pengujian Unit Tanda Tangan Digital RSA-PSS (tests/test_signature.py).

Memastikan:
1. Validitas penandatanganan dan verifikasi pesan sah.
2. Deteksi pemalsuan data / payload (tampering detection).
3. Deteksi korupsi byte tanda tangan (corrupted signature).
4. Penolakan verifikasi bila menggunakan kunci publik lawan bicara yang salah.
5. Validasi tipe data kunci dan masukan.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.rsa_oaep import generate_rsa_keypair
from src.crypto.rsa_pss import sign_data, verify_signature
from src.messaging.packet import MessagePacket


class TestRSAPSSSignature:
    @pytest.fixture
    def alice_keys(self):
        return generate_rsa_keypair(key_size=2048)

    @pytest.fixture
    def bob_keys(self):
        return generate_rsa_keypair(key_size=2048)

    def test_sign_and_verify_valid_signature(self, alice_keys):
        priv_key, pub_key = alice_keys
        payload = b"Transfer dana $10,000 dari Alice ke Charlie"

        sig = sign_data(priv_key, payload)
        assert isinstance(sig, bytes)
        assert len(sig) == 256  # 2048 bit

        is_valid = verify_signature(pub_key, payload, sig)
        assert is_valid is True

    def test_tampered_payload_rejected(self, alice_keys):
        priv_key, pub_key = alice_keys
        payload = b"Pesan asli yang belum diubah"

        sig = sign_data(priv_key, payload)

        # Ubah payload 1 karakter
        tampered_payload = b"Pesan asli yang SUDAH diubah"
        is_valid = verify_signature(pub_key, tampered_payload, sig)
        assert is_valid is False

    def test_tampered_signature_byte_rejected(self, alice_keys):
        priv_key, pub_key = alice_keys
        payload = b"Pesan penting"

        sig = bytearray(sign_data(priv_key, payload))
        sig[0] ^= 0xFF  # Flip 1 byte pada signature

        is_valid = verify_signature(pub_key, payload, bytes(sig))
        assert is_valid is False

    def test_wrong_public_key_rejected(self, alice_keys, bob_keys):
        alice_priv, alice_pub = alice_keys
        bob_priv, bob_pub = bob_keys

        payload = b"Pesan sah yang ditandatangani oleh Alice"
        sig = sign_data(alice_priv, payload)

        # Coba verifikasi tanda tangan Alice dengan kunci publik Bob
        is_valid = verify_signature(bob_pub, payload, sig)
        assert is_valid is False

    def test_type_validation(self, alice_keys):
        priv_key, pub_key = alice_keys
        with pytest.raises(TypeError, match="private_key harus berupa instance"):
            sign_data("bukan_kunci", b"data")

        with pytest.raises(TypeError, match="public_key harus berupa instance"):
            verify_signature("bukan_kunci", b"data", b"x" * 256)
