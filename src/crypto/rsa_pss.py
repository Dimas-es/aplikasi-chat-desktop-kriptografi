"""
Modul Tanda Tangan Digital RSA-PSS (PKCS#1 v2.2 / RFC 8017).

Menyediakan:
- sign_packet_payload: Membubuhkan tanda tangan digital probabilistik RSA-PSS dengan SHA-256.
- verify_packet_signature: Memverifikasi keabsahan tanda tangan pengirim menggunakan Kunci Publik pengirim.
"""

from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Membubuhkan tanda tangan digital RSA-PSS pada data stream byte.

    Parameter:
        private_key: Kunci privat RSA-2048 pengirim
        data: Byte payload yang akan ditandatangani

    Returns:
        bytes tanda tangan digital berukuran 256 byte (2048 bit).
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key harus berupa instance rsa.RSAPrivateKey")

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,  # Salt 32-byte
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Memverifikasi tanda tangan digital RSA-PSS menggunakan kunci publik pengirim.

    Parameter:
        public_key: Kunci publik RSA pengirim
        data: Byte payload asli yang ditandatangani
        signature: Byte tanda tangan digital yang diperiksa

    Returns:
        True jika tanda tangan sah matematis, False jika tanda tangan salah/termanipulasi.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_key harus berupa instance rsa.RSAPublicKey")

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
