"""
Implementasi Enkripsi dan Dekripsi Simetris AES-256-GCM.

Sesuai standar:
- NIST SP 800-38D (Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode).
- Kunci simetris: 256-bit (32 byte).
- Nonce / IV: 96-bit (12 byte) unik per pesan.
- Authentication Tag: 128-bit (16 byte).
- Pengikatan Additional Authenticated Data (AAD) untuk mencegah manipulasi metadata pengiriman.
"""

import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class AuthenticationError(Exception):
    """Dilempar ketika verifikasi authentication tag atau AAD gagal pada AES-GCM."""
    pass


def generate_aes_key() -> bytes:
    """
    Membangkitkan kunci simetris 256-bit (32 byte) secara acak kriptografis (CSPRNG).
    """
    return os.urandom(32)


def generate_nonce() -> bytes:
    """
    Membangkitkan initialization vector / nonce 96-bit (12 byte) secara acak.
    Sesuai rekomendasi NIST SP 800-38D Bagian 5.2.1.1.
    """
    return os.urandom(12)


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Mengenkrpsi plaintext dengan AES-256-GCM dan menghasilkan ciphertext serta authentication tag.

    Args:
        plaintext: Data biner pesan yang akan diamankan.
        key: Kunci simetris 256-bit (wajib 32 byte).
        nonce: Nonce unik 96-bit (wajib 12 byte).
        associated_data: Data terautentikasi tambahan (AAD kanonikal: sender:receiver:counter).

    Returns:
        Tuple (ciphertext, tag):
        - ciphertext: Data terenkripsi (panjang sama persis dengan plaintext).
        - tag: Authentication tag 128-bit (16 byte).

    Raises:
        ValueError: Jika panjang kunci bukan 32 byte atau panjang nonce bukan 12 byte.
    """
    if len(key) != 32:
        raise ValueError(f"Panjang kunci AES harus 32 byte (256-bit), diterima: {len(key)} byte.")
    if len(nonce) != 12:
        raise ValueError(f"Panjang nonce GCM harus 12 byte (96-bit), diterima: {len(nonce)} byte.")

    aesgcm = AESGCM(key)
    # PyCA AESGCM.encrypt mengembalikan data berformat: ciphertext + tag (16 byte terakhir)
    combined = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    ciphertext = combined[:-16]
    tag = combined[-16:]
    return ciphertext, tag


def decrypt_aes_gcm(
    ciphertext: bytes,
    tag: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Memverifikasi integritas tag, AAD, dan mendekripsi ciphertext AES-256-GCM menjadi plaintext.

    Args:
        ciphertext: Data terenkripsi.
        tag: Authentication tag 128-bit (wajib 16 byte).
        key: Kunci simetris 256-bit (wajib 32 byte).
        nonce: Nonce 96-bit yang digunakan saat enkripsi (wajib 12 byte).
        associated_data: Data terautentikasi tambahan yang identik dengan saat enkripsi.

    Returns:
        bytes: Plaintext asli hasil dekripsi jika verifikasi tag berhasil.

    Raises:
        ValueError: Jika panjang parameter kunci, nonce, atau tag tidak sesuai spesifikasi.
        AuthenticationError: Jika 1 byte ciphertext, tag, nonce, atau AAD telah dimodifikasi.
    """
    if len(key) != 32:
        raise ValueError(f"Panjang kunci AES harus 32 byte (256-bit), diterima: {len(key)} byte.")
    if len(nonce) != 12:
        raise ValueError(f"Panjang nonce GCM harus 12 byte (96-bit), diterima: {len(nonce)} byte.")
    if len(tag) != 16:
        raise ValueError(f"Panjang authentication tag harus 16 byte (128-bit), diterima: {len(tag)} byte.")

    aesgcm = AESGCM(key)
    combined = ciphertext + tag

    try:
        plaintext = aesgcm.decrypt(nonce, combined, associated_data)
        return plaintext
    except InvalidTag as exc:
        raise AuthenticationError(
            "Verifikasi integritas AES-GCM gagal! Ciphertext, Tag, Nonce, atau AAD telah dimodifikasi."
        ) from exc
