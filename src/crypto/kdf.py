"""
Implementasi Fungsi Derivasi Kunci (Key Derivation Function / KDF) dan Proteksi Private Key.

Sesuai standar:
- PBKDF2-HMAC-SHA256 dengan 100.000 iterasi dan salt acak 128-bit (16 byte).
- Kunci turunan digunakan untuk mengenkripsi private key RSA menggunakan AES-256-GCM.
- Memastikan private key tidak pernah tersimpan dalam format plaintext di media penyimpanan lokal.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm, AuthenticationError
from src.crypto.rsa_oaep import private_key_to_pem, pem_to_private_key


class InvalidPassphraseError(Exception):
    """Dilempar ketika passphrase yang dimasukkan salah saat membuka private key."""
    pass


def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes,
    iterations: int = 100_000,
    key_length: int = 32,
) -> bytes:
    """
    Menurunkan kunci kriptografis simetris dari string passphrase menggunakan PBKDF2-HMAC-SHA256.

    Args:
        passphrase: Kata sandi yang dimasukkan pengguna.
        salt: Nilai salt acak (wajib 16 byte).
        iterations: Jumlah putaran hashing (default: 100.000 iterasi).
        key_length: Panjang kunci keluaran dalam byte (default: 32 byte untuk AES-256).

    Returns:
        bytes: Kunci simetris turunan berkekuatan tinggi (32 byte).
    """
    if not passphrase:
        raise ValueError("Passphrase tidak boleh kosong.")
    if len(salt) < 16:
        raise ValueError("Salt minimal harus 16 byte (128-bit) untuk mencegah serangan rainbow table.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_private_key(
    private_key: rsa.RSAPrivateKey,
    passphrase: str,
) -> Tuple[bytes, bytes]:
    """
    Mengenkrpsi private key RSA menggunakan kunci yang diderivasi dari passphrase pengguna.

    Args:
        private_key: Objek private key RSA.
        passphrase: Kata sandi pengguna untuk mengunci private key.

    Returns:
        Tuple (encrypted_blob, salt):
        - encrypted_blob: Paket biner memuat [Nonce 12B] + [Ciphertext] + [Tag 16B].
        - salt: Nilai salt 16B yang disimpan bersama untuk keperluan dekripsi nanti.
    """
    salt = os.urandom(16)
    derived_key = derive_key_from_passphrase(passphrase, salt)
    nonce = os.urandom(12)

    # Serialisasi private key ke PEM tanpa enkripsi langsung, karena enkripsi dilakukan oleh AES-GCM kita
    pem_bytes = private_key_to_pem(private_key, password=None)
    
    # Enkripsi data PEM menggunakan AES-256-GCM dengan AAD identitas
    aad = b"trustgive:local_keystore:private_key_v1"
    ciphertext, tag = encrypt_aes_gcm(pem_bytes, derived_key, nonce, associated_data=aad)

    # Gabungkan menjadi encrypted_blob: nonce (12 byte) + ciphertext + tag (16 byte)
    encrypted_blob = nonce + ciphertext + tag
    return encrypted_blob, salt


def decrypt_private_key(
    encrypted_blob: bytes,
    salt: bytes,
    passphrase: str,
) -> rsa.RSAPrivateKey:
    """
    Mendekripsi paket biner terenkripsi menjadi objek RSA Private Key menggunakan passphrase pengguna.

    Args:
        encrypted_blob: Paket data biner memuat [Nonce 12B] + [Ciphertext] + [Tag 16B].
        salt: Nilai salt yang disimpan saat proses enkripsi.
        passphrase: Kata sandi yang dimasukkan pengguna.

    Returns:
        rsa.RSAPrivateKey: Objek kunci privat RSA yang berhasil dipulihkan.

    Raises:
        InvalidPassphraseError: Jika passphrase salah atau data berkas kunci telah rusak/dimodifikasi.
    """
    if len(encrypted_blob) < (12 + 16):
        raise InvalidPassphraseError("Format berkas private key terenkripsi tidak valid atau rusak.")

    nonce = encrypted_blob[:12]
    tag = encrypted_blob[-16:]
    ciphertext = encrypted_blob[12:-16]

    try:
        derived_key = derive_key_from_passphrase(passphrase, salt)
        aad = b"trustgive:local_keystore:private_key_v1"
        pem_bytes = decrypt_aes_gcm(ciphertext, tag, derived_key, nonce, associated_data=aad)
        private_key = pem_to_private_key(pem_bytes, password=None)
        return private_key
    except (AuthenticationError, ValueError, Exception) as exc:
        raise InvalidPassphraseError(
            "Passphrase salah atau berkas private key telah rusak! Gagal memulihkan kunci."
        ) from exc
