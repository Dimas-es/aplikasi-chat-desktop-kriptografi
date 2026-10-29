"""
Modul Kriptografi Inti untuk Aplikasi Chat Desktop Enkripsi Hybrid.

Menerapkan:
- AES-256-GCM dengan Nonce 96-bit dan autentikasi AAD kanonikal (RFC 5116 / NIST SP 800-38D).
- RSA-OAEP 2048-bit dengan parameter eksplisit SHA-256 dan MGF1 SHA-256 (RFC 8017).
- Derivasi Kunci Passphrase PBKDF2-HMAC-SHA256 dengan salt acak 128-bit untuk proteksi private key.
- Perhitungan dan pemformatan Fingerprint SHA-256 dari public key.
"""

from src.crypto.aes_gcm import (
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AuthenticationError,
)
from src.crypto.rsa_oaep import (
    generate_rsa_keypair,
    get_oaep_padding,
    wrap_key,
    unwrap_key,
    public_key_to_pem,
    pem_to_public_key,
    private_key_to_pem,
    pem_to_private_key,
    KeyUnwrapError,
    PayloadTooLargeError,
)
from src.crypto.kdf import (
    derive_key_from_passphrase,
    encrypt_private_key,
    decrypt_private_key,
    InvalidPassphraseError,
)
from src.crypto.fingerprint import (
    calculate_fingerprint,
    verify_fingerprint,
)

__all__ = [
    "generate_aes_key",
    "generate_nonce",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "AuthenticationError",
    "generate_rsa_keypair",
    "get_oaep_padding",
    "wrap_key",
    "unwrap_key",
    "public_key_to_pem",
    "pem_to_public_key",
    "private_key_to_pem",
    "pem_to_private_key",
    "KeyUnwrapError",
    "PayloadTooLargeError",
    "derive_key_from_passphrase",
    "encrypt_private_key",
    "decrypt_private_key",
    "InvalidPassphraseError",
    "calculate_fingerprint",
    "verify_fingerprint",
]
