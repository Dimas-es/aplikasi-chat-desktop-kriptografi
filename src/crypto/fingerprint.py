"""
Implementasi Perhitungan dan Verifikasi Nilai Fingerprint Public Key.

Fungsi:
- Menghasilkan representasi ringkas SHA-256 (32 byte / 64 karakter hex) dari public key.
- Format standar: Heksadesimal huruf kapital yang dipisahkan tanda titik dua (contoh: 4A:1B:3C:...).
- Digunakan untuk mitigasi serangan Man-in-the-Middle (MITM) melalui pencocokan manual out-of-band.
"""

import hmac
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def calculate_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """
    Menghitung fingerprint SHA-256 dari kunci publik RSA dalam format DER kanonikal (SubjectPublicKeyInfo).

    Args:
        public_key: Objek kunci publik RSA.

    Returns:
        str: String fingerprint berupa 32 pasang heksadesimal kapital yang dipisahkan titik dua.
             Contoh: "A1:B2:C3:D4:..."
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    # Format menjadi kelompok 2 karakter dipisahkan titik dua
    formatted_fingerprint = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    return formatted_fingerprint


def normalize_fingerprint(fingerprint_str: str) -> str:
    """Membersihkan format fingerprint (menghapus spasi, titik dua, dan mengubah ke huruf kapital)."""
    return fingerprint_str.replace(":", "").replace(" ", "").strip().upper()


def verify_fingerprint(public_key: rsa.RSAPublicKey, expected_fingerprint: str) -> bool:
    """
    Memverifikasi apakah kunci publik menghasilkan fingerprint yang cocok dengan nilai yang diharapkan.
    Menggunakan perbandingan waktu-konstan (constant-time compare) untuk mencegah timing attack.

    Args:
        public_key: Objek kunci publik RSA.
        expected_fingerprint: Nilai fingerprint yang diharapkan (format bebas, boleh dengan/tanpa titik dua).

    Returns:
        bool: True jika cocok sempurna, False jika ada perbedaan.
    """
    actual_norm = normalize_fingerprint(calculate_fingerprint(public_key))
    expected_norm = normalize_fingerprint(expected_fingerprint)
    return hmac.compare_digest(actual_norm, expected_norm)
