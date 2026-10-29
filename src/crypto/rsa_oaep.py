"""
Implementasi Pembangkitan Kunci Asimetris dan Pembungkusan Kunci (Key Wrapping) RSA-OAEP SHA-256.

Sesuai standar:
- RFC 8017 (PKCS #1: RSA Cryptography Specifications Version 2.2).
- RSA-2048 bit dengan eksponen publik e=65537.
- Skema padding: RSAES-OAEP.
- Parameter eksplisit: Hash Utama SHA-256, MGF1 Hash SHA-256, Label kosong (None).
- Batas muatan matematis (Maximum Payload Size): 190 byte untuk RSA-2048 dengan OAEP SHA-256.
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class KeyUnwrapError(Exception):
    """Dilempar ketika proses pembukaan (unwrap) kunci simetris dengan RSA-OAEP gagal."""
    pass


class PayloadTooLargeError(Exception):
    """Dilempar ketika ukuran data melebihi batas muatan matematis RSA-OAEP."""
    pass


def get_oaep_padding() -> padding.OAEP:
    """
    Mengembalikan konfigurasi padding RSA-OAEP dengan parameter eksplisit konsisten.
    Menghindari ambiguitas bawaan pustaka (default MGF1-SHA1) dengan menetapkan SHA-256
    secara eksplisit baik untuk fungsi hash utama maupun MGF1 (Mask Generation Function 1).
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Membangkitkan pasangan kunci RSA (private key dan public key).

    Args:
        key_size: Ukuran modulus RSA dalam bit (default: 2048 bit).

    Returns:
        Tuple (private_key, public_key)
    """
    if key_size < 2048:
        raise ValueError("Ukuran kunci RSA minimal harus 2048 bit untuk keamanan standar industri.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def calculate_max_oaep_payload(key_size_bits: int = 2048) -> int:
    """
    Menghitung batas maksimum ukuran muatan (plaintext) untuk RSA-OAEP dengan SHA-256.
    Rumus: k - 2 * hLen - 2
    Untuk RSA-2048 (k=256 byte) dan SHA-256 (hLen=32 byte):
    Max = 256 - 2(32) - 2 = 190 byte.
    """
    k = key_size_bits // 8
    hlen = 32  # SHA-256 menghasilkan 32 byte digest
    return k - (2 * hlen) - 2


def wrap_key(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Membungkus (wrap / mengenkripsi) kunci simetris AES menggunakan public key RSA penerima.

    Args:
        symmetric_key: Kunci simetris (misal 32 byte untuk AES-256).
        public_key: Kunci publik penerima pesan.

    Returns:
        bytes: Wrapped key berukuran 256 byte (untuk RSA-2048).

    Raises:
        PayloadTooLargeError: Jika ukuran data melebihi batas 190 byte.
    """
    max_payload = calculate_max_oaep_payload(public_key.key_size)
    if len(symmetric_key) > max_payload:
        raise PayloadTooLargeError(
            f"Ukuran data ({len(symmetric_key)} byte) melebihi batas muatan RSA-OAEP SHA-256 "
            f"maksimal ({max_payload} byte untuk RSA-{public_key.key_size})."
        )

    wrapped_key = public_key.encrypt(
        symmetric_key,
        get_oaep_padding(),
    )
    return wrapped_key


def unwrap_key(wrapped_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Membuka (unwrap / mendekripsi) kunci simetris yang terbungkus menggunakan private key RSA penerima.

    Args:
        wrapped_key: Data kunci terbungkus (256 byte untuk RSA-2048).
        private_key: Kunci privat milik penerima.

    Returns:
        bytes: Kunci simetris asli (misal 32 byte untuk AES-256).

    Raises:
        KeyUnwrapError: Jika private key salah atau padding OAEP rusak akibat manipulasi data.
    """
    expected_length = private_key.key_size // 8
    if len(wrapped_key) != expected_length:
        raise KeyUnwrapError(
            f"Panjang wrapped key tidak valid: {len(wrapped_key)} byte (diharapkan {expected_length} byte)."
        )

    try:
        symmetric_key = private_key.decrypt(
            wrapped_key,
            get_oaep_padding(),
        )
        return symmetric_key
    except Exception as exc:
        raise KeyUnwrapError(
            "Gagal membuka kunci (RSA-OAEP Unwrap Error)! Private key tidak sesuai atau ciphertext rusak."
        ) from exc


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Melakukan serialisasi public key ke format biner PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_to_public_key(pem_bytes: bytes) -> rsa.RSAPublicKey:
    """Memuat public key dari format PEM."""
    return serialization.load_pem_public_key(pem_bytes)


def private_key_to_pem(
    private_key: rsa.RSAPrivateKey,
    password: Optional[str] = None,
) -> bytes:
    """Melakukan serialisasi private key ke format PEM (PKCS#8)."""
    encryption_algorithm: serialization.KeySerializationEncryption
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption_algorithm = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def pem_to_private_key(
    pem_bytes: bytes,
    password: Optional[str] = None,
) -> rsa.RSAPrivateKey:
    """Memuat private key dari format PEM."""
    pwd_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)
