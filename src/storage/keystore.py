"""
Penyimpanan dan Pengelolaan Kunci Identitas Pengguna Lokal (KeyStore).

Menjamin:
- Kunci privat RSA selalu dienkripsi menggunakan kunci turunan dari passphrase (PBKDF2).
- Data identitas disimpan aman di tabel SQLite lokal `identity`.
"""

import base64
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa

from src.storage.db import DatabaseManager
from src.crypto.rsa_oaep import public_key_to_pem, pem_to_public_key
from src.crypto.kdf import encrypt_private_key, decrypt_private_key, InvalidPassphraseError
from src.crypto.fingerprint import calculate_fingerprint


class KeyStoreManager:
    """Mengelola persistensi identitas pengguna lokal dan pembukaan kunci terenkripsi."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def save_identity(
        self,
        user_id: str,
        display_name: str,
        private_key: rsa.RSAPrivateKey,
        passphrase: str,
    ) -> None:
        """
        Menyimpan profil identitas baru beserta private key yang dienkripsi dengan passphrase.
        """
        public_key = private_key.public_key()
        pub_pem = public_key_to_pem(public_key).decode("utf-8")
        
        # Enkripsi private key dengan KDF passphrase
        encrypted_blob, salt = encrypt_private_key(private_key, passphrase)
        
        enc_b64 = base64.b64encode(encrypted_blob).decode("ascii")
        salt_b64 = base64.b64encode(salt).decode("ascii")

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO identity 
                (user_id, display_name, public_key_pem, encrypted_private_key_b64, salt_b64)
                VALUES (?, ?, ?, ?, ?);
                """,
                (user_id, display_name, pub_pem, enc_b64, salt_b64),
            )
            conn.commit()

    def has_identity(self, user_id: str) -> bool:
        """Memeriksa apakah profil identitas lokal sudah dibuat."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT 1 FROM identity WHERE user_id = ?;", (user_id,)).fetchone()
            return row is not None

    def get_public_identity(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Mengambil data publik identitas (user_id, display_name, public_key_pem, fingerprint)."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT user_id, display_name, public_key_pem FROM identity WHERE user_id = ?;",
                (user_id,),
            ).fetchone()
            if not row:
                return None
            
            pub_key = pem_to_public_key(row["public_key_pem"].encode("utf-8"))
            fingerprint = calculate_fingerprint(pub_key)
            return {
                "user_id": row["user_id"],
                "display_name": row["display_name"],
                "public_key_pem": row["public_key_pem"],
                "fingerprint": fingerprint,
            }

    def load_identity(
        self,
        user_id: str,
        passphrase: str,
    ) -> Tuple[str, rsa.RSAPublicKey, rsa.RSAPrivateKey]:
        """
        Membuka kunci privat dari penyimpanan terenkripsi menggunakan passphrase pengguna.

        Returns:
            Tuple (display_name, public_key, private_key).

        Raises:
            KeyError: Jika user_id belum terdaftar di database.
            InvalidPassphraseError: Jika passphrase salah atau berkas rusak.
        """
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT display_name, public_key_pem, encrypted_private_key_b64, salt_b64
                FROM identity WHERE user_id = ?;
                """,
                (user_id,),
            ).fetchone()

        if not row:
            raise KeyError(f"Identitas lokal untuk user '{user_id}' tidak ditemukan.")

        encrypted_blob = base64.b64decode(row["encrypted_private_key_b64"])
        salt = base64.b64decode(row["salt_b64"])
        pub_key = pem_to_public_key(row["public_key_pem"].encode("utf-8"))

        private_key = decrypt_private_key(encrypted_blob, salt, passphrase)
        return row["display_name"], pub_key, private_key
