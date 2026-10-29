"""
Pengelolaan Buku Kontak dan Verifikasi Kunci Publik Lawan Bicara (ContactStore).
"""

from typing import Optional, List, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa

from src.storage.db import DatabaseManager
from src.crypto.rsa_oaep import pem_to_public_key
from src.crypto.fingerprint import calculate_fingerprint


class ContactStore:
    """Mengelola data kontak rekan percakapan dan status verifikasi fingerprint."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def save_contact(
        self,
        contact_id: str,
        display_name: str,
        public_key_pem: str,
        verified: bool = False,
    ) -> str:
        """
        Menyimpan atau memperbarui kontak lawan bicara dan menghitung nilai fingerprint otomatis.

        Returns:
            str: Fingerprint SHA-256 dari kunci publik kontak tersebut.
        """
        # Validasi PEM dan hitung fingerprint
        pub_key = pem_to_public_key(public_key_pem.encode("utf-8"))
        fingerprint = calculate_fingerprint(pub_key)

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO contacts 
                (contact_id, display_name, public_key_pem, fingerprint, verified, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
                """,
                (contact_id, display_name, public_key_pem, fingerprint, 1 if verified else 0),
            )
            conn.commit()
        return fingerprint

    def get_contact(self, contact_id: str) -> Optional[Dict[str, Any]]:
        """Mengambil data kontak berdasarkan contact_id."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT contact_id, display_name, public_key_pem, fingerprint, verified, updated_at
                FROM contacts WHERE contact_id = ?;
                """,
                (contact_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "contact_id": row["contact_id"],
                "display_name": row["display_name"],
                "public_key_pem": row["public_key_pem"],
                "fingerprint": row["fingerprint"],
                "verified": bool(row["verified"]),
                "updated_at": row["updated_at"],
            }

    def get_public_key(self, contact_id: str) -> rsa.RSAPublicKey:
        """Mengambil objek RSA Public Key dari kontak untuk keperluan enkripsi."""
        contact = self.get_contact(contact_id)
        if not contact:
            raise KeyError(f"Kontak '{contact_id}' tidak ditemukan di buku kontak lokal.")
        return pem_to_public_key(contact["public_key_pem"].encode("utf-8"))

    def set_verified(self, contact_id: str, verified: bool = True) -> None:
        """Menyetel status verifikasi fingerprint out-of-band."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE contacts SET verified = ?, updated_at = CURRENT_TIMESTAMP WHERE contact_id = ?;",
                (1 if verified else 0, contact_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Kontak '{contact_id}' tidak ditemukan untuk diupdate statusnya.")
            conn.commit()

    def list_contacts(self) -> List[Dict[str, Any]]:
        """Mendaftar semua kontak yang tersimpan."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT contact_id, display_name, public_key_pem, fingerprint, verified, updated_at FROM contacts ORDER BY display_name ASC;"
            ).fetchall()
            return [
                {
                    "contact_id": r["contact_id"],
                    "display_name": r["display_name"],
                    "public_key_pem": r["public_key_pem"],
                    "fingerprint": r["fingerprint"],
                    "verified": bool(r["verified"]),
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]

    def delete_contact(self, contact_id: str) -> None:
        """Menghapus kontak dari database."""
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM contacts WHERE contact_id = ?;", (contact_id,))
            conn.commit()
