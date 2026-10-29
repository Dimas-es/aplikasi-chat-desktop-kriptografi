"""
Direktori Kunci Publik Sederhana pada Relay Server (Key Registry).

Menyimpan pasangan (user_id -> public_key_pem) untuk memfasilitasi pertukaran kunci
antar-klien yang terhubung pada jaringan lokal.
"""

from typing import Dict, Optional, List


class KeyRegistry:
    """Penyimpanan direktori kunci publik in-memory pada relay server."""

    def __init__(self):
        self._keys: Dict[str, str] = {}

    def register_key(self, user_id: str, public_key_pem: str) -> bool:
        """Mendaftarkan atau memperbarui kunci publik untuk user_id tertentu."""
        clean_uid = user_id.strip().lower()
        if not clean_uid or not public_key_pem:
            return False
        self._keys[clean_uid] = public_key_pem.strip()
        return True

    def get_key(self, user_id: str) -> Optional[str]:
        """Mengambil kunci publik PEM untuk user_id tertentu."""
        clean_uid = user_id.strip().lower()
        return self._keys.get(clean_uid)

    def list_users(self) -> List[str]:
        """Mendaftar seluruh user_id yang telah mendaftarkan kunci publik."""
        return sorted(list(self._keys.keys()))

    def clear(self) -> None:
        """Mengosongkan seluruh direktori kunci."""
        self._keys.clear()
