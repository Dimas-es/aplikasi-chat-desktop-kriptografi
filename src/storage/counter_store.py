"""
Pengelolaan State Counter Anti-Replay Atomik dan Crash-Consistent (CounterStore).

Menerapkan aturan konsistensi dokumen 04 - ARSITEKTUR dan 06 - WORKFLOW:
- Pengirim: last_sent_counter bertambah monotonik setiap mengirim pesan baru.
- Penerima: can_accept_counter() menolak jika counter <= highest_received_counter.
- ATURAN KRITIS: highest_received_counter HANYA di-commit ke disk setelah
  seluruh proses verifikasi tag AES-GCM terbukti sukses (mencegah DoS spoofed counter).
"""

from src.storage.db import DatabaseManager


class CounterStore:
    """Mengelola counter pengiriman dan counter anti-replay penerimaan per kontak."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def _ensure_entry(self, contact_id: str) -> None:
        """Memastikan entri counter_state untuk contact_id telah dibuat."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO counter_state 
                (contact_id, last_sent_counter, highest_received_counter)
                VALUES (?, 0, 0);
                """,
                (contact_id,),
            )
            conn.commit()

    def get_next_sent_counter(self, contact_id: str) -> int:
        """
        Menaikkan last_sent_counter secara atomik dan mengembalikan nomor counter baru untuk pengiriman.
        """
        self._ensure_entry(contact_id)
        with self.db.get_connection() as conn:
            # Gunakan transaksi atomik
            cursor = conn.execute(
                """
                UPDATE counter_state 
                SET last_sent_counter = last_sent_counter + 1, updated_at = CURRENT_TIMESTAMP
                WHERE contact_id = ?
                RETURNING last_sent_counter;
                """,
                (contact_id,),
            )
            new_counter = cursor.fetchone()[0]
            conn.commit()
            return int(new_counter)

    def get_highest_received_counter(self, contact_id: str) -> int:
        """Mengambil nilai counter tertinggi yang pernah sah diterima dari kontak ini."""
        self._ensure_entry(contact_id)
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT highest_received_counter FROM counter_state WHERE contact_id = ?;",
                (contact_id,),
            ).fetchone()
            return int(row["highest_received_counter"]) if row else 0

    def can_accept_counter(self, contact_id: str, incoming_counter: int) -> bool:
        """
        Memeriksa apakah counter paket masuk memenuhi syarat anti-replay (counter > highest_received_counter).
        Tidak mengubah state apapun di database.
        """
        highest = self.get_highest_received_counter(contact_id)
        return incoming_counter > highest

    def commit_received_counter(self, contact_id: str, verified_counter: int) -> None:
        """
        Menyimpan counter yang telah diverifikasi secara permanen ke disk.
        PERINGATAN: Fungsi ini HANYA boleh dipanggil setelah dekripsi AES-GCM terbukti VALID!
        """
        self._ensure_entry(contact_id)
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE counter_state 
                SET highest_received_counter = MAX(highest_received_counter, ?),
                    updated_at = CURRENT_TIMESTAMP
                WHERE contact_id = ?;
                """,
                (verified_counter, contact_id),
            )
            conn.commit()

    def get_state(self, contact_id: str) -> dict:
        """Mengembalikan dictionary state counter lengkap."""
        self._ensure_entry(contact_id)
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT last_sent_counter, highest_received_counter, updated_at FROM counter_state WHERE contact_id = ?;",
                (contact_id,),
            ).fetchone()
            return {
                "contact_id": contact_id,
                "last_sent_counter": int(row["last_sent_counter"]),
                "highest_received_counter": int(row["highest_received_counter"]),
                "updated_at": row["updated_at"],
            }
