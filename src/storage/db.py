"""
Pengelola Basis Data SQLite Lokal untuk Klien Chat Desktop.

Menyediakan inisialisasi skema tabel:
- identity: Menyimpan data profil lokal dan kunci privat terenkripsi.
- contacts: Menyimpan buku kontak, public key lawan bicara, dan status verifikasi fingerprint.
- counter_state: Menyimpan state counter anti-replay secara atomik dan crash-consistent.
"""

import sqlite3
import os
from typing import Optional


class DatabaseManager:
    """Mengelola koneksi SQLite dan inisialisasi tabel lokal."""

    def __init__(self, db_path: str = "data/client.db"):
        self.db_path = db_path
        self._open_conns = []
        # Buat direktori parent jika belum ada
        dir_name = os.path.dirname(db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        """Membuka koneksi baru dengan pengaktifan Write-Ahead Logging (WAL) dan Foreign Keys."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Mode WAL menjamin performa tinggi dan crash consistency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        self._open_conns.append(conn)
        return conn

    def close(self) -> None:
        """Menutup seluruh koneksi aktif ke berkas database."""
        for conn in self._open_conns:
            try:
                conn.close()
            except Exception:
                pass
        self._open_conns.clear()

    def init_schema(self) -> None:
        """Membuat tabel jika belum tersedia."""
        with self.get_connection() as conn:
            # 1. Tabel Identitas Lokal
            conn.execute("""
                CREATE TABLE IF NOT EXISTS identity (
                    user_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    encrypted_private_key_b64 TEXT NOT NULL,
                    salt_b64 TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Tabel Kontak Lawan Bicara
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    contact_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 3. Tabel State Counter Anti-Replay
            conn.execute("""
                CREATE TABLE IF NOT EXISTS counter_state (
                    contact_id TEXT PRIMARY KEY,
                    last_sent_counter INTEGER DEFAULT 0,
                    highest_received_counter INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
