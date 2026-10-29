"""
Antrean Paket Ciphertext Tertunda pada Relay Server (RelayQueue).

Menampung paket JSON v1 untuk penerima yang sedang offline atau belum mengambil pesan.
Bersifat zero-knowledge: antrean hanya menyimpan ciphertext tanpa tahu isi pesan.
"""

from typing import Dict, List, Any
from datetime import datetime


class RelayQueue:
    """Pengelola antrean pesan sementara berbasis memori."""

    def __init__(self):
        # Struktur: {receiver_id: [ {"packet": dict, "received_at": str}, ... ]}
        self._queues: Dict[str, List[Dict[str, Any]]] = {}

    def enqueue(self, receiver_id: str, packet_data: Dict[str, Any]) -> int:
        """Menambahkan paket ke dalam antrean penerima."""
        clean_rid = receiver_id.strip().lower()
        if clean_rid not in self._queues:
            self._queues[clean_rid] = []

        entry = {
            "packet": packet_data,
            "received_at": datetime.now().isoformat(),
        }
        self._queues[clean_rid].append(entry)
        return len(self._queues[clean_rid])

    def dequeue_all(self, receiver_id: str) -> List[Dict[str, Any]]:
        """Mengambil dan menghapus seluruh paket tertunda untuk penerima tertentu."""
        clean_rid = receiver_id.strip().lower()
        items = self._queues.pop(clean_rid, [])
        return items

    def peek_count(self, receiver_id: str) -> int:
        """Melihat jumlah pesan yang sedang antre untuk penerima."""
        clean_rid = receiver_id.strip().lower()
        return len(self._queues.get(clean_rid, []))

    def clear(self) -> None:
        """Mengosongkan antrean seluruh penerima."""
        self._queues.clear()
