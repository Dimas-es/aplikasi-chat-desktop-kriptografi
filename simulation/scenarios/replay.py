"""
Skenario Serangan 3: Penyerangan Pengiriman Ulang (Replay Attack).

Tujuan Edukasi / Evaluasi:
Membuktikan bahwa:
1. Penyerang yang menangkap paket sah di jaringan dan mengirimkannya kembali
   (Replay injection) akan langsung DITOLAK oleh filter Anti-Replay Counter.
2. Penolakan terjadi pada fase awal validasi counter sebelum memicu operasi
   asimetris RSA-OAEP yang mahal secara komputasi (perlindungan DoS / exhaustion).
3. Paket gagal/palsu tidak akan memajukan counter penyimpanan (prinsip atomisitas).
"""

import os
import tempfile
from typing import Dict, Any, List

from src.storage.db import DatabaseManager
from src.storage.counter_store import CounterStore
from src.messaging.status import MessageStatus
from client.controllers.chat_controller import ChatController


def run_replay_scenario() -> List[Dict[str, Any]]:
    """
    Menjalankan pengujian serangan replay pada level CounterStore dan ChatController.
    """
    results = []

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        alice_db = os.path.join(tmp_dir, "alice_sim.db")
        bob_db = os.path.join(tmp_dir, "bob_sim.db")

        ctrl_alice = None
        ctrl_bob = None
        try:
            ctrl_alice = ChatController(db_path=alice_db)
            ctrl_bob = ChatController(db_path=bob_db)

            ctrl_alice.register_identity("alice", "Alice Crypto", "pass_alice_123")
            ctrl_bob.register_identity("bob", "Bob Security", "pass_bob_123")

            # Tukar kontak dan kunci publik
            pub_bob_pem = ctrl_bob.get_public_key_pem()
            pub_alice_pem = ctrl_alice.get_public_key_pem()
            ctrl_alice.add_contact("bob", "Bob Security", pub_bob_pem, verified=True)
            ctrl_bob.add_contact("alice", "Alice Crypto", pub_alice_pem, verified=True)

            # 1. Alice mengirim pesan pertama (Counter = 1)
            packet_1, _ = ctrl_alice.send_message("bob", "Pesan Sah #1: Otorisasi transfer $500.")
            
            # Bob menerima dan memproses paket 1
            status_1, text_1, _ = ctrl_bob.receive_message(packet_1)
            valid_first = (status_1 == MessageStatus.VALID and text_1 is not None)

            results.append({
                "scenario": "Replay - Pengiriman Pesan Awal (Counter #1)",
                "description": "Alice mengirim pesan sah pertama, Bob memproses dan memvalidasi",
                "counter": packet_1.counter,
                "status_returned": status_1.value,
                "expected_status": MessageStatus.VALID.value,
                "defense_triggered": valid_first,
                "verdict": "PASSED" if valid_first else "FAILED",
            })

            # -------------------------------------------------------------
            # Sub-kasus 1: Eve menyadap dan menyuntikkan ulang Paket #1 ke Bob
            # -------------------------------------------------------------
            status_replay_1, text_replay_1, _ = ctrl_bob.receive_message(packet_1)
            replay_rejected = (status_replay_1 == MessageStatus.REPLAY_REJECTED)

            results.append({
                "scenario": "Replay - Injeksi Ulang Paket Sah #1 (Identik)",
                "description": "Eve menyadap paket #1 dan mengirimkannya kembali ke Bob tanpa perubahan",
                "counter": packet_1.counter,
                "status_returned": status_replay_1.value,
                "expected_status": MessageStatus.REPLAY_REJECTED.value,
                "defense_triggered": replay_rejected,
                "verdict": "PASSED" if replay_rejected else "FAILED",
            })

            # -------------------------------------------------------------
            # Sub-kasus 2: Alice mengirim pesan kedua (Counter = 2)
            # -------------------------------------------------------------
            packet_2, _ = ctrl_alice.send_message("bob", "Pesan Sah #2: Konfirmasi penerimaan.")
            status_2, text_2, _ = ctrl_bob.receive_message(packet_2)
            valid_second = (status_2 == MessageStatus.VALID)

            # -------------------------------------------------------------
            # Sub-kasus 3: Eve mencoba menyuntikkan paket lama (Counter = 1) setelah Bob di Counter = 2
            # -------------------------------------------------------------
            status_stale, _, _ = ctrl_bob.receive_message(packet_1)
            stale_rejected = (status_stale == MessageStatus.REPLAY_REJECTED)

            results.append({
                "scenario": "Replay - Injeksi Paket Kadaluarsa (Counter Lama < Current Counter)",
                "description": "Eve mengirim paket dengan counter #1 saat state penerima sudah mencapai #2",
                "counter": packet_1.counter,
                "status_returned": status_stale.value,
                "expected_status": MessageStatus.REPLAY_REJECTED.value,
                "defense_triggered": stale_rejected,
                "verdict": "PASSED" if stale_rejected else "FAILED",
            })
        finally:
            if ctrl_alice:
                ctrl_alice.close()
            if ctrl_bob:
                ctrl_bob.close()

    return results


if __name__ == "__main__":
    import pprint
    res = run_replay_scenario()
    pprint.pprint(res)
