"""
Pengarah Lalu Lintas Paket dan Sesi Klien pada Relay Server (RelayRouter).
"""

import json
from typing import Dict, Any, Optional, Callable
from relay.registry import KeyRegistry
from relay.queue import RelayQueue


class RelayRouter:
    """Mengatur perutean pesan antar klien aktif atau ke antrean tertunda."""

    def __init__(self):
        self.registry = KeyRegistry()
        self.queue = RelayQueue()
        # Pemetaan sesi aktif: {user_id: send_callback_fn}
        self.active_sessions: Dict[str, Callable[[str], None]] = {}
        # Sesi penyadap aktif (Sniffer / Eavesdropper tap)
        self.sniffers: list = []

    def register_client_session(self, user_id: str, sender_fn: Callable[[str], None]) -> None:
        """Mencatat koneksi soket aktif pengguna untuk pengiriman real-time."""
        clean_uid = user_id.strip().lower()
        self.active_sessions[clean_uid] = sender_fn

    def unregister_client_session(self, user_id: str) -> None:
        """Menghapus sesi saat klien terputus."""
        clean_uid = user_id.strip().lower()
        fn = self.active_sessions.pop(clean_uid, None)
        if fn and fn in self.sniffers:
            self.sniffers.remove(fn)

    def handle_request(self, raw_message: str, client_sender_fn: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """
        Memproses pesan protokol JSON dari klien dan mengembalikan respons JSON.
        """
        try:
            req = json.loads(raw_message.strip())
        except Exception as exc:
            return {"status": "ERROR", "message": f"Sintaks JSON tidak valid: {exc}"}

        action = req.get("action", "").upper()

        # 1. Pendaftaran / Publikasi Kunci Publik
        if action == "PUBLISH_KEY":
            uid = req.get("user_id", "")
            pub_pem = req.get("public_key", "")
            if not uid or not pub_pem:
                return {"status": "ERROR", "message": "user_id dan public_key wajib diisi."}
            self.registry.register_key(uid, pub_pem)
            return {"status": "OK", "action": "PUBLISH_KEY", "user_id": uid.lower(), "message": "Kunci berhasil terdaftar."}

        # 2. Pengambilan Kunci Publik Lawan Bicara
        elif action == "GET_KEY":
            uid = req.get("user_id", "")
            pub_pem = self.registry.get_key(uid)
            if not pub_pem:
                return {"status": "ERROR", "action": "GET_KEY", "user_id": uid, "message": "User ID tidak ditemukan di direktori."}
            return {"status": "OK", "action": "GET_KEY", "user_id": uid.lower(), "public_key": pub_pem}

        # 3. Mendaftar Semua Pengguna Terdaftar
        elif action == "LIST_USERS":
            users = self.registry.list_users()
            return {"status": "OK", "action": "LIST_USERS", "users": users}

        # 4. Identifikasi Sesi Soket Aktif
        elif action == "IDENTIFY":
            uid = req.get("user_id", "")
            if uid and client_sender_fn:
                self.register_client_session(uid, client_sender_fn)
                # Kirimkan pesan yang tertunda jika ada di antrean
                pending = self.queue.dequeue_all(uid)
                if pending:
                    for item in pending:
                        push_msg = json.dumps({"action": "INCOMING_PACKET", "packet": item["packet"]}) + "\n"
                        client_sender_fn(push_msg)
                return {"status": "OK", "action": "IDENTIFY", "user_id": uid.lower(), "pending_count": len(pending)}
            return {"status": "ERROR", "message": "Gagal identifikasi sesi."}

        # 5. Pengiriman Paket Pesan (SEND)
        elif action == "SEND":
            packet_data = req.get("packet")
            if not packet_data or not isinstance(packet_data, dict):
                return {"status": "ERROR", "message": "Field packet wajib disertakan dalam format dictionary."}

            receiver = str(packet_data.get("receiver", "")).strip().lower()
            if not receiver:
                return {"status": "ERROR", "message": "Paket tidak memuat receiver yang valid."}

            # Tembusan real-time ke sniffer / konsol hacker (jika ada yang menyadap)
            for sniffer_fn in list(self.sniffers):
                try:
                    sniff_msg = json.dumps({"action": "SNIFFED_PACKET", "packet": packet_data}) + "\n"
                    sniffer_fn(sniff_msg)
                except Exception:
                    if sniffer_fn in self.sniffers:
                        self.sniffers.remove(sniffer_fn)

            # Cek apakah penerima sedang terhubung secara aktif
            receiver_sender_fn = self.active_sessions.get(receiver)
            if receiver_sender_fn:
                # Teruskan langsung (Real-time push)
                push_msg = json.dumps({"action": "INCOMING_PACKET", "packet": packet_data}) + "\n"
                try:
                    receiver_sender_fn(push_msg)
                    return {"status": "OK", "action": "SEND", "delivered": True, "queued": False}
                except Exception:
                    # Jika gagal kirim via socket, simpan ke antrean
                    self.queue.enqueue(receiver, packet_data)
                    return {"status": "OK", "action": "SEND", "delivered": False, "queued": True}
            else:
                # Penerima offline -> simpan ke antrean
                q_len = self.queue.enqueue(receiver, packet_data)
                return {"status": "OK", "action": "SEND", "delivered": False, "queued": True, "queue_length": q_len}

        # 6. Pengambilan Pesan Tertunda Manual (FETCH)
        elif action == "FETCH":
            uid = req.get("user_id", "").strip().lower()
            if not uid:
                return {"status": "ERROR", "message": "user_id wajib diisi untuk FETCH."}
            items = self.queue.dequeue_all(uid)
            return {"status": "OK", "action": "FETCH", "count": len(items), "messages": [i["packet"] for i in items]}

        # 7. Registrasi Sesi Sniffer / Sadap Paket
        elif action == "REGISTER_SNIFFER":
            if client_sender_fn and client_sender_fn not in self.sniffers:
                self.sniffers.append(client_sender_fn)
            return {"status": "OK", "action": "REGISTER_SNIFFER", "message": "Mode penyadap (sniffer) aktif."}

        else:
            return {"status": "ERROR", "message": f"Action '{action}' tidak dikenal."}
