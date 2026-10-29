"""
Aplikasi Utama Desktop Klien (App Orchestrator).
"""

import customtkinter as ctk
from typing import Optional

from client.controllers.chat_controller import ChatController
from client.ui.key_dialog import IdentityDialog
from client.ui.chat_window import ChatWindow
from src.messaging.packet import MessagePacket
from src.network.relay_client import RelayClient


class CryptoChatApp:
    """Orkestrator siklus hidup aplikasi desktop chat kripto."""

    def __init__(
        self,
        user_id: str = "alice",
        db_path: Optional[str] = None,
        relay_host: str = "127.0.0.1",
        relay_port: int = 8000,
        enable_network: bool = True,
    ):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title(f"Chat Kripto Desktop (AES-GCM & RSA-OAEP) - [{user_id.upper()}]")
        self.root.geometry("1180x680")
        self.root.minsize(980, 560)

        # Inisialisasi controller
        actual_db_path = db_path or f"data/{user_id}.db"
        self.controller = ChatController(db_path=actual_db_path)
        self.user_id = user_id
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.enable_network = enable_network

        self.relay_client: Optional[RelayClient] = None
        self.chat_window: Optional[ChatWindow] = None

        # Mulai alur autentikasi / bootstrap identitas
        self.root.after(100, self._start_auth_flow)

    def _start_auth_flow(self):
        """Memeriksa apakah identitas sudah pernah dibuat atau perlu didaftarkan."""
        is_first_time = not self.controller.keystore.has_identity(self.user_id)

        def on_auth_success(uid, dname, passphrase, r_host=None, r_port=None):
            if r_host:
                self.relay_host = r_host
            if r_port:
                try:
                    self.relay_port = int(r_port)
                except ValueError:
                    pass

            if is_first_time:
                self.controller.register_identity(uid, dname, passphrase)
            else:
                self.controller.login_identity(uid, passphrase)
            
            # 1. Tampilkan jendela obrolan utama terlebih dahulu agar siap menerima paket
            self._launch_chat_window()

            # 2. Setup jaringan setelah UI siap (mencegah incoming packet hilang saat connect)
            if self.enable_network:
                self._setup_network()

        IdentityDialog(
            parent=self.root,
            user_id=self.user_id,
            is_first_time=is_first_time,
            on_success=on_auth_success,
            default_relay_host=self.relay_host,
            default_relay_port=self.relay_port,
        )

    def _setup_network(self):
        """Membuka koneksi ke Relay Server jika tersedia di latar belakang."""
        def on_incoming_packet(packet: MessagePacket):
            # Dispatch thread-safe ke main UI loop Tkinter
            if self.chat_window:
                self.root.after(0, lambda: self.chat_window.handle_incoming_packet(packet))

        try:
            self.relay_client = RelayClient(
                host=self.relay_host,
                port=self.relay_port,
                user_id=self.user_id,
                on_incoming_packet=on_incoming_packet,
            )
            connected = self.relay_client.connect(timeout=2.0)
            if connected:
                print(f"[*] Berhasil terhubung ke relay server di {self.relay_host}:{self.relay_port}")
                # Otomatis publikasikan public key ke direktori relay
                pub_pem = self.controller.get_public_key_pem()
                self.relay_client.publish_key(pub_pem)
            else:
                print("[!] Relay server tidak aktif. Berjalan dalam mode simulasi lokal.")
        except Exception as exc:
            print(f"[!] Jaringan relay offline: {exc}. Mode lokal aktif.")

    def _on_send_network(self, packet: MessagePacket):
        """Dipanggil saat tombol kirim di UI ditekan."""
        if self.relay_client and self.relay_client.is_connected:
            self.relay_client.send_packet(packet)

    def _launch_chat_window(self):
        """Menampilkan antarmuka obrolan utama setelah private key berhasil dibuka."""
        self.chat_window = ChatWindow(
            parent=self.root,
            controller=self.controller,
            on_send_network_packet=self._on_send_network,
        )
        self.chat_window.pack(fill="both", expand=True)

    def run(self):
        """Menjalankan main event loop Tkinter."""
        try:
            self.root.mainloop()
        finally:
            if self.relay_client:
                self.relay_client.disconnect()

