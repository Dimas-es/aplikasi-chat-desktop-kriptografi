"""
Aplikasi Konsol Penyadapan & Simulasi Serangan (Eve the Hacker).

Menyediakan antarmuka grafis (GUI) bertema hacker / cybersecurity untuk:
1. Menyadap paket ciphertext yang melintas di jaringan antara Bob dan Alice secara real-time.
2. Mencoba mendekripsi paket curian (dan membuktikan kegagalannya karena tidak punya kunci privat Alice).
3. Melakukan injeksi serangan Man-in-the-Middle (Tampering, Replay, dan Spoofing) secara independen.

Penggunaan:
    python -m client.eve_hacker --host 127.0.0.1 --port 8000
"""

import sys
import json
import socket
import threading
import argparse
from typing import Optional, Dict, Any
from datetime import datetime

import customtkinter as ctk

from src.messaging.packet import MessagePacket
from src.crypto.rsa_oaep import generate_rsa_keypair, unwrap_key, KeyUnwrapError
from src.crypto.aes_gcm import decrypt_aes_gcm, AuthenticationError
from src.messaging.aad import build_canonical_aad


class EveHackerApp:
    """Aplikasi GUI Konsol Penyadapan Eve."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.root = ctk.CTk()
        self.root.title("☠️ [EVE] - KONSOL PENYADAPAN JARINGAN & MAN-IN-THE-MIDDLE")
        self.root.geometry("980x700")
        self.root.minsize(860, 600)

        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.is_connected = False
        self.listen_thread: Optional[threading.Thread] = None

        # Kunci RSA milik Eve sendiri (bukan kunci Alice/Bob)
        self.eve_priv_key, self.eve_pub_key = generate_rsa_keypair(key_size=2048)

        # Paket terakhir yang berhasil disadap
        self.stolen_packet: Optional[MessagePacket] = None

        self._build_ui()
        self.root.after(200, self.connect_to_relay)

    def _build_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)

        # -------------------------------------------------------------
        # 1. HEADER / STATUS BAR PENYADAP
        # -------------------------------------------------------------
        header = ctk.CTkFrame(self.root, fg_color="#181818", corner_radius=0, height=65)
        header.grid(row=0, column=0, sticky="ew")

        title_lbl = ctk.CTkLabel(
            header,
            text="💀 EVE THE SNIFFER // KONSOL PENYADAPAN MAN-IN-THE-MIDDLE",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color="#FF4C4C",
        )
        title_lbl.pack(side="left", padx=20, pady=15)

        self.status_lbl = ctk.CTkLabel(
            header,
            text="🔴 TERPUTUS DARI RELAY",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#E74C3C",
        )
        self.status_lbl.pack(side="right", padx=20, pady=15)

        # -------------------------------------------------------------
        # 2. PANEL DATA SADAPAN (INTERCEPTED PACKET)
        # -------------------------------------------------------------
        inspect_frame = ctk.CTkFrame(self.root, fg_color="#1F1F1F", corner_radius=8)
        inspect_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(15, 5))

        inspect_header = ctk.CTkFrame(inspect_frame, fg_color="transparent")
        inspect_header.pack(fill="x", padx=15, pady=(10, 5))

        ctk.CTkLabel(
            inspect_header,
            text="📡 PAKET TERAKHIR YANG BERHASIL DICEGAT DI JARINGAN:",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color="#2ECC71",
        ).pack(side="left")

        self.pkt_meta_lbl = ctk.CTkLabel(
            inspect_header,
            text="[Menunggu lalu lintas data antara Bob & Alice...]",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#95A5A6",
        )
        self.pkt_meta_lbl.pack(side="right")

        # Rincian Field Biner (Hex Display)
        hex_grid = ctk.CTkFrame(inspect_frame, fg_color="#121212", corner_radius=6)
        hex_grid.pack(fill="x", padx=15, pady=(5, 12))

        # Row 1: Ciphertext & Tag
        ct_row = ctk.CTkFrame(hex_grid, fg_color="transparent")
        ct_row.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(ct_row, text="CIPHERTEXT :", width=120, anchor="w", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#F39C12").pack(side="left")
        self.lbl_ct = ctk.CTkLabel(ct_row, text="-", anchor="w", font=ctk.CTkFont(family="Consolas", size=11), text_color="#BDC3C7")
        self.lbl_ct.pack(side="left", fill="x", expand=True)

        tag_row = ctk.CTkFrame(hex_grid, fg_color="transparent")
        tag_row.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(tag_row, text="AUTH TAG   :", width=120, anchor="w", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#E67E22").pack(side="left")
        self.lbl_tag = ctk.CTkLabel(tag_row, text="-", anchor="w", font=ctk.CTkFont(family="Consolas", size=11), text_color="#BDC3C7")
        self.lbl_tag.pack(side="left", fill="x", expand=True)

        # Row 2: Wrapped Key & Nonce
        wk_row = ctk.CTkFrame(hex_grid, fg_color="transparent")
        wk_row.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(wk_row, text="WRAPPED KEY:", width=120, anchor="w", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#9B59B6").pack(side="left")
        self.lbl_wk = ctk.CTkLabel(wk_row, text="-", anchor="w", font=ctk.CTkFont(family="Consolas", size=11), text_color="#BDC3C7")
        self.lbl_wk.pack(side="left", fill="x", expand=True)

        sig_row = ctk.CTkFrame(hex_grid, fg_color="transparent")
        sig_row.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(sig_row, text="SIGNATURE  :", width=120, anchor="w", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#3498DB").pack(side="left")
        self.lbl_sig = ctk.CTkLabel(sig_row, text="-", anchor="w", font=ctk.CTkFont(family="Consolas", size=11), text_color="#BDC3C7")
        self.lbl_sig.pack(side="left", fill="x", expand=True)

        # -------------------------------------------------------------
        # 3. TOMBOL AKSI SERANGAN HACKER (ACTION PANEL)
        # -------------------------------------------------------------
        action_frame = ctk.CTkFrame(self.root, fg_color="#222222", corner_radius=8)
        action_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=5)

        act_title = ctk.CTkLabel(
            action_frame,
            text="⚡ OPERASI SERANGAN PENYADAP (PILIH AKSI):",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#E74C3C",
        )
        act_title.pack(anchor="w", padx=15, pady=(10, 6))

        btn_bar = ctk.CTkFrame(action_frame, fg_color="transparent")
        btn_bar.pack(fill="x", padx=15, pady=(0, 12))

        # Tombol 1: Coba Dekripsi (Membuktikan ketidakmampuan membongkar pesan)
        self.btn_decrypt = ctk.CTkButton(
            btn_bar,
            text="🔓 1. Coba Buka Isi Pesan\n(Gunakan Kunci Eve)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#34495E",
            hover_color="#2C3E50",
            height=42,
            state="disabled",
            command=self._action_try_decrypt,
        )
        self.btn_decrypt.pack(side="left", fill="x", expand=True, padx=4)

        # Tombol 2: Manipulasi Ciphertext (Tamper Attack)
        self.btn_tamper = ctk.CTkButton(
            btn_bar,
            text="⚡ 2. Rusak 1 Byte Pesan\n(Kirim Tamper ke Alice)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#922B21",
            hover_color="#7B241C",
            height=42,
            state="disabled",
            command=self._action_tamper_attack,
        )
        self.btn_tamper.pack(side="left", fill="x", expand=True, padx=4)

        # Tombol 3: Replay Attack (Suntik Ulang)
        self.btn_replay = ctk.CTkButton(
            btn_bar,
            text="🔁 3. Kirim Ulang Paket Asli\n(Uji Replay ke Alice)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#6C3483",
            hover_color="#512E5F",
            height=42,
            state="disabled",
            command=self._action_replay_attack,
        )
        self.btn_replay.pack(side="left", fill="x", expand=True, padx=4)

        # Tombol 4: Palsukan Tanda Tangan (Spoofing)
        self.btn_spoof = ctk.CTkButton(
            btn_bar,
            text="✍️ 4. Palsukan Signature\n(Kirim Spoof ke Alice)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#B7950B",
            hover_color="#7D6608",
            height=42,
            state="disabled",
            command=self._action_spoof_attack,
        )
        self.btn_spoof.pack(side="left", fill="x", expand=True, padx=4)

        # -------------------------------------------------------------
        # 4. TERMINAL LOG EVE (HACKER CONSOLE OUTPUT)
        # -------------------------------------------------------------
        log_frame = ctk.CTkFrame(self.root, fg_color="#141414", corner_radius=8)
        log_frame.grid(row=3, column=0, sticky="nsew", padx=15, pady=(5, 15))
        self.root.grid_rowconfigure(3, weight=1)

        log_hdr = ctk.CTkLabel(
            log_frame,
            text="💻 TERMINAL AKTIVITAS PENYADAPAN (LIVE LOG):",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color="#7F8C8D",
            anchor="w",
        )
        log_hdr.pack(fill="x", padx=15, pady=(8, 2))

        self.log_box = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0A0A0A",
            text_color="#2ECC71",
            corner_radius=4,
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _log(self, text: str, color_tag: str = "INFO"):
        """Menambahkan log baris baru ke terminal hacker."""
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{ts}] "
        self.log_box.insert("end", f"{prefix}{text}\n")
        self.log_box.see("end")

    # =============================================================
    # JARINGAN & PENYADAPAN
    # =============================================================
    def connect_to_relay(self):
        """Membuka koneksi soket ke Relay Server dan mendaftarkan mode sniffer."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.is_connected = True

            # 1. Identifikasi diri sebagai Eve
            self._send_raw({"action": "IDENTIFY", "user_id": "eve"})

            # 2. Aktifkan mode sadap (SNIFFER TAP)
            self._send_raw({"action": "REGISTER_SNIFFER"})

            self.status_lbl.configure(text="🟢 MENYADAP JARINGAN (EVE ONLINE)", text_color="#2ECC71")
            self._log(f"Berhasil menyusup ke Relay Server di {self.host}:{self.port}!")
            self._log("Mode SNIFFER aktif. Menunggu paket obrolan antara Bob dan Alice...")

            # Mulai thread pendengar paket masuk
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()

        except Exception as exc:
            self.status_lbl.configure(text="🔴 GAGAL KONEKSI KE RELAY", text_color="#E74C3C")
            self._log(f"Gagal menyambung ke relay: {exc}. Pastikan relay server aktif di {self.host}:{self.port}!")

    def _send_raw(self, msg_dict: Dict[str, Any]):
        """Mengirim pesan baris JSON ke relay server."""
        if self.socket and self.is_connected:
            line = json.dumps(msg_dict) + "\n"
            self.socket.sendall(line.encode("utf-8"))

    def _listen_loop(self):
        """Menerima aliran data dari relay server di latar belakang."""
        buffer = ""
        while self.is_connected and self.socket:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    self._handle_server_line(line)
            except Exception:
                break

        self.is_connected = False
        self.root.after(0, lambda: self.status_lbl.configure(text="🔴 KONEKSI TERPUTUS", text_color="#E74C3C"))

    def _handle_server_line(self, line: str):
        try:
            msg = json.loads(line)
            action = msg.get("action")
            status = msg.get("status")

            if status == "ERROR":
                err_text = msg.get("message", "Galat server tidak diketahui")
                self.root.after(0, lambda: self._log(f"⚠️ [Peringatan Relay] {err_text}"))

            if action == "SNIFFED_PACKET":
                pkt_data = msg.get("packet")
                if pkt_data:
                    # Dispatch thread-safe ke Tkinter
                    self.root.after(0, lambda: self._on_packet_intercepted(pkt_data))
            elif action == "REGISTER_SNIFFER" and status == "OK":
                self.root.after(0, lambda: self._log("✅ Konfirmasi Relay: Penyadapan berhasil terpasang di router!"))

        except Exception as exc:
            print(f"[Eve] Error parsing line: {exc}")

    def _on_packet_intercepted(self, pkt_data: Dict[str, Any]):
        """Dipanggil saat paket pesan Bob -> Alice berhasil dicegat."""
        try:
            packet = MessagePacket.from_dict(pkt_data)
            self.stolen_packet = packet

            # Update Metadata Label
            self.pkt_meta_lbl.configure(
                text=f"🎯 DICEGAT: Dari @{packet.sender} ➔ @{packet.receiver} (Counter #{packet.counter})",
                text_color="#F1C40F",
            )

            # Update Hex Fields
            ct_hex = packet.ciphertext.hex()
            self.lbl_ct.configure(text=f"{ct_hex[:32]}... ({len(packet.ciphertext)} byte)")

            tag_hex = packet.tag.hex()
            self.lbl_tag.configure(text=f"{tag_hex} (16 byte)")

            wk_hex = packet.wrapped_key.hex()
            self.lbl_wk.configure(text=f"{wk_hex[:32]}... (256 byte RSA-OAEP)")

            sig_hex = packet.signature.hex() if packet.signature else "None"
            self.lbl_sig.configure(text=f"{sig_hex[:32]}... (256 byte RSA-PSS)")

            # Aktifkan tombol aksi
            self.btn_decrypt.configure(state="normal")
            self.btn_tamper.configure(state="normal")
            self.btn_replay.configure(state="normal")
            self.btn_spoof.configure(state="normal")

            self._log("=" * 60)
            self._log(f"🚨 [PAKET BERHASIL DISADAP!] Dari: @{packet.sender} | Kepada: @{packet.receiver} | Counter: #{packet.counter}")
            self._log(f"   -> Ciphertext Terkunci : {ct_hex[:24]}...")
            self._log(f"   -> Wrapped Key (RSA)   : {wk_hex[:24]}...")
            self._log("   -> Silakan pilih operasi serangan pada tombol di atas!")

        except Exception as exc:
            self._log(f"Gagal membedah paket yang dicegat: {exc}")

    # =============================================================
    # AKSI-AKSI SERANGAN EVE
    # =============================================================
    def _action_try_decrypt(self):
        """Eve mencoba membuka kunci dan membaca isi pesan."""
        if not self.stolen_packet:
            return

        self._log("\n🕵️ [AKSI EVE] Mencoba membuka kunci wrapped_key menggunakan Kunci Privat milik Eve...")
        try:
            # 1. Coba unwrap RSA-OAEP menggunakan kunci privat Eve
            unwrap_key(self.stolen_packet.wrapped_key, self.eve_priv_key)
            self._log("❌ ANEH: Kunci berhasil dibuka (ini tidak seharusnya terjadi!).")
        except KeyUnwrapError as exc:
            self._log(f"❌ DEKRIPSI GAGAL: {exc}")
            self._log("🛡️ PERTAHANAN BERHASIL: Kunci privat Eve TIDAK COCOK dengan Kunci Publik Alice yang dipakai mengenkripsi!")
            self._log("   -> Eve TIDAK BISA membaca isi pesan teks asli sama sekali! Rahasia pesan tetap aman.")

    def _action_tamper_attack(self):
        """Eve merusak 1 byte pada ciphertext lalu mengirimkannya ke Alice."""
        if not self.stolen_packet:
            return

        corrupted_ct = bytearray(self.stolen_packet.ciphertext)
        corrupted_ct[0] ^= 0x55  # Balik bit (tamper)

        # Counter dinaikkan agar lolos anti-replay, sehingga menguji murni tag integritas
        tampered_packet = MessagePacket(
            version=self.stolen_packet.version,
            sender=self.stolen_packet.sender,
            receiver=self.stolen_packet.receiver,
            counter=self.stolen_packet.counter + 1,
            wrapped_key=self.stolen_packet.wrapped_key,
            nonce=self.stolen_packet.nonce,
            ciphertext=bytes(corrupted_ct),
            tag=self.stolen_packet.tag,
            signature=self.stolen_packet.signature,
        )

        self._log("\n⚡ [AKSI EVE] Menjalankan Serangan Tampering (Man-in-the-Middle):")
        self._log("   - Mengubah 1 byte pada Ciphertext.")
        self._log(f"   - Mengirim paket yang telah rusak ke @{tampered_packet.receiver} via Relay...")

        self._send_raw({"action": "SEND", "packet": tampered_packet.to_dict()})
        self._log("   -> Paket rusak terkirim! Perhatikan jendela Alice: Alarm PERINGATAN INTEGRITAS GAGAL akan menyala!")

    def _action_replay_attack(self):
        """Eve mengirim ulang persis paket asli yang pernah dicegat."""
        if not self.stolen_packet:
            return

        self._log("\n🔁 [AKSI EVE] Menjalankan Serangan Replay:")
        self._log(f"   - Mengirim ulang paket asli dengan Counter #{self.stolen_packet.counter} ke @{self.stolen_packet.receiver}...")

        self._send_raw({"action": "SEND", "packet": self.stolen_packet.to_dict()})
        self._log("   -> Paket duplikat terkirim! Perhatikan jendela Alice: Alarm SERANGAN REPLAY DITOLAK akan menyala!")

    def _action_spoof_attack(self):
        """Eve memalsukan tanda tangan digital RSA-PSS."""
        if not self.stolen_packet:
            return

        fake_sig = bytearray(self.stolen_packet.signature or (b"\xAA" * 256))
        fake_sig[0] ^= 0xFF  # Rusak signature

        spoofed_packet = MessagePacket(
            version=self.stolen_packet.version,
            sender=self.stolen_packet.sender,
            receiver=self.stolen_packet.receiver,
            counter=self.stolen_packet.counter + 1,
            wrapped_key=self.stolen_packet.wrapped_key,
            nonce=self.stolen_packet.nonce,
            ciphertext=self.stolen_packet.ciphertext,
            tag=self.stolen_packet.tag,
            signature=bytes(fake_sig),
        )

        self._log("\n✍️ [AKSI EVE] Menjalankan Serangan Pemalsuan Identitas (Spoofing):")
        self._log("   - Mengubah tanda tangan digital RSA-PSS menjadi signature palsu.")
        self._log(f"   - Mengirim paket dengan signature palsu ke @{spoofed_packet.receiver}...")

        self._send_raw({"action": "SEND", "packet": spoofed_packet.to_dict()})
        self._log("   -> Paket palsu terkirim! Perhatikan jendela Alice: Alarm PEMALSUAN IDENTITAS TERDETEKSI akan menyala!")

    def run(self):
        try:
            self.root.mainloop()
        finally:
            self.is_connected = False
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass


def main():
    parser = argparse.ArgumentParser(description="Konsol Penyadapan & Serangan MITM (Eve the Hacker)")
    parser.add_argument("--host", default="127.0.0.1", help="Host Relay Server (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port Relay Server (default: 8000)")
    args = parser.parse_args()

    app = EveHackerApp(host=args.host, port=args.port)
    app.run()


if __name__ == "__main__":
    main()

