"""
Jendela Utama Aplikasi Chat Desktop (ChatWindow).

Menampilkan:
1. Panel Kiri: Profil Pengguna, Fingerprint, Daftar Kontak, dan Aksi Tambah Kontak.
2. Panel Tengah: Gelembung Obrolan (Chat Bubbles) 1-ke-1, Status Badge Kripto, Input Pesan, dan Tombol Simulasi Cepat.
3. Panel Kanan: Mode Visualisasi Kriptografi (Hex & Byte Inspector) Real-Time.
"""

import tkinter as tk
import customtkinter as ctk
from typing import Optional, Dict, Any, Callable
from datetime import datetime

from client.controllers.chat_controller import ChatController
from client.ui.visualizer_panel import VisualizerPanel
from client.ui.key_dialog import AddContactDialog
from src.messaging.packet import MessagePacket
from src.messaging.status import MessageStatus


class ChatWindow(ctk.CTkFrame):
    """Jendela utama aplikasi percakapan."""

    def __init__(
        self,
        parent,
        controller: ChatController,
        on_send_network_packet: Optional[Callable[[MessagePacket], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.controller = controller
        self.on_send_network_packet = on_send_network_packet
        self.active_contact_id: Optional[str] = None
        self.last_sent_packet: Optional[MessagePacket] = None
        self.last_received_packet: Optional[MessagePacket] = None

        self._build_ui()
        self.refresh_contacts()

    def _build_ui(self):
        # Layout 3 Kolom: Sidebar Kontak (250px) | Obrolan (Fleksibel) | Visualizer (450px)
        self.grid_columnconfigure(0, weight=0, minsize=260)
        self.grid_columnconfigure(1, weight=1, minsize=400)
        self.grid_columnconfigure(2, weight=0, minsize=460)
        self.grid_rowconfigure(0, weight=1)

        # ============================================================
        # 1. KOLOM KIRI: SIDEBAR PROFIL & KONTAK
        # ============================================================
        self.sidebar = ctk.CTkFrame(self, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 2), pady=0)

        # Kartu Profil Pengguna
        profile_card = ctk.CTkFrame(self.sidebar, fg_color="#1E1E1E")
        profile_card.pack(fill="x", padx=10, pady=10)

        self.user_lbl = ctk.CTkLabel(
            profile_card,
            text=f"👤 {self.controller.display_name or self.controller.user_id}",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self.user_lbl.pack(fill="x", padx=10, pady=(8, 2))

        fp_display = (self.controller.fingerprint[:17] + "...") if self.controller.fingerprint else "Tanpa Kunci"
        self.fp_lbl = ctk.CTkLabel(
            profile_card,
            text=f"FP: {fp_display}",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#3B8ED0",
            anchor="w",
        )
        self.fp_lbl.pack(fill="x", padx=10, pady=(0, 6))

        # Tombol Salin Public Key
        copy_pub_btn = ctk.CTkButton(
            self.sidebar,
            text="📋 Salin Public Key PEM",
            font=ctk.CTkFont(size=11),
            height=28,
            fg_color="#2A2A2A",
            hover_color="#3A3A3A",
            command=self._copy_public_key,
        )
        copy_pub_btn.pack(fill="x", padx=10, pady=(0, 5))

        # Tombol Tambah Kontak
        add_contact_btn = ctk.CTkButton(
            self.sidebar,
            text="➕ Tambah Kontak Baru",
            font=ctk.CTkFont(size=11),
            height=28,
            fg_color="#1F6AA5",
            hover_color="#144870",
            command=self._open_add_contact,
        )
        add_contact_btn.pack(fill="x", padx=10, pady=(0, 10))

        # Header Daftar Kontak
        ctk.CTkLabel(
            self.sidebar,
            text="DAFTAR KONTAK",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray",
        ).pack(anchor="w", padx=12, pady=(5, 2))

        # Scrollable Contact List
        self.contact_scroll = ctk.CTkScrollableFrame(self.sidebar)
        self.contact_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        # ============================================================
        # 2. KOLOM TENGAH: AREA OBROLAN & INPUT PESAN
        # ============================================================
        self.chat_area = ctk.CTkFrame(self, corner_radius=0)
        self.chat_area.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.chat_area.grid_rowconfigure(1, weight=1)
        self.chat_area.grid_columnconfigure(0, weight=1)

        # Header Obrolan
        self.chat_header = ctk.CTkFrame(self.chat_area, height=55, corner_radius=0)
        self.chat_header.grid(row=0, column=0, sticky="ew")

        self.chat_title = ctk.CTkLabel(
            self.chat_header,
            text="Pilih kontak untuk memulai percakapan",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.chat_title.pack(side="left", padx=15, pady=10)

        self.verify_toggle_btn = ctk.CTkButton(
            self.chat_header,
            text="Verifikasi Fingerprint",
            font=ctk.CTkFont(size=10),
            height=24,
            width=130,
            fg_color="#333333",
            command=self._toggle_verified_contact,
        )

        # Area Gelembung Pesan (Scrollable)
        self.message_frame = ctk.CTkScrollableFrame(self.chat_area)
        self.message_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        # Action Bar Simulasi Cepat (Edukasi / Demonstrasi Serangan)
        sim_bar = ctk.CTkFrame(self.chat_area, height=30, fg_color="transparent")
        sim_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(2, 0))

        sim_label = ctk.CTkLabel(sim_bar, text="Uji Serangan:", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray")
        sim_label.pack(side="left", padx=(5, 5))

        btn_replay = ctk.CTkButton(
            sim_bar, text="🔁 Uji Replay", font=ctk.CTkFont(size=10), height=22, width=80, fg_color="#6C3483",
            command=self._simulate_replay_attack,
        )
        btn_replay.pack(side="left", padx=3)

        btn_tamper = ctk.CTkButton(
            sim_bar, text="⚡ Tamper 1-Byte", font=ctk.CTkFont(size=10), height=22, width=95, fg_color="#922B21",
            command=self._simulate_tamper_attack,
        )
        btn_tamper.pack(side="left", padx=3)

        btn_spoof = ctk.CTkButton(
            sim_bar, text="✍️ Palsukan Sig", font=ctk.CTkFont(size=10), height=22, width=95, fg_color="#7B241C",
            command=self._simulate_spoof_signature_attack,
        )
        btn_spoof.pack(side="left", padx=3)

        # Baris Input Pesan
        input_container = ctk.CTkFrame(self.chat_area, height=50)
        input_container.grid(row=3, column=0, sticky="ew", padx=10, pady=10)

        self.msg_entry = ctk.CTkEntry(
            input_container,
            placeholder_text="Ketik pesan terenkripsi... (Tekan Enter untuk kirim)",
            height=38,
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(10, 8), pady=8)
        self.msg_entry.bind("<Return>", lambda e: self._on_send_click())

        self.send_btn = ctk.CTkButton(
            input_container,
            text="Kirim 🔐",
            width=80,
            height=38,
            fg_color="#1F6AA5",
            hover_color="#144870",
            command=self._on_send_click,
        )
        self.send_btn.pack(side="right", padx=(0, 10), pady=8)

        # ============================================================
        # 3. KOLOM KANAN: PANEL VISUALISASI KRIPTOGRAFI
        # ============================================================
        self.visualizer = VisualizerPanel(self)
        self.visualizer.grid(row=0, column=2, sticky="nsew", padx=(2, 0), pady=0)

    def refresh_contacts(self):
        """Memuat ulang daftar kontak di sidebar."""
        for widget in self.contact_scroll.winfo_children():
            widget.destroy()

        contacts = self.controller.list_contacts()
        if not contacts:
            lbl = ctk.CTkLabel(
                self.contact_scroll,
                text="Belum ada kontak.\nKlik 'Tambah Kontak Baru'.",
                font=ctk.CTkFont(size=11),
                text_color="gray",
                justify="center",
            )
            lbl.pack(pady=30)
            return

        for contact in contacts:
            cid = contact["contact_id"]
            dname = contact["display_name"]
            verified = contact["verified"]

            btn_frame = ctk.CTkFrame(self.contact_scroll, fg_color="#222222", corner_radius=6)
            btn_frame.pack(fill="x", pady=3)

            is_active = self.active_contact_id == cid
            bg_color = "#1F6AA5" if is_active else "transparent"

            item_btn = ctk.CTkButton(
                btn_frame,
                text=f"{'🛡️ ' if verified else '👤 '}{dname} (@{cid})",
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal"),
                anchor="w",
                fg_color=bg_color,
                hover_color="#2A4D69",
                height=32,
                command=lambda c=cid: self.select_contact(c),
            )
            item_btn.pack(fill="x", padx=4, pady=3)

    def select_contact(self, contact_id: str):
        """Memilih kontak aktif untuk bertukar pesan."""
        self.active_contact_id = contact_id
        contact = self.controller.contact_store.get_contact(contact_id)
        if not contact:
            return

        dname = contact["display_name"]
        verified = contact["verified"]
        fp = contact["fingerprint"]

        # Update Chat Header
        self.chat_title.configure(text=f"Obrolan dengan {dname} (@{contact_id})")
        self.verify_toggle_btn.pack(side="right", padx=15, pady=10)
        self._update_verify_button(verified)

        self.refresh_contacts()
        self._clear_messages()
        self._add_system_message(
            f"Sesi percakapan terenkripsi dimulai dengan {dname}.\n"
            f"Fingerprint: {fp[:23]}...\n"
            f"Status Kunci: {'🛡️ TERVERIFIKASI OUT-OF-BAND' if verified else '⚠️ BELUM DIVERIFIKASI (MITM RISK)'}"
        )

    def _update_verify_button(self, verified: bool):
        if verified:
            self.verify_toggle_btn.configure(
                text="🛡️ Terverifikasi",
                fg_color="#107C41",
                hover_color="#0B552C",
            )
        else:
            self.verify_toggle_btn.configure(
                text="⚠️ Verifikasi Fingerprint",
                fg_color="#D35400",
                hover_color="#A04000",
            )

    def _toggle_verified_contact(self):
        if not self.active_contact_id:
            return
        contact = self.controller.contact_store.get_contact(self.active_contact_id)
        if not contact:
            return
        new_status = not contact["verified"]
        self.controller.set_contact_verified(self.active_contact_id, verified=new_status)
        self._update_verify_button(new_status)
        self.refresh_contacts()
        status_text = "DITANDAI TERVERIFIKASI" if new_status else "STATUS VERIFIKASI DICABUT"
        self._add_system_message(f"Keamanan: Kontak @{self.active_contact_id} {status_text}.")

    def _open_add_contact(self):
        def on_save_contact(cid, dname, pem):
            fp = self.controller.add_contact(cid, dname, pem, verified=False)
            self.refresh_contacts()
            self.select_contact(cid)
            return fp

        AddContactDialog(self.winfo_toplevel(), on_save=on_save_contact)

    def _copy_public_key(self):
        try:
            pem = self.controller.get_public_key_pem()
            self.clipboard_clear()
            self.clipboard_append(pem)
            self._add_system_message("Kunci Publik PEM berhasil disalin ke clipboard! Bagikan ke lawan bicara.")
        except Exception as exc:
            self._add_system_message(f"Gagal menyalin kunci: {exc}")

    def _on_send_click(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        if not self.active_contact_id:
            self._add_system_message("Pilih kontak penerima terlebih dahulu dari sidebar!")
            return

        try:
            # 1. Eksekusi Enkripsi Hybrid via Controller
            packet, trace = self.controller.send_message(self.active_contact_id, text)
            self.last_sent_packet = packet

            # 2. Render visualizer real-time
            self.visualizer.render_trace(trace)

            # 3. Tampilkan gelembung pesan keluar
            self._add_chat_bubble(
                sender_name="Anda",
                text=text,
                counter=packet.counter,
                status="terkirim",
                is_outgoing=True,
            )

            # 4. Kosongkan input
            self.msg_entry.delete(0, "end")

            # 5. Teruskan ke callback network jika aktif
            if self.on_send_network_packet:
                self.on_send_network_packet(packet)

        except Exception as exc:
            self._add_system_message(f"Error Pengiriman: {exc}")

    def handle_incoming_packet(self, packet: MessagePacket):
        """Menerima dan memproses paket pesan masuk dari lawan bicara."""
        # Pastikan kontak terdaftar
        if not self.active_contact_id:
            self.select_contact(packet.sender)

        status, decrypted_text, trace = self.controller.receive_message(packet)
        self.visualizer.render_trace(trace)

        if status == MessageStatus.VALID:
            self.last_received_packet = packet
            self._add_chat_bubble(
                sender_name=packet.sender,
                text=decrypted_text or "",
                counter=packet.counter,
                status="valid",
                is_outgoing=False,
            )
        elif status == MessageStatus.REPLAY_REJECTED:
            self._add_security_alert(
                f"🚨 SERANGAN REPLAY DITOLAK!\n"
                f"Paket masuk dengan counter #{packet.counter} ditolak karena sudah pernah diproses."
            )
        elif status == MessageStatus.VERIFICATION_FAILED:
            self._add_security_alert(
                f"⚠️ PERINGATAN INTEGRITAS GAGAL!\n"
                f"Authentication Tag AES-GCM tidak cocok pada counter #{packet.counter}.\n"
                f"Ciphertext atau metadata AAD telah termodifikasi!"
            )
        elif status == MessageStatus.SIGNATURE_FAILED:
            self._add_security_alert(
                f"🚨 PEMALSUAN IDENTITAS TERDETEKSI (SIGNATURE ERROR)!\n"
                f"Tanda tangan digital RSA-PSS pada counter #{packet.counter} tidak cocok dengan kunci publik @{packet.sender}!\n"
                f"Paket mungkin dikirim oleh penyerang yang memalsukan identitas (Spoofing)!"
            )
        elif status == MessageStatus.UNWRAP_FAILED:
            self._add_security_alert(
                f"❌ GAGAL MEMBUKA KUNCI (UNWRAP ERROR)!\n"
                f"Wrapped key tidak cocok dengan kunci privat RSA Anda."
            )

    # ============================================================
    # SIMULASI SERANGAN LANGSUNG (EDUKASI)
    # ============================================================
    def _simulate_replay_attack(self):
        """Mensimulasikan injeksi ulang paket yang sama untuk menguji filter anti-replay."""
        if not self.last_sent_packet and not self.last_received_packet:
            self._add_system_message("Kirim atau terima setidaknya 1 pesan terlebih dahulu sebelum mencoba simulasi replay.")
            return

        # 1. Jika ada pesan masuk yang pernah diterima, jalankan pengujian replay lokal di jendela ini
        if self.last_received_packet:
            self._add_system_message(
                f"🔁 [Simulasi Replay Lokal] Menginjeksi ulang paket masuk (Counter #{self.last_received_packet.counter}) dari @{self.last_received_packet.sender}..."
            )
            self.handle_incoming_packet(self.last_received_packet)

        # 2. Jika terhubung ke jaringan relay dan ada paket terkirim, kirimkan duplikat paket ke lawan bicara
        if self.on_send_network_packet and self.last_sent_packet:
            self._add_system_message(
                f"🔁 [Simulasi Replay Jaringan] Mengirim ulang paket terkirim #{self.last_sent_packet.counter} ke @{self.last_sent_packet.receiver} via Relay...\n"
                f"Sistem anti-replay pada jendela @{self.last_sent_packet.receiver} akan mendeteksi dan menolaknya!"
            )
            self.on_send_network_packet(self.last_sent_packet)

    def _simulate_tamper_attack(self):
        """Mensimulasikan bit-flipping pada ciphertext untuk menguji deteksi AES-GCM."""
        if not self.last_sent_packet and not self.last_received_packet:
            self._add_system_message("Kirim atau terima setidaknya 1 pesan terlebih dahulu sebelum mencoba manipulasi data.")
            return

        # 1. Jika ada pesan masuk yang pernah diterima, manipulasi dan uji di jendela ini (kunci privat cocok)
        if self.last_received_packet:
            corrupted_ct = bytearray(self.last_received_packet.ciphertext)
            corrupted_ct[0] ^= 0x55  # Flip bit

            tampered_local = MessagePacket(
                version=self.last_received_packet.version,
                sender=self.last_received_packet.sender,
                receiver=self.last_received_packet.receiver,
                counter=self.last_received_packet.counter + 1,  # Counter baru agar lolos filter replay
                wrapped_key=self.last_received_packet.wrapped_key,
                nonce=self.last_received_packet.nonce,
                ciphertext=bytes(corrupted_ct),
                tag=self.last_received_packet.tag,
            )
            self._add_system_message("⚡ [Simulasi Tamper Lokal] Memproses paket dengan 1 byte ciphertext yang telah diubah...")
            self.handle_incoming_packet(tampered_local)

        # 2. Jika terhubung ke jaringan dan ada paket terkirim, kirim paket rusak ke jaringan menuju lawan bicara
        if self.on_send_network_packet and self.last_sent_packet:
            corrupted_ct_net = bytearray(self.last_sent_packet.ciphertext)
            corrupted_ct_net[0] ^= 0x55

            tampered_net = MessagePacket(
                version=self.last_sent_packet.version,
                sender=self.last_sent_packet.sender,
                receiver=self.last_sent_packet.receiver,
                counter=self.last_sent_packet.counter + 1,
                wrapped_key=self.last_sent_packet.wrapped_key,
                nonce=self.last_sent_packet.nonce,
                ciphertext=bytes(corrupted_ct_net),
                tag=self.last_sent_packet.tag,
            )
            self._add_system_message(
                f"⚡ [Simulasi Tamper Jaringan] Mengirim paket dengan ciphertext termanipulasi ke @{self.last_sent_packet.receiver}...\n"
                f"Verifikasi tag AES-GCM pada jendela @{self.last_sent_packet.receiver} akan mendeteksi kerusakan ini!"
            )
            self.on_send_network_packet(tampered_net)

    def _simulate_spoof_signature_attack(self):
        """Mensimulasikan pemalsuan tanda tangan digital RSA-PSS (Spoofing/Modifikasi Tanda Tangan)."""
        target_pkt = self.last_received_packet or self.last_sent_packet
        if not target_pkt:
            self._add_system_message("Kirim atau terima setidaknya 1 pesan terlebih dahulu sebelum mencoba manipulasi tanda tangan.")
            return

        # 1. Jika ada pesan masuk, uji secara lokal di jendela ini
        if self.last_received_packet:
            fake_sig = bytearray(self.last_received_packet.signature or (b"\xAA" * 256))
            fake_sig[0] ^= 0xFF  # Rusak tanda tangan

            spoofed_local = MessagePacket(
                version=2,
                sender=self.last_received_packet.sender,
                receiver=self.last_received_packet.receiver,
                counter=self.last_received_packet.counter + 1,  # Counter baru agar lolos anti-replay
                wrapped_key=self.last_received_packet.wrapped_key,
                nonce=self.last_received_packet.nonce,
                ciphertext=self.last_received_packet.ciphertext,
                tag=self.last_received_packet.tag,
                signature=bytes(fake_sig),
            )
            self._add_system_message("✍️ [Simulasi Palsukan Sig Lokal] Memproses paket dengan RSA-PSS signature yang tidak valid...")
            self.handle_incoming_packet(spoofed_local)

        # 2. Jika ada paket terkirim dan terhubung ke relay, kirimkan ke lawan bicara
        if self.on_send_network_packet and self.last_sent_packet:
            fake_sig_net = bytearray(self.last_sent_packet.signature or (b"\xAA" * 256))
            fake_sig_net[0] ^= 0xFF

            spoofed_net = MessagePacket(
                version=2,
                sender=self.last_sent_packet.sender,
                receiver=self.last_sent_packet.receiver,
                counter=self.last_sent_packet.counter + 1,
                wrapped_key=self.last_sent_packet.wrapped_key,
                nonce=self.last_sent_packet.nonce,
                ciphertext=self.last_sent_packet.ciphertext,
                tag=self.last_sent_packet.tag,
                signature=bytes(fake_sig_net),
            )
            self._add_system_message(
                f"✍️ [Simulasi Palsukan Sig Jaringan] Mengirim paket dengan signature palsu ke @{self.last_sent_packet.receiver}...\n"
                f"Verifikasi RSA-PSS pada jendela @{self.last_sent_packet.receiver} akan menolaknya sebagai pemalsuan identitas!"
            )
            self.on_send_network_packet(spoofed_net)

    # ============================================================
    # HELPER RENDERING BUBBLES
    # ============================================================
    def _clear_messages(self):
        for widget in self.message_frame.winfo_children():
            widget.destroy()

    def _add_chat_bubble(self, sender_name: str, text: str, counter: int, status: str, is_outgoing: bool):
        row = ctk.CTkFrame(self.message_frame, fg_color="transparent")
        row.pack(fill="x", pady=4, padx=5)

        align = "e" if is_outgoing else "w"
        bg_color = "#1F6AA5" if is_outgoing else "#2B2B2B"

        bubble = ctk.CTkFrame(row, fg_color=bg_color, corner_radius=10)
        bubble.pack(anchor=align, padx=5)

        # Header Gelembung
        meta_row = ctk.CTkFrame(bubble, fg_color="transparent")
        meta_row.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            meta_row,
            text=f"{sender_name}  •  #{counter}",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#B0B0B0",
        ).pack(side="left")

        time_str = datetime.now().strftime("%H:%M")
        badge_text = " terkirim ✓" if is_outgoing else " valid 🔐"
        ctk.CTkLabel(
            meta_row,
            text=f"{time_str} {badge_text}",
            font=ctk.CTkFont(size=9),
            text_color="#64B5F6" if is_outgoing else "#81C784",
        ).pack(side="right", padx=(8, 0))

        # Isi Pesan
        msg_lbl = ctk.CTkLabel(
            bubble,
            text=text,
            font=ctk.CTkFont(size=13),
            wraplength=350,
            justify="left" if not is_outgoing else "right",
        )
        msg_lbl.pack(padx=10, pady=(0, 8), anchor=align)

    def _add_system_message(self, text: str):
        lbl = ctk.CTkLabel(
            self.message_frame,
            text=f"ℹ️ {text}",
            font=ctk.CTkFont(size=11),
            text_color="#9E9E9E",
            wraplength=380,
            justify="center",
        )
        lbl.pack(pady=4)

    def _add_security_alert(self, text: str):
        alert_box = ctk.CTkFrame(self.message_frame, fg_color="#4A1515", corner_radius=6)
        alert_box.pack(fill="x", pady=6, padx=10)

        lbl = ctk.CTkLabel(
            alert_box,
            text=text,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#FF8A80",
            justify="left",
        )
        lbl.pack(padx=10, pady=8)
