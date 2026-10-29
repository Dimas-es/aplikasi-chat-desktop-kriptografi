"""
Dialog Inisialisasi Identitas, Passphrase, dan Manajemen Kontak.
Menggunakan CustomTkinter untuk tampilan modern bertema gelap.
"""

import customtkinter as ctk
from typing import Optional, Callable


class IdentityDialog(ctk.CTkToplevel):
    """Dialog untuk registrasi identitas baru atau login dengan passphrase."""

    def __init__(
        self,
        parent,
        user_id: str,
        is_first_time: bool,
        on_success: Callable[..., None],
        default_relay_host: str = "127.0.0.1",
        default_relay_port: int = 8000,
    ):
        super().__init__(parent)
        self.user_id = user_id
        self.is_first_time = is_first_time
        self.on_success = on_success
        self.default_relay_host = default_relay_host
        self.default_relay_port = default_relay_port

        self.title("Inisialisasi Keystore Identitas" if is_first_time else "Buka Kunci Keystore")
        self.geometry("480x600")
        self.minsize(440, 560)
        self.resizable(True, True)
        self.grab_set()  # Modal dialog

        self._build_ui()

    def _build_ui(self):
        # Header
        title_text = "Pendaftaran Identitas Lokal" if self.is_first_time else "Autentikasi Passphrase"
        header = ctk.CTkLabel(
            self,
            text=title_text,
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.pack(pady=(16, 6))

        desc_text = (
            "Kunci privat RSA-2048 akan dibuat dan diamankan menggunakan enkripsi PBKDF2.\n"
            "Masukkan passphrase yang kuat."
            if self.is_first_time
            else f"Masukkan passphrase untuk membuka private key akun '{self.user_id}'."
        )
        desc = ctk.CTkLabel(self, text=desc_text, font=ctk.CTkFont(size=11), text_color="gray", justify="center")
        desc.pack(padx=20, pady=(0, 8))

        # Form Container
        form_frame = ctk.CTkFrame(self)
        form_frame.pack(fill="x", padx=25, pady=5)

        # User ID (read-only)
        ctk.CTkLabel(form_frame, text="User ID:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(8, 2))
        self.user_entry = ctk.CTkEntry(form_frame)
        self.user_entry.insert(0, self.user_id)
        self.user_entry.configure(state="disabled")
        self.user_entry.pack(fill="x", padx=15, pady=(0, 8))

        # Display Name (only if first time)
        if self.is_first_time:
            ctk.CTkLabel(form_frame, text="Display Name:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(0, 2))
            self.name_entry = ctk.CTkEntry(form_frame, placeholder_text="Contoh: Alice Crypto")
            self.name_entry.insert(0, self.user_id.capitalize())
            self.name_entry.pack(fill="x", padx=15, pady=(0, 8))
        else:
            self.name_entry = None

        # Passphrase Entry
        ctk.CTkLabel(form_frame, text="Passphrase Keystore:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(0, 2))
        self.pass_entry = ctk.CTkEntry(form_frame, placeholder_text="Masukkan kata sandi...", show="*")
        self.pass_entry.pack(fill="x", padx=15, pady=(0, 8))
        self.pass_entry.focus()

        # Pengaturan Jaringan Relay Server (LAN)
        relay_box = ctk.CTkFrame(form_frame, fg_color="#222222", corner_radius=6)
        relay_box.pack(fill="x", padx=15, pady=(4, 10))

        ctk.CTkLabel(
            relay_box,
            text="🌐 Konfigurasi Relay Server (LAN / Wi-Fi):",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#3B8ED0",
        ).pack(anchor="w", padx=10, pady=(6, 2))

        net_row = ctk.CTkFrame(relay_box, fg_color="transparent")
        net_row.pack(fill="x", padx=10, pady=(0, 6))

        # Relay Host
        host_frame = ctk.CTkFrame(net_row, fg_color="transparent")
        host_frame.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkLabel(host_frame, text="IP Host / Komputer Relay:", font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w")
        self.relay_host_entry = ctk.CTkEntry(host_frame, placeholder_text="127.0.0.1 / 192.168.x.x")
        self.relay_host_entry.insert(0, self.default_relay_host)
        self.relay_host_entry.pack(fill="x")

        # Relay Port
        port_frame = ctk.CTkFrame(net_row, fg_color="transparent")
        port_frame.pack(side="right", fill="x", padx=(5, 0))
        ctk.CTkLabel(port_frame, text="Port:", font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w")
        self.relay_port_entry = ctk.CTkEntry(port_frame, width=70, placeholder_text="8000")
        self.relay_port_entry.insert(0, str(self.default_relay_port))
        self.relay_port_entry.pack(fill="x")

        # Error label
        self.err_label = ctk.CTkLabel(self, text="", text_color="#FF4D4D", font=ctk.CTkFont(size=11))
        self.err_label.pack(pady=2)

        # Action Buttons
        btn_text = "🔐 Buat Pasangan Kunci RSA" if self.is_first_time else "🔓 Buka Kunci & Hubungkan"
        submit_btn = ctk.CTkButton(
            self,
            text=btn_text,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1F6AA5",
            hover_color="#144870",
            command=self._on_submit,
        )
        submit_btn.pack(pady=(6, 16), padx=25, fill="x")

        # Bind Enter key
        self.bind("<Return>", lambda e: self._on_submit())

    def _on_submit(self):
        passphrase = self.pass_entry.get().strip()
        if not passphrase:
            self.err_label.configure(text="Passphrase tidak boleh kosong!")
            return

        display_name = self.name_entry.get().strip() if self.name_entry else self.user_id
        if self.is_first_time and not display_name:
            self.err_label.configure(text="Display name tidak boleh kosong!")
            return

        relay_host = self.relay_host_entry.get().strip() or "127.0.0.1"
        try:
            relay_port = int(self.relay_port_entry.get().strip() or "8000")
        except ValueError:
            self.err_label.configure(text="Port harus berupa angka valid!")
            return

        try:
            self.on_success(self.user_id, display_name, passphrase, relay_host, relay_port)
            self.destroy()
        except Exception as exc:
            self.err_label.configure(text=f"Error: {exc}")


class AddContactDialog(ctk.CTkToplevel):
    """Dialog untuk menambahkan kontak baru dan memverifikasi fingerprint."""

    def __init__(self, parent, on_save: Callable[[str, str, str], str]):
        super().__init__(parent)
        self.on_save = on_save

        self.title("Tambah Kontak Baru")
        self.geometry("540x540")
        self.minsize(480, 480)
        self.resizable(True, True)
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        header = ctk.CTkLabel(self, text="Tambah Kontak Lawan Bicara", font=ctk.CTkFont(size=16, weight="bold"))
        header.pack(pady=(15, 5))

        desc = ctk.CTkLabel(
            self,
            text="Tempelkan Public Key PEM lawan bicara untuk menghitung fingerprint SHA-256.",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        desc.pack(padx=20, pady=(0, 10))

        form = ctk.CTkFrame(self)
        form.pack(fill="both", expand=True, padx=25, pady=5)

        # Contact ID
        ctk.CTkLabel(form, text="User ID Kontak (contoh: bob):", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=15, pady=(10, 2))
        self.id_entry = ctk.CTkEntry(form, placeholder_text="bob")
        self.id_entry.pack(fill="x", padx=15, pady=(0, 8))

        # Display Name
        ctk.CTkLabel(form, text="Nama Tampilan (Display Name):", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=15, pady=(0, 2))
        self.name_entry = ctk.CTkEntry(form, placeholder_text="Bob Peneliti")
        self.name_entry.pack(fill="x", padx=15, pady=(0, 8))

        # Public Key PEM Text Area
        ctk.CTkLabel(form, text="Public Key PEM (SubjectPublicKeyInfo):", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=15, pady=(0, 2))
        self.pem_textbox = ctk.CTkTextbox(form, height=120, font=ctk.CTkFont(family="Consolas", size=10))
        self.pem_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self.err_label = ctk.CTkLabel(self, text="", text_color="#FF4D4D", font=ctk.CTkFont(size=11))
        self.err_label.pack(pady=2)

        save_btn = ctk.CTkButton(
            self,
            text="Hitung Fingerprint & Simpan Kontak",
            fg_color="#2FA572",
            hover_color="#107C41",
            command=self._on_save,
        )
        save_btn.pack(pady=(5, 15), padx=25, fill="x")

    def _on_save(self):
        contact_id = self.id_entry.get().strip().lower()
        display_name = self.name_entry.get().strip() or contact_id
        pem_text = self.pem_textbox.get("1.0", "end").strip()

        if not contact_id:
            self.err_label.configure(text="User ID Kontak wajib diisi!")
            return
        if not pem_text or "BEGIN PUBLIC KEY" not in pem_text:
            self.err_label.configure(text="Public key PEM tidak valid!")
            return

        try:
            fingerprint = self.on_save(contact_id, display_name, pem_text)
            self.destroy()
        except Exception as exc:
            self.err_label.configure(text=f"Error: {exc}")
