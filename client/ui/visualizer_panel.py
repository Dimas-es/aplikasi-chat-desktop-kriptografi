"""
Panel Mode Visualisasi Kriptografi (Hex & Byte Inspector).

Menampilkan inspeksi detail transformasi matematis tiap tahapan:
- Sisi Pengirim: Plaintext -> K_AES/Nonce -> AAD -> Ciphertext+Tag -> Wrapped Key -> JSON Packet.
- Sisi Penerima: Anti-Replay Check -> RSA-OAEP Unwrap -> Rekonstruksi AAD -> Verifikasi Tag -> Plaintext Commit.
"""

import customtkinter as ctk
from typing import Optional
from client.controllers.visualizer_controller import PipelineTrace, StageInfo


class VisualizerPanel(ctk.CTkFrame):
    """Panel inspeksi pipeline kriptografi interaktif."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.current_trace: Optional[PipelineTrace] = None
        self._build_ui()

    def _build_ui(self):
        # Header Panel
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))

        self.title_label = ctk.CTkLabel(
            header_frame,
            text="🔬 Mode Visualisasi Kriptografi",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        self.title_label.pack(side="left")

        # Status & Direction Badges
        self.badge_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.badge_frame.pack(fill="x", padx=15, pady=2)

        self.dir_badge = ctk.CTkLabel(
            self.badge_frame,
            text="Siap",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#333333",
            corner_radius=6,
            padx=8,
            pady=2,
        )
        self.dir_badge.pack(side="left", padx=(0, 6))

        self.status_badge = ctk.CTkLabel(
            self.badge_frame,
            text="Menunggu pesan...",
            font=ctk.CTkFont(size=11),
            fg_color="#2B2B2B",
            corner_radius=6,
            padx=8,
            pady=2,
        )
        self.status_badge.pack(side="left")

        # Scrollable area untuk menampilkan kartu-kartu tahapan
        self.scroll_stages = ctk.CTkScrollableFrame(self)
        self.scroll_stages.pack(fill="both", expand=True, padx=10, pady=10)

        self._show_empty_placeholder()

    def _show_empty_placeholder(self):
        """Menampilkan teks petunjuk saat belum ada pesan yang diproses."""
        for widget in self.scroll_stages.winfo_children():
            widget.destroy()

        placeholder = ctk.CTkLabel(
            self.scroll_stages,
            text=(
                "Belum ada aktivitas kriptografi.\n\n"
                "Kirim pesan atau terima pesan dari lawan bicara\n"
                "untuk mengamati transformasi matematis\n"
                "(K_AES, Nonce, AAD, Tag, dan Wrapped Key)\n"
                "secara transparan di panel ini."
            ),
            font=ctk.CTkFont(size=12),
            text_color="gray",
            justify="center",
        )
        placeholder.pack(pady=60, padx=20)

    def render_trace(self, trace: PipelineTrace):
        """Merender seluruh tahapan proses dari objek PipelineTrace."""
        self.current_trace = trace

        # Update Badge Header
        is_send = trace.direction == "SEND"
        dir_text = f"📤 PENGIRIM ({trace.sender} ➔ {trace.receiver})" if is_send else f"📥 PENERIMA ({trace.sender} ➔ {trace.receiver})"
        dir_color = "#1F6AA5" if is_send else "#2FA572"
        self.dir_badge.configure(text=dir_text, fg_color=dir_color)

        status_colors = {
            "terkirim": "#1F6AA5",
            "valid": "#2FA572",
            "ditolak_replay": "#C0392B",
            "gagal_unwrap": "#D35400",
            "gagal_verifikasi": "#E74C3C",
            "gagal_signature": "#7B241C",
        }
        color = status_colors.get(trace.final_status, "#555555")
        status_text = f"Status: {trace.final_status.upper()} (Counter #{trace.counter} @ {trace.timestamp})"
        if trace.error_message:
            status_text += f" | {trace.error_message}"
        self.status_badge.configure(text=status_text, fg_color=color)

        # Bersihkan widget lama
        for widget in self.scroll_stages.winfo_children():
            widget.destroy()

        # Render masing-masing stage card
        for stage in trace.stages:
            self._render_stage_card(stage)

    def _render_stage_card(self, stage: StageInfo):
        """Membuat satu kartu tahapan proses kriptografi."""
        card = ctk.CTkFrame(self.scroll_stages, corner_radius=8)
        card.pack(fill="x", pady=6, padx=5)

        # Baris Header Kartu (Stage Number, Name, Status)
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=(8, 2))

        title_lbl = ctk.CTkLabel(
            top_row,
            text=f"Tahap {stage.stage_number}: {stage.name}",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        title_lbl.pack(side="left")

        # Badge status tahap (OK / FAIL)
        badge_color = "#2FA572" if stage.status == "OK" else "#E74C3C"
        status_lbl = ctk.CTkLabel(
            top_row,
            text=stage.status,
            font=ctk.CTkFont(size=10, weight="bold"),
            fg_color=badge_color,
            corner_radius=4,
            padx=6,
            pady=1,
        )
        status_lbl.pack(side="right")

        # Deskripsi
        desc_lbl = ctk.CTkLabel(
            card,
            text=stage.description,
            font=ctk.CTkFont(size=11),
            text_color="#B0B0B0",
            anchor="w",
            justify="left",
        )
        desc_lbl.pack(fill="x", padx=10, pady=(0, 4))

        # Preview teks & byte length
        meta_row = ctk.CTkFrame(card, fg_color="transparent")
        meta_row.pack(fill="x", padx=10, pady=(0, 4))

        len_badge = ctk.CTkLabel(
            meta_row,
            text=f"Ukuran: {stage.byte_length} byte",
            font=ctk.CTkFont(size=10),
            text_color="#888888",
        )
        len_badge.pack(side="left")

        if stage.text_preview:
            preview_lbl = ctk.CTkLabel(
                meta_row,
                text=f"Preview: {stage.text_preview[:40]}{'...' if len(stage.text_preview) > 40 else ''}",
                font=ctk.CTkFont(size=10),
                text_color="#3B8ED0",
            )
            preview_lbl.pack(side="right")

        # Kotak Hex Viewer (Monospace font)
        hex_box = ctk.CTkTextbox(
            card,
            height=65,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#181818",
            text_color="#00FF66",
            wrap="char",
        )
        hex_box.insert("1.0", stage.hex_data)
        hex_box.configure(state="disabled")
        hex_box.pack(fill="x", padx=10, pady=(0, 8))
