"""
Pengendali dan Perekam Pipeline Mode Visualisasi Kriptografi (VisualizerController).

Menyediakan pencatatan data heksadesimal per tahap tanpa menuliskan kunci ke file log permanen.
Digunakan oleh UI Visualizer (Hex & Byte Inspector) untuk edukasi dan demonstrasi akademik.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class StageInfo:
    """Informasi satu tahapan matematis kriptografi."""
    stage_number: int
    name: str
    description: str
    hex_data: str
    byte_length: int
    text_preview: str
    status: str = "OK"  # "OK", "FAIL", "SKIPPED"


@dataclass
class PipelineTrace:
    """Rekaman urutan lengkap proses enkripsi atau dekripsi pesan."""
    direction: str  # "SEND" (Alice) atau "RECEIVE" (Bob)
    sender: str
    receiver: str
    counter: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S.%f")[:-3])
    stages: List[StageInfo] = field(default_factory=list)
    final_status: str = "OK"
    error_message: Optional[str] = None


class VisualizerController:
    """Mengelola rekam jejak pipeline transformasi kripto di memori aktif."""

    def __init__(self):
        self.history: List[PipelineTrace] = []
        self.current_trace: Optional[PipelineTrace] = None

    def record_send_pipeline(
        self,
        sender: str,
        receiver: str,
        counter: int,
        plaintext: bytes,
        k_aes: bytes,
        nonce: bytes,
        aad: bytes,
        ciphertext: bytes,
        tag: bytes,
        wrapped_key: bytes,
        signature: Optional[bytes] = None,
        packet_json: str = "",
    ) -> PipelineTrace:
        """
        Merekam 6 tahap proses enkripsi hybrid di sisi pengirim.
        """
        trace = PipelineTrace(
            direction="SEND",
            sender=sender,
            receiver=receiver,
            counter=counter,
            final_status="terkirim",
        )

        # Stage 1: Plaintext Asli
        try:
            pt_preview = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            pt_preview = "<biner>"
        trace.stages.append(
            StageInfo(
                stage_number=1,
                name="Input Plaintext",
                description="Pesan teks asli dikonversi menjadi stream byte UTF-8.",
                hex_data=plaintext.hex().upper(),
                byte_length=len(plaintext),
                text_preview=pt_preview,
            )
        )

        # Stage 2: Kunci Simetris & Nonce CSPRNG
        trace.stages.append(
            StageInfo(
                stage_number=2,
                name="Pembangkitan K_AES & Nonce GCM",
                description="Kunci AES-256 (32 byte) dan Nonce (12 byte) dibangkitkan segar menggunakan CSPRNG.",
                hex_data=f"K_AES: {k_aes.hex().upper()}\nNONCE: {nonce.hex().upper()}",
                byte_length=len(k_aes) + len(nonce),
                text_preview=f"AES Key (256-bit) + Nonce (96-bit)",
            )
        )

        # Stage 3: AAD Kanonikal
        trace.stages.append(
            StageInfo(
                stage_number=3,
                name="Pengikatan AAD Kanonikal",
                description="Metadata sender:receiver:counter diikat ke operasi autentikasi AES-GCM.",
                hex_data=aad.hex().upper(),
                byte_length=len(aad),
                text_preview=aad.decode("utf-8"),
            )
        )

        # Stage 4: AES-256-GCM Enkripsi & Tag
        trace.stages.append(
            StageInfo(
                stage_number=4,
                name="Enkripsi AES-256-GCM & Tag Autentikasi",
                description="Plaintext dienkripsi; dihasilkan Ciphertext dan Authentication Tag 128-bit (16 byte).",
                hex_data=f"CIPHERTEXT:\n{ciphertext.hex().upper()}\n\nTAG (16B):\n{tag.hex().upper()}",
                byte_length=len(ciphertext) + len(tag),
                text_preview=f"Ciphertext ({len(ciphertext)}B) + Tag (16B)",
            )
        )

        # Stage 5: RSA-OAEP Pembungkusan Kunci (Key Wrapping)
        trace.stages.append(
            StageInfo(
                stage_number=5,
                name="Pembungkusan Kunci (RSA-OAEP Wrap)",
                description=f"Kunci K_AES dibungkus menggunakan Public Key {receiver.capitalize()} dengan padding SHA-256 dan MGF1 SHA-256.",
                hex_data=wrapped_key.hex().upper(),
                byte_length=len(wrapped_key),
                text_preview=f"Wrapped Key (2048-bit / 256 byte)",
            )
        )

        stage_idx = 6
        if signature:
            trace.stages.append(
                StageInfo(
                    stage_number=stage_idx,
                    name="Tanda Tangan Digital (RSA-PSS)",
                    description=f"Pengirim membubuhkan digital signature 256-byte dengan Kunci Privat {sender.capitalize()} untuk bukti keaslian identitas (Non-Repudiation).",
                    hex_data=signature.hex().upper(),
                    byte_length=len(signature),
                    text_preview=f"RSA-PSS Signature (2048-bit / 256 byte)",
                )
            )
            stage_idx += 1

        # Final Packet JSON
        trace.stages.append(
            StageInfo(
                stage_number=stage_idx,
                name="Paket Pesan JSON (Terserialisasi)",
                description="Paket lengkap siap kirim dengan muatan Base64 terenkripsi dan tanda tangan digital.",
                hex_data=packet_json.encode("utf-8").hex().upper(),
                byte_length=len(packet_json.encode("utf-8")),
                text_preview=packet_json,
            )
        )

        self.history.append(trace)
        self.current_trace = trace
        return trace

    def record_receive_pipeline(
        self,
        sender: str,
        receiver: str,
        counter: int,
        can_accept_counter: bool,
        current_highest_counter: int,
        wrapped_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes,
        signature: Optional[bytes] = None,
        signature_valid: bool = True,
        signature_error: Optional[str] = None,
        unwrapped_key: Optional[bytes] = None,
        unwrap_error: Optional[str] = None,
        verification_success: bool = False,
        verification_error: Optional[str] = None,
        plaintext: Optional[bytes] = None,
    ) -> PipelineTrace:
        """
        Merekam tahapan verifikasi dan dekripsi di sisi penerima.
        """
        trace = PipelineTrace(
            direction="RECEIVE",
            sender=sender,
            receiver=receiver,
            counter=counter,
        )

        # Stage 1: Anti-Replay Counter Check
        status_s1 = "OK" if can_accept_counter else "FAIL"
        trace.stages.append(
            StageInfo(
                stage_number=1,
                name="Pemeriksaan Counter Anti-Replay",
                description=(
                    f"Counter paket ({counter}) dibandingkan dengan counter tertinggi yang tersimpan ({current_highest_counter})."
                ),
                hex_data=f"INCOMING_COUNTER: {counter} | HIGHEST_VERIFIED: {current_highest_counter}",
                byte_length=4,
                text_preview="Counter Sah (> highest)" if can_accept_counter else "DITOLAK: Replay Attack Terdeteksi!",
                status=status_s1,
            )
        )

        if not can_accept_counter:
            trace.final_status = "ditolak_replay"
            trace.error_message = f"Paket dengan counter {counter} ditolak karena <= {current_highest_counter}"
            self.history.append(trace)
            self.current_trace = trace
            return trace

        stage_num = 2
        # Stage 2: Verifikasi Tanda Tangan Digital RSA-PSS (jika ada signature)
        if signature:
            status_sig = "OK" if signature_valid else "FAIL"
            trace.stages.append(
                StageInfo(
                    stage_number=stage_num,
                    name="Verifikasi Tanda Tangan Digital (RSA-PSS)",
                    description=f"Kunci Publik {sender.capitalize()} memverifikasi integritas dan keaslian identitas pengirim (Authenticity & Non-Repudiation).",
                    hex_data=signature.hex().upper(),
                    byte_length=len(signature),
                    text_preview="Signature Sah (Pengirim Asli Terverifikasi)" if signature_valid else f"DITOLAK: {signature_error}",
                    status=status_sig,
                )
            )
            if not signature_valid:
                trace.final_status = "gagal_signature"
                trace.error_message = signature_error or "Tanda tangan digital tidak cocok dengan kunci publik pengirim"
                self.history.append(trace)
                self.current_trace = trace
                return trace
            stage_num += 1

        # Stage: RSA-OAEP Key Unwrapping
        status_unwrap = "OK" if (unwrapped_key is not None and not unwrap_error) else "FAIL"
        trace.stages.append(
            StageInfo(
                stage_number=stage_num,
                name="Pembukaan Kunci (RSA-OAEP Unwrap)",
                description=f"Private Key {receiver.capitalize()} membuka wrapped_key 256-byte untuk memulihkan K_AES 32-byte.",
                hex_data=unwrapped_key.hex().upper() if unwrapped_key else "DECRYPTION_FAILED",
                byte_length=len(unwrapped_key) if unwrapped_key else 0,
                text_preview="K_AES Berhasil Dipulihkan" if status_unwrap == "OK" else f"Gagal Unwrap: {unwrap_error}",
                status=status_unwrap,
            )
        )

        if status_unwrap == "FAIL":
            trace.final_status = "gagal_unwrap"
            trace.error_message = unwrap_error or "Gagal mendekripsi wrapped_key dengan RSA-OAEP"
            self.history.append(trace)
            self.current_trace = trace
            return trace
        stage_num += 1

        # Stage: Rekonstruksi AAD
        trace.stages.append(
            StageInfo(
                stage_number=stage_num,
                name="Rekonstruksi AAD Kanonikal",
                description="Penerima menyusun string kanonikal sender:receiver:counter untuk verifikasi integritas.",
                hex_data=aad.hex().upper(),
                byte_length=len(aad),
                text_preview=aad.decode("utf-8"),
                status="OK",
            )
        )
        stage_num += 1

        # Stage: Verifikasi Tag AES-GCM
        status_gcm = "OK" if verification_success else "FAIL"
        trace.stages.append(
            StageInfo(
                stage_number=stage_num,
                name="Verifikasi Tag Integritas AES-GCM",
                description="Tag 128-bit diverifikasi terhadap Ciphertext, Nonce, dan AAD.",
                hex_data=f"TAG:\n{tag.hex().upper()}\n\nNONCE:\n{nonce.hex().upper()}",
                byte_length=len(tag) + len(nonce),
                text_preview="Tag Valid & Autentik" if verification_success else f"Gagal Verifikasi: {verification_error}",
                status=status_gcm,
            )
        )

        if not verification_success:
            trace.final_status = "gagal_verifikasi"
            trace.error_message = verification_error or "Tag AES-GCM tidak cocok (Data telah dimodifikasi)"
            self.history.append(trace)
            self.current_trace = trace
            return trace

        # Stage 5: Ekstraksi Plaintext & Commit Counter
        pt_str = plaintext.decode("utf-8", errors="replace") if plaintext else ""
        trace.stages.append(
            StageInfo(
                stage_number=5,
                name="Dekripsi Plaintext & Commit Counter",
                description="Muatan berhasil didekripsi; counter tertinggi diperbarui secara persisten ke disk.",
                hex_data=plaintext.hex().upper() if plaintext else "",
                byte_length=len(plaintext) if plaintext else 0,
                text_preview=pt_str,
                status="OK",
            )
        )

        trace.final_status = "valid"
        self.history.append(trace)
        self.current_trace = trace
        return trace
