"""
Definisi Status Siklus Hidup Pesan (Message Lifecycle Status).

Sesuai spesifikasi dokumen 05 - PERANCANGAN SISTEM Bagian 6:
- terkirim: Paket berhasil dikirim oleh pengirim.
- valid: Paket lolos filter anti-replay, unwrap RSA-OAEP berhasil, dan tag AES-GCM cocok.
- ditolak_replay: Counter paket <= counter tertinggi yang pernah terverifikasi.
- gagal_unwrap: Unwrap kunci simetris dengan RSA-OAEP gagal (private key salah atau corrupt).
- gagal_verifikasi: Authentication tag AES-GCM tidak cocok (manipulasi ciphertext/tag/AAD).
"""

from enum import Enum


class MessageStatus(str, Enum):
    """Status verifikasi dan pengolahan pesan."""
    SENT = "terkirim"
    VALID = "valid"
    REPLAY_REJECTED = "ditolak_replay"
    SIGNATURE_FAILED = "gagal_signature"
    UNWRAP_FAILED = "gagal_unwrap"
    VERIFICATION_FAILED = "gagal_verifikasi"

    @property
    def is_successful(self) -> bool:
        """Memeriksa apakah status pesan merupakan kondisi berhasil (terkirim atau valid)."""
        return self in (MessageStatus.SENT, MessageStatus.VALID)

    @property
    def is_security_rejection(self) -> bool:
        """Memeriksa apakah status merupakan penolakan keamanan aktif."""
        return self in (
            MessageStatus.REPLAY_REJECTED,
            MessageStatus.SIGNATURE_FAILED,
            MessageStatus.UNWRAP_FAILED,
            MessageStatus.VERIFICATION_FAILED,
        )
