"""
Penyusun Format Kanonikal Additional Authenticated Data (AAD).

Sesuai spesifikasi dokumen 05 - PERANCANGAN SISTEM dan 06 - WORKFLOW:
AAD mengikat metadata pengiriman (pengirim, penerima, dan counter) secara kriptografis
ke dalam authentication tag AES-256-GCM.
Format kanonikal: `<sender>:<receiver>:<counter>` dalam encoding UTF-8.
"""

from typing import Tuple


def build_canonical_aad(sender: str, receiver: str, counter: int) -> bytes:
    """
    Menyusun string representasi kanonikal AAD dan mengembalikannya dalam byte UTF-8.

    Args:
        sender: Identitas unik pengirim pesan (contoh: "alice").
        receiver: Identitas unik penerima pesan (contoh: "bob").
        counter: Nomor urutan pesan (integer monotonik naik, contoh: 1, 2, ...).

    Returns:
        bytes: Buffer UTF-8 dari "sender:receiver:counter".

    Raises:
        ValueError: Jika sender/receiver kosong atau counter bernilai negatif.
    """
    if not sender or not sender.strip():
        raise ValueError("Field sender tidak boleh kosong dalam penyusunan AAD.")
    if not receiver or not receiver.strip():
        raise ValueError("Field receiver tidak boleh kosong dalam penyusunan AAD.")
    if counter < 0:
        raise ValueError(f"Nilai counter tidak boleh negatif ({counter}).")

    canonical_str = f"{sender.strip()}:{receiver.strip()}:{counter}"
    return canonical_str.encode("utf-8")


def parse_canonical_aad(aad_bytes: bytes) -> Tuple[str, str, int]:
    """
    Mengekstrak kembali field sender, receiver, dan counter dari buffer AAD kanonikal.

    Args:
        aad_bytes: Buffer AAD kanonikal UTF-8.

    Returns:
        Tuple (sender, receiver, counter).

    Raises:
        ValueError: Jika format AAD tidak valid atau tidak memuat 3 elemen.
    """
    try:
        decoded_str = aad_bytes.decode("utf-8")
        parts = decoded_str.split(":")
        if len(parts) != 3:
            raise ValueError(f"Format AAD tidak valid: diharapkan 3 elemen, ditemukan {len(parts)}.")
        sender, receiver, counter_str = parts
        counter = int(counter_str)
        return sender, receiver, counter
    except Exception as exc:
        raise ValueError(f"Gagal mem-parse data AAD kanonikal: {exc}") from exc
