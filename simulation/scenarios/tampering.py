"""
Skenario Serangan 1: Modifikasi Integritas & Manipulasi Data (Tampering Attack).

Tujuan Edukasi / Evaluasi:
Membuktikan bahwa algoritma AES-256-GCM dengan authentication tag 128-bit
dan AAD (Additional Authenticated Data) kanonikal mampu mendeteksi secara instan
perubahan sekecil 1 bit/byte pada:
1. Ciphertext (muatan pesan rahasia)
2. Authentication Tag
3. Nonce (Initialization Vector 96-bit)
4. Metadata AAD (pengirim, penerima, atau counter)
"""

from typing import Dict, Any, List
from src.crypto.aes_gcm import generate_aes_key, generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm, AuthenticationError
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key
from src.messaging.packet import MessagePacket
from src.messaging.aad import build_canonical_aad


def run_tampering_scenario() -> List[Dict[str, Any]]:
    """
    Menjalankan serangkaian pengujian manipulasi data (tampering) terhadap
    paket pesan terenkripsi AES-GCM dan memverifikasi kegagalan integritas.
    """
    results = []

    # Setup kunci dasar
    priv_bob, pub_bob = generate_rsa_keypair(key_size=2048)
    aes_key = generate_aes_key()
    nonce = generate_nonce()
    aad = build_canonical_aad("alice", "bob", 1)
    original_text = "Transfer rahasia sebesar Rp 10.000.000,- ke rekening 12345."
    ct, tag = encrypt_aes_gcm(original_text.encode("utf-8"), aes_key, nonce, aad)
    wrapped_key = wrap_key(aes_key, pub_bob)

    base_packet = MessagePacket(
        version=1,
        sender="alice",
        receiver="bob",
        counter=1,
        wrapped_key=wrapped_key,
        nonce=nonce,
        ciphertext=ct,
        tag=tag,
    )

    # -------------------------------------------------------------
    # Sub-kasus 1: Modifikasi 1 byte pada Ciphertext (Bit-flipping)
    # -------------------------------------------------------------
    corrupted_ct = bytearray(ct)
    corrupted_ct[0] ^= 0x01  # Balik 1 bit
    detected = False
    error_msg = ""
    try:
        decrypt_aes_gcm(bytes(corrupted_ct), tag, aes_key, nonce, aad)
    except AuthenticationError as exc:
        detected = True
        error_msg = str(exc)

    results.append({
        "scenario": "Tampering - 1 Byte Flip pada Ciphertext",
        "description": "Penyerang mengubah 1 byte muatan ciphertext di tengah transmisi jaringan",
        "target_field": "ciphertext",
        "expected_defense": "AES-GCM Tag Mismatch (AuthenticationError)",
        "detected": detected,
        "error_message": error_msg,
        "verdict": "PASSED" if detected else "FAILED",
    })

    # -------------------------------------------------------------
    # Sub-kasus 2: Modifikasi 1 byte pada Authentication Tag
    # -------------------------------------------------------------
    corrupted_tag = bytearray(tag)
    corrupted_tag[-1] ^= 0xFF
    detected = False
    error_msg = ""
    try:
        decrypt_aes_gcm(ct, bytes(corrupted_tag), aes_key, nonce, aad)
    except AuthenticationError as exc:
        detected = True
        error_msg = str(exc)

    results.append({
        "scenario": "Tampering - 1 Byte Modifikasi pada Authentication Tag",
        "description": "Penyerang memalsukan/merusak nilai tag autentikasi 128-bit",
        "target_field": "tag",
        "expected_defense": "AES-GCM GHASH Verification Failure",
        "detected": detected,
        "error_message": error_msg,
        "verdict": "PASSED" if detected else "FAILED",
    })

    # -------------------------------------------------------------
    # Sub-kasus 3: Modifikasi 1 byte pada Nonce
    # -------------------------------------------------------------
    corrupted_nonce = bytearray(nonce)
    corrupted_nonce[0] ^= 0xAA
    detected = False
    error_msg = ""
    try:
        decrypt_aes_gcm(ct, tag, aes_key, bytes(corrupted_nonce), aad)
    except AuthenticationError as exc:
        detected = True
        error_msg = str(exc)

    results.append({
        "scenario": "Tampering - 1 Byte Modifikasi pada Nonce (IV 96-bit)",
        "description": "Penyerang mengganti nilai IV / nonce 96-bit dengan nilai acak lain",
        "target_field": "nonce",
        "expected_defense": "AES-GCM Authentication Tag Mismatch",
        "detected": detected,
        "error_message": error_msg,
        "verdict": "PASSED" if detected else "FAILED",
    })

    # -------------------------------------------------------------
    # Sub-kasus 4: Modifikasi Metadata AAD (Perubahan Identitas Penerima)
    # -------------------------------------------------------------
    tampered_aad = build_canonical_aad("alice", "charlie", 1)  # Seharusnya bob
    detected = False
    error_msg = ""
    try:
        decrypt_aes_gcm(ct, tag, aes_key, nonce, tampered_aad)
    except AuthenticationError as exc:
        detected = True
        error_msg = str(exc)

    results.append({
        "scenario": "Tampering - Modifikasi Metadata AAD (Pengirim/Penerima)",
        "description": "Penyerang merutekan pesan ke 'charlie' sementara ciphertext asli untuk 'bob'",
        "target_field": "aad",
        "expected_defense": "Integrity Failure on Associated Data Binding",
        "detected": detected,
        "error_message": error_msg,
        "verdict": "PASSED" if detected else "FAILED",
    })

    return results


if __name__ == "__main__":
    import pprint
    res = run_tampering_scenario()
    pprint.pprint(res)
