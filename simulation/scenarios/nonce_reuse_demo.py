"""
Skenario Serangan 4 (Edukasi / Bonus): Demonstrasi Dampak Nonce Reuse pada AES-GCM.

Tujuan Edukasi / Evaluasi:
Mendemonstrasikan secara nyata mengapa pengulangan Nonce (IV) pada algoritma
berbasis stream/counter seperti AES-GCM (AES-CTR) berakibat fatal:
1. Pembatalan Keystream (Keystream Cancellation):
   C1 = P1 XOR S,  C2 = P2 XOR S  ==>  C1 XOR C2 = P1 XOR P2.
2. Serangan Known-Plaintext / Crib-Dragging:
   Jika penyerang mengetahui atau menebak sebagian isi P1 (misal: "CONFIDENTIAL:"),
   maka P2 dapat langsung diungkap: P2 = (C1 XOR C2) XOR P1.
3. Mengapa sistem obrolan ini aman:
   Proyek ini menggunakan nonce acak 96-bit (os.urandom(12)) yang dibangkitkan
   secara independen pada setiap pengiriman pesan (ruang probabilitas 2^96).
"""

from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from src.crypto.aes_gcm import generate_aes_key, generate_nonce


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Melakukan operasi XOR byte-by-byte terhadap dua deretan biner."""
    return bytes(x ^ y for x, y in zip(a, b))


def run_nonce_reuse_scenario() -> Dict[str, Any]:
    """
    Mensimulasikan insiden kegagalan kriptografi akibat penggunaan ulang nonce (two-time pad)
    pada AES-CTR/GCM dan mendemonstrasikan keberhasilan serangan crib-dragging.
    """
    key = generate_aes_key()  # 256-bit AES Key
    fixed_nonce = generate_nonce()  # Nonce yang sengaja dipakai 2 kali (FATAL FLAW)

    # Dua pesan rahasia yang berbeda dengan panjang byte sama persis
    p1 = b"CONFIDENTIAL: PIN ATM Anda adalah 9876."
    p2 = b"CONFIDENTIAL: PIN ATM Anda adalah 5432."

    # Enkripsi P1 dan P2 dengan Key dan Nonce yang sama persis
    # (Catatan: Menggunakan cipher AES-GCM)
    cipher_1 = Cipher(algorithms.AES(key), modes.GCM(fixed_nonce))
    encryptor_1 = cipher_1.encryptor()
    c1 = encryptor_1.update(p1) + encryptor_1.finalize()

    cipher_2 = Cipher(algorithms.AES(key), modes.GCM(fixed_nonce))
    encryptor_2 = cipher_2.encryptor()
    c2 = encryptor_2.update(p2) + encryptor_2.finalize()

    # 1. Penyerang menyadap C1 dan C2 di jaringan
    # Hitung C1 XOR C2
    c1_xor_c2 = xor_bytes(c1, c2)

    # 2. Penyerang memiliki "crib" (tebakan pola plaintext umum di sistem perbankan)
    # Penyerang menebak bahwa awal pesan P1 adalah "CONFIDENTIAL: "
    known_crib_p1 = b"CONFIDENTIAL: "
    
    # 3. Penyerang mengekstrak sebagian pesan P2 tanpa mengetahui KUNCI AES sama sekali!
    recovered_fragment_p2 = xor_bytes(c1_xor_c2[:len(known_crib_p1)], known_crib_p1)

    # 4. Jika penyerang mengetahui seluruh P1:
    fully_recovered_p2 = xor_bytes(c1_xor_c2, p1)

    success = (recovered_fragment_p2 == p2[:len(known_crib_p1)]) and (fully_recovered_p2 == p2)

    return {
        "scenario": "Nonce Reuse - Keystream Cancellation & Crib-Dragging",
        "description": "Penggunaan ulang nonce 96-bit yang sama pada dua plaintext berbeda dengan kunci AES identik",
        "p1_length": len(p1),
        "p2_length": len(p2),
        "c1_hex": c1.hex(),
        "c2_hex": c2.hex(),
        "c1_xor_c2_hex": c1_xor_c2.hex(),
        "known_crib": known_crib_p1.decode("utf-8"),
        "recovered_fragment": recovered_fragment_p2.decode("utf-8", errors="replace"),
        "fully_recovered_match": (fully_recovered_p2 == p2),
        "security_verdict": "VULNERABILITY_CONFIRMED" if success else "ATTACK_FAILED",
        "mitigation_in_app": "Proyek ini mewajibkan nonce 96-bit unik acak (os.urandom(12)) per paket sehingga C1 XOR C2 tidak pernah berkorelasi.",
    }


if __name__ == "__main__":
    import pprint
    res = run_nonce_reuse_scenario()
    pprint.pprint(res)
