"""
Skenario Serangan 5: Pemalsuan Identitas & Pelanggaran Non-Repudiation (Spoofing Attack).

Tujuan Edukasi / Evaluasi:
Membuktikan bahwa skema Tanda Tangan Digital RSA-PSS (PKCS#1 v2.2 / RFC 8017)
secara instan mampu mendeteksi dan menolak:
1. Pemalsuan nama pengirim (Eve menyamar sebagai Alice menggunakan kunci palsu).
2. Modifikasi bit pada tanda tangan digital (Corrupted Signature).
3. Modifikasi muatan ciphertext yang terikat tanda tangan kanonikal.
4. Memvalidasi bahwa pesan sah bertanda tangan dari pengirim asli diterima dengan sukses.
"""

from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.aes_gcm import generate_aes_key, generate_nonce, encrypt_aes_gcm
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key, public_key_to_pem
from src.crypto.rsa_pss import sign_data, verify_signature
from src.messaging.packet import MessagePacket
from src.messaging.aad import build_canonical_aad
from src.messaging.status import MessageStatus
from client.controllers.chat_controller import ChatController
import tempfile
import os


def run_spoofing_scenario() -> List[Dict[str, Any]]:
    """
    Menjalankan serangkaian pengujian pemalsuan identitas (spoofing) dan
    memverifikasi efektivitas pertahanan tanda tangan digital RSA-PSS.
    """
    results = []

    # Setup database sementara untuk simulasi
    with tempfile.TemporaryDirectory() as temp_dir:
        alice_db = os.path.join(temp_dir, "alice.db")
        bob_db = os.path.join(temp_dir, "bob.db")
        eve_db = os.path.join(temp_dir, "eve.db")

        ctrl_alice = ChatController(db_path=alice_db)
        ctrl_bob = ChatController(db_path=bob_db)
        ctrl_eve = ChatController(db_path=eve_db)

        ctrl_alice.register_identity("alice", "Alice Sah", "pass_alice_123")
        ctrl_bob.register_identity("bob", "Bob Penerima", "pass_bob_123")
        ctrl_eve.register_identity("eve", "Eve Penyerang", "pass_eve_123")

        # Pertukaran buku kontak awal
        ctrl_bob.add_contact("alice", "Alice Sah", ctrl_alice.get_public_key_pem())
        ctrl_alice.add_contact("bob", "Bob Penerima", ctrl_bob.get_public_key_pem())

        # -------------------------------------------------------------
        # Sub-kasus 1: Pesan Sah dengan RSA-PSS Signature Valid
        # -------------------------------------------------------------
        valid_packet, _ = ctrl_alice.send_message("bob", "Otorisasi transfer resmi dari Alice.")
        status_1, text_1, trace_1 = ctrl_bob.receive_message(valid_packet)

        case_1_passed = (status_1 == MessageStatus.VALID and text_1 is not None)
        results.append({
            "scenario": "Pesan Sah Bertanda Tangan RSA-PSS",
            "attacker": "None (Pengirim Asli)",
            "expected_defense": "Signature valid dan identitas Alice terverifikasi",
            "status_returned": status_1.value,
            "detected": case_1_passed,
            "verdict": "PASSED" if case_1_passed else "FAILED",
        })

        # -------------------------------------------------------------
        # Sub-kasus 2: Eve Menyamar sebagai Alice (Identity Spoofing)
        # Eve membuat paket dengan sender 'alice', tetapi menandatanganinya
        # menggunakan kunci privat milik Eve (karena tidak punya kunci Alice)
        # -------------------------------------------------------------
        k_aes = generate_aes_key()
        nonce = generate_nonce()
        aad = build_canonical_aad("alice", "bob", 2)
        ct, tag = encrypt_aes_gcm(b"Transfer palsu $1,000,000 ke Eve!", k_aes, nonce, aad)
        
        # Bungkus kunci dengan kunci publik Bob
        wrapped_key = wrap_key(k_aes, ctrl_bob.public_key)

        spoofed_packet = MessagePacket(
            version=2,
            sender="alice",  # Eve memalsukan header pengirim
            receiver="bob",
            counter=2,
            wrapped_key=wrapped_key,
            nonce=nonce,
            ciphertext=ct,
            tag=tag,
        )
        # Eve menandatangani payload dengan kunci privat Eve sendiri
        sig_payload = spoofed_packet.compute_signature_payload()
        spoofed_packet.signature = sign_data(ctrl_eve.private_key, sig_payload)

        status_2, text_2, trace_2 = ctrl_bob.receive_message(spoofed_packet)
        case_2_passed = (status_2 == MessageStatus.SIGNATURE_FAILED and text_2 is None)
        results.append({
            "scenario": "Pemalsuan Identitas (Eve mengaku Alice)",
            "attacker": "Eve Eavesdropper",
            "expected_defense": "Ditolak: Signature Eve tidak cocok dengan Public Key Alice",
            "status_returned": status_2.value,
            "detected": case_2_passed,
            "verdict": "PASSED" if case_2_passed else "FAILED",
        })

        # -------------------------------------------------------------
        # Sub-kasus 3: Modifikasi Bit pada Tanda Tangan (Corrupted Sig)
        # -------------------------------------------------------------
        corrupted_sig_packet, _ = ctrl_alice.send_message("bob", "Pesan penting kedua")
        bad_sig = bytearray(corrupted_sig_packet.signature)
        bad_sig[0] ^= 0xFF  # Flip 1 byte pada tanda tangan
        corrupted_sig_packet.signature = bytes(bad_sig)

        status_3, text_3, trace_3 = ctrl_bob.receive_message(corrupted_sig_packet)
        case_3_passed = (status_3 == MessageStatus.SIGNATURE_FAILED and text_3 is None)
        results.append({
            "scenario": "Modifikasi Byte Tanda Tangan Digital",
            "attacker": "Man-in-the-Middle (MitM)",
            "expected_defense": "Ditolak: Verifikasi kriptografis RSA-PSS gagal",
            "status_returned": status_3.value,
            "detected": case_3_passed,
            "verdict": "PASSED" if case_3_passed else "FAILED",
        })

        # -------------------------------------------------------------
        # Sub-kasus 4: Modifikasi Ciphertext pada Paket Bertanda Tangan
        # -------------------------------------------------------------
        tampered_pkt, _ = ctrl_alice.send_message("bob", "Pesan integritas ketiga")
        bad_ct = bytearray(tampered_pkt.ciphertext)
        bad_ct[0] ^= 0x55
        tampered_pkt.ciphertext = bytes(bad_ct)

        status_4, text_4, trace_4 = ctrl_bob.receive_message(tampered_pkt)
        case_4_passed = (status_4 == MessageStatus.SIGNATURE_FAILED and text_4 is None)
        results.append({
            "scenario": "Modifikasi Ciphertext pada Paket Bertanda Tangan",
            "attacker": "Man-in-the-Middle (MitM)",
            "expected_defense": "Ditolak: Signature kanonikal mendeteksi perubahan ciphertext",
            "status_returned": status_4.value,
            "detected": case_4_passed,
            "verdict": "PASSED" if case_4_passed else "FAILED",
        })

        ctrl_alice.close()
        ctrl_bob.close()
        ctrl_eve.close()

    return results


if __name__ == "__main__":
    print("[*] Menjalankan Simulasi Skenario Pemalsuan Identitas...")
    for res in run_spoofing_scenario():
        print(f"  - {res['scenario']}: {res['verdict']} ({res['status_returned']})")
