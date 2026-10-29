"""
Skenario Serangan 2: Percobaan Pembukaan Kunci oleh Pihak Ketiga (Wrong Key / Unauthorized Decryption).

Tujuan Edukasi / Evaluasi:
Membuktikan bahwa:
1. Wrapped key (kunci simetris AES-256 yang dibungkus RSA-OAEP untuk Bob)
   TIDAK DAPAT dibuka oleh penyerang/pihak ketiga (Eve) menggunakan kunci privat miliknya sendiri.
2. Padding RSA-OAEP SHA-256 secara matematis akan gagal (KeyUnwrapError)
   karena kegagalan verifikasi mask generation function (MGF1) dan decoding OAEP.
3. Penyerang yang mencoba menebak kunci AES sembarang akan langsung ditolak oleh
   verifikasi tag AES-GCM.
"""

from typing import Dict, Any, List
from src.crypto.aes_gcm import generate_aes_key, generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm, AuthenticationError
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key, unwrap_key, KeyUnwrapError
from src.messaging.aad import build_canonical_aad


def run_wrong_key_scenario() -> List[Dict[str, Any]]:
    """
    Menjalankan simulasi serangan penyadapan di mana penyerang (Eve) berupaya
    mendekripsi muatan pesan yang ditujukan untuk Bob.
    """
    results = []

    # 1. Setup Aktor: Bob (Penerima Sah) dan Eve (Penyadap / Penyerang)
    priv_bob, pub_bob = generate_rsa_keypair(key_size=2048)
    priv_eve, pub_eve = generate_rsa_keypair(key_size=2048)

    # 2. Alice membungkus kunci AES untuk Bob
    real_aes_key = generate_aes_key()
    wrapped_key_for_bob = wrap_key(real_aes_key, pub_bob)

    # Alice mengenkripsi pesan rahasia
    nonce = generate_nonce()
    aad = build_canonical_aad("alice", "bob", 1)
    secret_text = "Dokumen proposal rahasia: https://internal.company/vault/doc-99"
    ct, tag = encrypt_aes_gcm(secret_text.encode("utf-8"), real_aes_key, nonce, aad)

    # -------------------------------------------------------------
    # Sub-kasus 1: Eve mencoba Unwrap kunci AES dengan Private Key Eve
    # -------------------------------------------------------------
    eve_unwrap_success = False
    unwrap_error_msg = ""
    try:
        unwrapped_key_by_eve = unwrap_key(wrapped_key_for_bob, priv_eve)
        eve_unwrap_success = True
    except KeyUnwrapError as exc:
        unwrap_error_msg = str(exc)

    results.append({
        "scenario": "Wrong RSA Key - Eve Mencoba Unwrap Kunci AES",
        "description": "Eve menyadap wrapped_key di jaringan dan mencoba membuka dengan RSA private key milik Eve",
        "expected_defense": "RSA-OAEP Padding / Hash Verification Failure (KeyUnwrapError)",
        "attack_succeeded": eve_unwrap_success,
        "security_defense_triggered": not eve_unwrap_success,
        "error_message": unwrap_error_msg,
        "verdict": "PASSED" if not eve_unwrap_success else "FAILED",
    })

    # -------------------------------------------------------------
    # Sub-kasus 2: Eve mencoba menebak kunci AES acak langsung ke Ciphertext
    # -------------------------------------------------------------
    guessed_aes_key = generate_aes_key()
    eve_aes_guess_success = False
    aes_error_msg = ""
    try:
        decrypt_aes_gcm(ct, tag, guessed_aes_key, nonce, aad)
        eve_aes_guess_success = True
    except AuthenticationError as exc:
        aes_error_msg = str(exc)

    results.append({
        "scenario": "Brute-force / Random Guess Kunci AES Simetris",
        "description": "Eve mencoba mendekripsi ciphertext menggunakan kunci AES-256 acak tanpa private key Bob",
        "expected_defense": "AES-GCM Tag Mismatch (AuthenticationError) - Ruang kunci 2^256",
        "attack_succeeded": eve_aes_guess_success,
        "security_defense_triggered": not eve_aes_guess_success,
        "error_message": aes_error_msg,
        "verdict": "PASSED" if not eve_aes_guess_success else "FAILED",
    })

    # -------------------------------------------------------------
    # Sub-kasus 3: Bob (Penerima Sah) berhasil membuka kunci dengan sempurna
    # -------------------------------------------------------------
    bob_success = False
    try:
        unwrapped_by_bob = unwrap_key(wrapped_key_for_bob, priv_bob)
        decrypted_by_bob = decrypt_aes_gcm(ct, tag, unwrapped_by_bob, nonce, aad)
        bob_success = (decrypted_by_bob.decode("utf-8") == secret_text)
    except Exception:
        bob_success = False

    results.append({
        "scenario": "Valid Recipient - Bob Membuka Pesan",
        "description": "Bob menggunakan private key miliknya sendiri yang cocok dengan public key penerima",
        "expected_defense": "Dekripsi Berhasil Sempurna (Integritas dan Kerahasiaan Terjamin)",
        "attack_succeeded": False,
        "security_defense_triggered": bob_success,
        "error_message": "None",
        "verdict": "PASSED" if bob_success else "FAILED",
    })

    return results


if __name__ == "__main__":
    import pprint
    res = run_wrong_key_scenario()
    pprint.pprint(res)
