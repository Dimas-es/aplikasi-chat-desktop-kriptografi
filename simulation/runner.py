"""
Orkestrator dan Pelari Seluruh Skenario Simulasi Serangan Kriptografi.

Menjalankan dan merangkum hasil dari 4 skenario:
1. Modifikasi Integritas & Bit-Flipping (AES-GCM Authenticated Encryption)
2. Percobaan Dekripsi Pihak Ketiga (RSA-OAEP Padding Verification)
3. Injeksi Pengulangan Paket (Anti-Replay Counter Filter)
4. Demonstrasi Bahaya Nonce-Reuse (Keystream Leakage & Crib-Dragging)

Dapat dijalankan langsung dengan:
    python -m simulation.runner
"""

import sys
import time
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from simulation.scenarios.tampering import run_tampering_scenario
from simulation.scenarios.wrong_key import run_wrong_key_scenario
from simulation.scenarios.replay import run_replay_scenario
from simulation.scenarios.nonce_reuse_demo import run_nonce_reuse_scenario
from simulation.scenarios.spoofing import run_spoofing_scenario


def print_banner():
    print("=" * 80)
    print(" SUITE SIMULASI PENGUJIAN ANCAMAN KEAMANAN & INTEGRITAS KRIPTOGRAFI")
    print(" Sistem Chat Desktop Hybrid (AES-256-GCM + RSA-2048-OAEP SHA-256)")
    print("=" * 80)


def print_section(title: str):
    print(f"\n[+] {title}")
    print("-" * 80)


def run_all_simulations() -> bool:
    print_banner()
    all_passed = True
    start_time = time.perf_counter()

    # -------------------------------------------------------------
    # 1. Skenario Tampering
    # -------------------------------------------------------------
    print_section("1. SKENARIO MODIFIKASI DATA & INTEGRITAS (TAMPERING)")
    tamper_results = run_tampering_scenario()
    for item in tamper_results:
        status_icon = "[OK] Lolos (Terdeteksi)" if item["verdict"] == "PASSED" else "[FAIL] GAGAL"
        print(f"  * Kasus: {item['scenario']}")
        print(f"    - Target Field     : {item['target_field']}")
        print(f"    - Pertahanan Kripto: {item['expected_defense']}")
        print(f"    - Status Evaluasi  : {status_icon}")
        if item["verdict"] != "PASSED":
            all_passed = False

    # -------------------------------------------------------------
    # 2. Skenario Wrong Key
    # -------------------------------------------------------------
    print_section("2. SKENARIO DEKRIPSI PIHAK KETIGA / KUNCI SALAH (WRONG KEY)")
    wrong_key_results = run_wrong_key_scenario()
    for item in wrong_key_results:
        status_icon = "[OK] Lolos (Aman)" if item["verdict"] == "PASSED" else "[FAIL] GAGAL"
        print(f"  * Kasus: {item['scenario']}")
        print(f"    - Deskripsi        : {item['description']}")
        print(f"    - Mekanisme Aman   : {item['expected_defense']}")
        print(f"    - Status Evaluasi  : {status_icon}")
        if item["verdict"] != "PASSED":
            all_passed = False

    # -------------------------------------------------------------
    # 3. Skenario Replay Attack
    # -------------------------------------------------------------
    print_section("3. SKENARIO SERANGAN PENGIRIMAN ULANG (REPLAY ATTACK)")
    replay_results = run_replay_scenario()
    for item in replay_results:
        status_icon = "[OK] Lolos" if item["verdict"] == "PASSED" else "[FAIL] GAGAL"
        print(f"  * Kasus: {item['scenario']}")
        print(f"    - Counter Paket    : #{item['counter']}")
        print(f"    - Status Diterima  : {item['status_returned']}")
        print(f"    - Status Evaluasi  : {status_icon}")
        if item["verdict"] != "PASSED":
            all_passed = False

    # -------------------------------------------------------------
    # 4. Skenario Nonce Reuse Demo
    # -------------------------------------------------------------
    print_section("4. DEMONSTRASI KELEMAHAN NONCE REUSE (CTR STREAM MODE)")
    nonce_demo = run_nonce_reuse_scenario()
    vuln_confirmed = (nonce_demo["security_verdict"] == "VULNERABILITY_CONFIRMED")
    print(f"  * Kasus: {nonce_demo['scenario']}")
    print(f"    - Deskripsi        : {nonce_demo['description']}")
    print(f"    - Known Crib (P1)  : \"{nonce_demo['known_crib']}\"")
    print(f"    - P2 Terekstrak    : \"{nonce_demo['recovered_fragment']}\"")
    print(f"    - Pemulihan Penuh  : {'BERHASIL (Keystream Bocor)' if nonce_demo['fully_recovered_match'] else 'GAGAL'}")
    print(f"    - Mitigasi Desain  : {nonce_demo['mitigation_in_app']}")
    if not vuln_confirmed:
        all_passed = False

    # -------------------------------------------------------------
    # 5. Skenario Pemalsuan Identitas (RSA-PSS Digital Signature)
    # -------------------------------------------------------------
    print_section("5. SKENARIO PEMALSUAN IDENTITAS & SIGNATURE (RSA-PSS)")
    spoofing_results = run_spoofing_scenario()
    for item in spoofing_results:
        status_icon = "[OK] Lolos" if item["verdict"] == "PASSED" else "[FAIL] GAGAL"
        print(f"  * Kasus: {item['scenario']}")
        print(f"    - Pelaku/Aktor     : {item['attacker']}")
        print(f"    - Ekspektasi Aman  : {item['expected_defense']}")
        print(f"    - Status Diterima  : {item['status_returned']}")
        print(f"    - Status Evaluasi  : {status_icon}")
        if item["verdict"] != "PASSED":
            all_passed = False

    elapsed = (time.perf_counter() - start_time) * 1000
    print("\n" + "=" * 80)
    print(f" HASIL AKHIR EVALUASI SIMULASI ANCAMAN: {'SEMUA LOLOS (100% AMAN)' if all_passed else 'DITEMUKAN KEGAGALAN'}")
    print(f" Total Durasi Eksekusi: {elapsed:.2f} ms")
    print("=" * 80 + "\n")

    return all_passed


if __name__ == "__main__":
    success = run_all_simulations()
    sys.exit(0 if success else 1)
