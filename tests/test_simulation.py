"""
Unit Testing Otomatis untuk Modul Simulasi Skenario Serangan.

Menguji:
1. Deteksi modifikasi ciphertext, tag, nonce, dan metadata AAD (tampering).
2. Penolakan unwrap oleh kunci privat yang salah (wrong key).
3. Penolakan paket lama dan injeksi ulang (replay attack).
4. Demonstrasi matematis kebocoran akibat nonce-reuse.
"""

import pytest
from simulation.scenarios.tampering import run_tampering_scenario
from simulation.scenarios.wrong_key import run_wrong_key_scenario
from simulation.scenarios.replay import run_replay_scenario
from simulation.scenarios.nonce_reuse_demo import run_nonce_reuse_scenario
from simulation.scenarios.spoofing import run_spoofing_scenario


class TestSimulationScenarios:
    def test_tampering_scenario_all_detected(self):
        results = run_tampering_scenario()
        assert len(results) == 4
        for r in results:
            assert r["detected"] is True
            assert r["verdict"] == "PASSED"

    def test_wrong_key_scenario_properly_rejected(self):
        results = run_wrong_key_scenario()
        assert len(results) == 3
        # Sub-case 1: Eve unwrap must fail
        assert results[0]["attack_succeeded"] is False
        assert results[0]["verdict"] == "PASSED"
        # Sub-case 2: Random AES guess must fail
        assert results[1]["attack_succeeded"] is False
        assert results[1]["verdict"] == "PASSED"
        # Sub-case 3: Bob unwrap must succeed
        assert results[2]["security_defense_triggered"] is True
        assert results[2]["verdict"] == "PASSED"

    def test_replay_scenario_stale_and_duplicate_rejected(self):
        results = run_replay_scenario()
        assert len(results) == 3
        # Sub-case 1: Initial message valid
        assert results[0]["status_returned"] == "valid"
        assert results[0]["verdict"] == "PASSED"
        # Sub-case 2: Duplicate packet rejected
        assert results[1]["status_returned"] == "ditolak_replay"
        assert results[1]["verdict"] == "PASSED"
        # Sub-case 3: Stale counter rejected
        assert results[2]["status_returned"] == "ditolak_replay"
        assert results[2]["verdict"] == "PASSED"

    def test_nonce_reuse_demo_confirms_stream_leakage(self):
        res = run_nonce_reuse_scenario()
        assert res["security_verdict"] == "VULNERABILITY_CONFIRMED"
        assert res["recovered_fragment"] == "CONFIDENTIAL: "
        assert res["fully_recovered_match"] is True

    def test_spoofing_scenario_all_defenses_working(self):
        results = run_spoofing_scenario()
        assert len(results) == 4
        for r in results:
            assert r["detected"] is True
            assert r["verdict"] == "PASSED"
