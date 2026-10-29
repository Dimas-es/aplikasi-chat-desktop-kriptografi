"""
Unit Testing Otomatis untuk Modul Benchmark Kriptografi.

Menguji:
1. Eksekusi pengujian latensi skema Hybrid (hybrid_bench).
2. Verifikasi batas matematis payload RSA-Only (rsa_only_bench).
3. Pembangkitan laporan Markdown (visualizer).
"""

import pytest
from benchmark.hybrid_bench import run_hybrid_benchmark
from benchmark.rsa_only_bench import run_rsa_only_benchmark
from benchmark.visualizer import generate_markdown_report


class TestBenchmarkSuite:
    def test_hybrid_benchmark_execution(self):
        # Gunakan 2 iterasi untuk kecepatan pengujian unit
        results = run_hybrid_benchmark(iterations=2)
        assert len(results) == 5
        for r in results:
            assert r["mean_total_ms"] > 0
            assert r["throughput_mb_s"] > 0
            assert r["size_bytes"] in [64, 1024, 10240, 102400, 1048576]

    def test_rsa_only_benchmark_limits(self):
        rsa_res = run_rsa_only_benchmark(iterations=2)
        assert rsa_res["max_allowed_payload_bytes"] == 190
        
        # Seluruh ukuran di bawah 190 byte harus terdukung
        assert len(rsa_res["supported"]) == 3
        for s in rsa_res["supported"]:
            assert s["status"] == "SUPPORTED"
            assert s["mean_total_ms"] > 0

        # Seluruh ukuran >= 190 byte harus terbukti gagal (PayloadTooLarge)
        assert len(rsa_res["unsupported"]) == 5
        for u in rsa_res["unsupported"]:
            assert u["failed_as_expected"] is True
            assert u["status"] == "UNSUPPORTED_EXCEEDS_CAPACITY"

    def test_markdown_report_generation(self):
        h_res = run_hybrid_benchmark(iterations=1)
        r_res = run_rsa_only_benchmark(iterations=1)
        md = generate_markdown_report(h_res, r_res)
        assert "# Laporan Hasil Benchmark Kinerja Kriptografi" in md
        assert "AES-256-GCM + RSA-2048-OAEP" in md
        assert "190 Byte" in md
