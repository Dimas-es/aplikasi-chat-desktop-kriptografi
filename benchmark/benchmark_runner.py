"""
Pelari Suite Benchmark Kinerja Kriptografi (Benchmark Runner).

Menjalankan pengujian performa komprehensif, mencakup:
1. Skema Hybrid (AES-256-GCM + RSA-2048-OAEP) untuk payload 64B s/d 1MB.
2. Skema RSA-Only (RSA-2048-OAEP) dan validasi batas 190 Byte.
3. Ekspor laporan tabel Markdown (benchmark/BENCHMARK_REPORT.md).
4. Ekspor data terstruktur JSON (benchmark/benchmark_results.json).
5. Ekspor grafik visualisasi perbandingan (benchmark/benchmark_comparison.png).

Dapat dijalankan langsung dengan:
    python -m benchmark.benchmark_runner
"""

import sys
import os
import json
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.hybrid_bench import run_hybrid_benchmark
from benchmark.rsa_only_bench import run_rsa_only_benchmark
from benchmark.visualizer import generate_markdown_report, plot_benchmark_charts


def run_all_benchmarks(iterations: int = 15):
    print("=" * 80)
    print(" SUITE PENGUJIAN BENCHMARK KINERJA KRIPTOGRAFI EMPIRIS")
    print(" Hybrid (AES-256-GCM + RSA-OAEP SHA-256) vs RSA-Only")
    print("=" * 80)
    print(f"[*] Menjalankan {iterations} repetisi per ukuran muatan untuk akurasi statistik...\n")

    start_time = time.perf_counter()

    # 1. Eksekusi Benchmark Hybrid
    print("[1/3] Menjalankan benchmark Skema Hybrid (64B s/d 1MB)...")
    hybrid_res = run_hybrid_benchmark(iterations=iterations)
    print("      -> Selesai.")

    # 2. Eksekusi Benchmark RSA-Only
    print("[2/3] Menjalankan benchmark Skema RSA-Only & Validasi Batas 190 Byte...")
    rsa_res = run_rsa_only_benchmark(iterations=iterations)
    print("      -> Selesai.")

    # 3. Pembangkitan Laporan & Grafik
    print("[3/3] Menyusun laporan dan grafik komparasi visual...")
    md_report = generate_markdown_report(hybrid_res, rsa_res)
    
    # Simpan laporan markdown
    report_path = "benchmark/BENCHMARK_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_report)
    print(f"[*] Laporan Markdown berhasil disimpan ke: {report_path}")

    # Simpan JSON mentah
    json_path = "benchmark/benchmark_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"hybrid": hybrid_res, "rsa_only": rsa_res}, f, indent=2)
    print(f"[*] Data statistik JSON berhasil disimpan ke: {json_path}")

    # Buat grafik Matplotlib jika modul tersedia
    chart_path = "benchmark/benchmark_comparison.png"
    plot_benchmark_charts(hybrid_res, rsa_res, output_path=chart_path)

    elapsed = time.perf_counter() - start_time

    # Tampilkan Ringkasan ke Konsol
    print("\n" + "=" * 80)
    print(" RINGKASAN HASIL PENGUKURAN")
    print("=" * 80)
    print(f"{'Payload':<12} | {'Hybrid (ms)':<14} | {'Throughput':<15} | {'RSA-Only (ms)':<16}")
    print("-" * 80)

    # Gabungkan data untuk tabel konsol
    rsa_dict = {s["label"]: s["mean_total_ms"] for s in rsa_res["supported"]}

    for h in hybrid_res:
        lbl = h["label"]
        h_ms = f"{h['mean_total_ms']:.3f} ms"
        tp = f"{h['throughput_mb_s']:.2f} MB/s"
        r_ms = f"{rsa_dict[lbl]:.3f} ms" if lbl in rsa_dict else "GAGAL (>=190B Limit)"
        print(f"{lbl:<12} | {h_ms:<14} | {tp:<15} | {r_ms:<16}")

    print("=" * 80)
    print(f"[*] Seluruh benchmark selesai dalam {elapsed:.2f} detik.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_all_benchmarks(iterations=10)
