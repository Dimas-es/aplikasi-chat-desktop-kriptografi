"""
Visualisasi dan Pembangkitan Laporan Statistik Komparasi Kinerja Kriptografi.

Menghasilkan:
1. Tabel perbandingan teks/markdown berformat rapi (ASCII & Markdown).
2. Grafik publikasi (High-DPI PNG) menggunakan Matplotlib:
   - Grafik 1: Latensi Roundtrip (ms) Hybrid vs RSA-Only (Batas 190 Byte).
   - Grafik 2: Skalabilitas Throughput Skema Hybrid (MB/s) hingga 1 MB.
"""

import os
from typing import Dict, Any, List

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-GUI backend aman untuk script & testing
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def generate_markdown_report(hybrid_res: List[Dict[str, Any]], rsa_res: Dict[str, Any]) -> str:
    """Menyusun laporan perbandingan dalam format Markdown akademik."""
    lines = []
    lines.append("# Laporan Hasil Benchmark Kinerja Kriptografi")
    lines.append("\n## 1. Performa Skema Hybrid (AES-256-GCM + RSA-2048-OAEP SHA-256)\n")
    lines.append("| Ukuran Payload | Enkripsi (ms) | Dekripsi (ms) | Total Roundtrip (ms) | Std Dev (ms) | Throughput (MB/s) |")
    lines.append("|---|---|---|---|---|---|")

    for h in hybrid_res:
        lines.append(
            f"| **{h['label']}** ({h['size_bytes']:,} B) | "
            f"{h['mean_enc_ms']:.3f} | {h['mean_dec_ms']:.3f} | "
            f"{h['mean_total_ms']:.3f} | ±{h['std_total_ms']:.3f} | "
            f"**{h['throughput_mb_s']:.2f}** |"
        )

    lines.append("\n## 2. Performa Skema RSA-Only (RSA-2048-OAEP SHA-256)\n")
    lines.append(f"**Batas Maksimum Muatan Matematis:** {rsa_res['max_allowed_payload_bytes']} Byte.\n")
    lines.append("| Ukuran Payload | Status Dukungan | Enkripsi (ms) | Dekripsi (ms) | Total (ms) | Throughput (MB/s) |")
    lines.append("|---|---|---|---|---|---|")

    for s in rsa_res["supported"]:
        lines.append(
            f"| **{s['label']}** ({s['size_bytes']} B) | "
            f"TERDUKUNG | {s['mean_enc_ms']:.3f} | {s['mean_dec_ms']:.3f} | "
            f"{s['mean_total_ms']:.3f} | {s['throughput_mb_s']:.2f} |"
        )

    for u in rsa_res["unsupported"]:
        lines.append(
            f"| **{u['label']}** ({u['size_bytes']:,} B) | "
            f"**GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |"
        )

    lines.append("\n## 3. Kesimpulan Evaluasi Kinerja\n")
    lines.append(
        "- **Kapasitas Ukuran:** Skema RSA-Only secara matematis tidak dapat mengenkripsi payload >= 190 byte "
        "karena batasan padding OAEP SHA-256 ($k - 2hLen - 2 = 190$ B). Sebaliknya, skema Hybrid mampu "
        "menangani payload 1 MB dan lebih besar secara mulus."
    )
    lines.append(
        "- **Efisiensi:** Skema Hybrid membatasi komputasi asimetris RSA hanya pada kunci simetris 32-byte, "
        "sehingga waktu eksekusi untuk pesan berukuran besar tetap didominasi oleh kecepatan perangkat keras AES-NI."
    )

    return "\n".join(lines)


def plot_benchmark_charts(
    hybrid_res: List[Dict[str, Any]],
    rsa_res: Dict[str, Any],
    output_path: str = "benchmark/benchmark_comparison.png",
) -> bool:
    """
    Membuat grafik visualisasi komparatif dan menyimpannya sebagai berkas gambar PNG.
    """
    if not HAS_MATPLOTLIB:
        print("[!] Matplotlib tidak terpasang. Melewati pembangkitan grafik gambar.")
        return False

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), dpi=150)
    fig.patch.set_facecolor("#1A1A1A")

    for ax in (ax1, ax2):
        ax.set_facecolor("#222222")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")
        for spine in ax.spines.values():
            spine.set_color("#444444")
        ax.grid(True, linestyle="--", alpha=0.3, color="#666666")

    # -------------------------------------------------------------
    # Plot 1: Latensi Total (ms) vs Ukuran Payload
    # -------------------------------------------------------------
    h_labels = [h["label"] for h in hybrid_res]
    h_totals = [h["mean_total_ms"] for h in hybrid_res]

    r_labels = [s["label"] for s in rsa_res["supported"]]
    r_totals = [s["mean_total_ms"] for s in rsa_res["supported"]]

    ax1.plot(h_labels, h_totals, marker="o", linewidth=2.5, color="#00B0FF", label="Skema Hybrid (AES+RSA)")
    
    # Titik untuk RSA didukung
    ax1.plot(r_labels, r_totals, marker="s", linewidth=2, color="#FF9100", label="RSA-Only (Didukung <190B)")
    
    # Garis penanda batas 190 Byte
    ax1.axvline(x=len(r_labels) - 0.5, color="#FF5252", linestyle=":", linewidth=2, label="Batas Maksimum RSA (190B)")

    ax1.set_title("Perbandingan Latensi Total Roundtrip (ms)", fontsize=13, fontweight="bold", pad=12)
    ax1.set_xlabel("Ukuran Muatan (Payload)", fontsize=11)
    ax1.set_ylabel("Waktu Pemrosesan (ms)", fontsize=11)
    ax1.legend(facecolor="#2A2A2A", edgecolor="#444444", labelcolor="white")

    # -------------------------------------------------------------
    # Plot 2: Throughput Skema Hybrid (MB/s)
    # -------------------------------------------------------------
    h_throughputs = [h["throughput_mb_s"] for h in hybrid_res]
    bars = ax2.bar(h_labels, h_throughputs, color="#00E676", width=0.5, edgecolor="#00B248")

    for bar, val in zip(bars, h_throughputs):
        height = bar.get_height()
        ax2.annotate(
            f"{val:.1f} MB/s",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
            color="white",
            fontweight="bold",
        )

    ax2.set_title("Throughput Skema Hybrid (MB/s)", fontsize=13, fontweight="bold", pad=12)
    ax2.set_xlabel("Ukuran Muatan (Payload)", fontsize=11)
    ax2.set_ylabel("Kecepatan Throughput (MB/s)", fontsize=11)

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()

    print(f"[*] Grafik perbandingan kinerja berhasil disimpan ke: {output_path}")
    return True
