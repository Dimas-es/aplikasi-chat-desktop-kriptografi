# Laporan Hasil Benchmark Kinerja Kriptografi

## 1. Performa Skema Hybrid (AES-256-GCM + RSA-2048-OAEP SHA-256)

| Ukuran Payload | Enkripsi (ms) | Dekripsi (ms) | Total Roundtrip (ms) | Std Dev (ms) | Throughput (MB/s) |
|---|---|---|---|---|---|
| **64 B** (64 B) | 0.052 | 0.645 | 0.698 | ±0.016 | **0.09** |
| **1 KB** (1,024 B) | 0.065 | 0.642 | 0.707 | ±0.060 | **1.38** |
| **10 KB** (10,240 B) | 0.072 | 0.748 | 0.820 | ±0.174 | **11.91** |
| **100 KB** (102,400 B) | 0.091 | 0.692 | 0.783 | ±0.036 | **124.71** |
| **1 MB** (1,048,576 B) | 1.533 | 2.129 | 3.662 | ±0.323 | **273.08** |

## 2. Performa Skema RSA-Only (RSA-2048-OAEP SHA-256)

**Batas Maksimum Muatan Matematis:** 190 Byte.

| Ukuran Payload | Status Dukungan | Enkripsi (ms) | Dekripsi (ms) | Total (ms) | Throughput (MB/s) |
|---|---|---|---|---|---|
| **64 B** (64 B) | TERDUKUNG | 0.036 | 0.618 | 0.654 | 0.09 |
| **128 B** (128 B) | TERDUKUNG | 0.036 | 0.613 | 0.649 | 0.19 |
| **190 B (Batas Maksimum)** (190 B) | TERDUKUNG | 0.035 | 0.664 | 0.699 | 0.26 |
| **191 B (Melebihi Batas 1 Byte)** (191 B) | **GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |
| **1 KB** (1,024 B) | **GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |
| **10 KB** (10,240 B) | **GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |
| **100 KB** (102,400 B) | **GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |
| **1 MB** (1,048,576 B) | **GAGAL (Melebihi Batas)** | N/A | N/A | N/A | 0.00 (Kapasitas Terlampaui) |

## 3. Kesimpulan Evaluasi Kinerja

- **Kapasitas Ukuran:** Skema RSA-Only secara matematis tidak dapat mengenkripsi payload >= 190 byte karena batasan padding OAEP SHA-256 ($k - 2hLen - 2 = 190$ B). Sebaliknya, skema Hybrid mampu menangani payload 1 MB dan lebih besar secara mulus.
- **Efisiensi:** Skema Hybrid membatasi komputasi asimetris RSA hanya pada kunci simetris 32-byte, sehingga waktu eksekusi untuk pesan berukuran besar tetap didominasi oleh kecepatan perangkat keras AES-NI.