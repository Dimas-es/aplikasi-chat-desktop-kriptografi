"""
Benchmark Kinerja Skema Hybrid (AES-256-GCM + RSA-2048-OAEP SHA-256).

Mengukur secara empiris:
1. Waktu Enkripsi Pengirim (AES Keygen + RSA Wrap + AES-GCM Encrypt + Nonce)
2. Waktu Dekripsi Penerima (RSA Unwrap + AES-GCM Decrypt + Verifikasi Tag)
3. Total Latensi Roundtrip (ms)
4. Throughput Pemrosesan Data (MB/s)
Pada variasi ukuran pesan: 64B, 1KB, 10KB, 100KB, 1MB.
"""

import time
import statistics
import os
from typing import Dict, Any, List

from src.crypto.aes_gcm import generate_aes_key, generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key, unwrap_key
from src.messaging.aad import build_canonical_aad


PAYLOAD_SIZES = [
    ("64 B", 64),
    ("1 KB", 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1024 * 1024),
]


def run_hybrid_benchmark(iterations: int = 15) -> List[Dict[str, Any]]:
    """
    Menjalankan pengujian latensi dan throughput skema Hybrid untuk berbagai ukuran pesan.
    """
    # Siapkan pasangan kunci RSA penerima
    priv_bob, pub_bob = generate_rsa_keypair(key_size=2048)
    aad = build_canonical_aad("alice", "bob", 1)

    results = []

    for label, size_bytes in PAYLOAD_SIZES:
        payload = os.urandom(size_bytes)

        enc_latencies_ms = []
        dec_latencies_ms = []
        total_latencies_ms = []

        # Warm-up 1 iterasi
        warm_key = generate_aes_key()
        warm_wrapped = wrap_key(warm_key, pub_bob)
        warm_nonce = generate_nonce()
        warm_ct, warm_tag = encrypt_aes_gcm(payload, warm_key, warm_nonce, aad)
        warm_unwrapped = unwrap_key(warm_wrapped, priv_bob)
        decrypt_aes_gcm(warm_ct, warm_tag, warm_unwrapped, warm_nonce, aad)

        # Pengukuran iterasi aktual
        for _ in range(iterations):
            # 1. Pipeline Pengirim
            t0 = time.perf_counter()
            aes_key = generate_aes_key()
            wrapped_key = wrap_key(aes_key, pub_bob)
            nonce = generate_nonce()
            ct, tag = encrypt_aes_gcm(payload, aes_key, nonce, aad)
            t1 = time.perf_counter()

            # 2. Pipeline Penerima
            t2 = time.perf_counter()
            unwrapped_key = unwrap_key(wrapped_key, priv_bob)
            pt = decrypt_aes_gcm(ct, tag, unwrapped_key, nonce, aad)
            t3 = time.perf_counter()

            assert pt == payload, "Integritas dekripsi gagal!"

            enc_ms = (t1 - t0) * 1000.0
            dec_ms = (t3 - t2) * 1000.0
            total_ms = enc_ms + dec_ms

            enc_latencies_ms.append(enc_ms)
            dec_latencies_ms.append(dec_ms)
            total_latencies_ms.append(total_ms)

        mean_total = statistics.mean(total_latencies_ms)
        std_total = statistics.stdev(total_latencies_ms) if len(total_latencies_ms) > 1 else 0.0
        mean_enc = statistics.mean(enc_latencies_ms)
        mean_dec = statistics.mean(dec_latencies_ms)

        # Throughput dalam Megabyte per detik (MB/s)
        throughput_mbps = (size_bytes / (1024 * 1024)) / (mean_total / 1000.0)

        results.append({
            "label": label,
            "size_bytes": size_bytes,
            "iterations": iterations,
            "mean_enc_ms": mean_enc,
            "mean_dec_ms": mean_dec,
            "mean_total_ms": mean_total,
            "std_total_ms": std_total,
            "min_total_ms": min(total_latencies_ms),
            "max_total_ms": max(total_latencies_ms),
            "throughput_mb_s": throughput_mbps,
        })

    return results


if __name__ == "__main__":
    import pprint
    res = run_hybrid_benchmark(iterations=10)
    pprint.pprint(res)
