"""
Benchmark dan Pembuktian Batas Muatan Skema RSA-Only (RSA-2048-OAEP SHA-256).

Tujuan Penelitian & Evaluasi:
1. Membuktikan secara empiris dan matematis batas maksimum ukuran muatan RSA-OAEP:
   Max Payload = Modulus_Byte - (2 * Hash_Length) - 2
   Untuk RSA-2048 (256 Byte) dan SHA-256 (32 Byte):
   Max = 256 - 2(32) - 2 = 190 Byte.
2. Mengukur latensi RSA-Only pada muatan yang didukung (< 190 Byte): 64 B, 128 B, 189 B.
3. Mendokumentasikan kegagalan mutlak (*Mathematical Infeasibility*) pada payload >= 190 Byte:
   (190 B, 1 KB, 10 KB, 100 KB, 1 MB).
"""

import time
import os
import statistics
from typing import Dict, Any, List

from src.crypto.rsa_oaep import (
    generate_rsa_keypair,
    get_oaep_padding,
    calculate_max_oaep_payload,
)


RSA_SUPPORTED_SIZES = [
    ("64 B", 64),
    ("128 B", 128),
    ("190 B (Batas Maksimum)", 190),
]

RSA_UNSUPPORTED_SIZES = [
    ("191 B (Melebihi Batas 1 Byte)", 191),
    ("1 KB", 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1024 * 1024),
]


def run_rsa_only_benchmark(iterations: int = 15) -> Dict[str, Any]:
    """
    Menjalankan benchmark performa RSA-Only pada ukuran valid dan memvalidasi
    eksepsi PayloadTooLarge / ValueError pada ukuran melebihi batas.
    """
    priv, pub = generate_rsa_keypair(key_size=2048)
    padding_obj = get_oaep_padding()
    max_allowed = calculate_max_oaep_payload(2048)

    supported_results = []
    unsupported_results = []

    # 1. Uji Ukuran yang Didukung (< 190 B)
    for label, size_bytes in RSA_SUPPORTED_SIZES:
        payload = os.urandom(size_bytes)
        enc_ms_list = []
        dec_ms_list = []
        total_ms_list = []

        # Warm-up
        warm_ct = pub.encrypt(payload, padding_obj)
        priv.decrypt(warm_ct, padding_obj)

        for _ in range(iterations):
            t0 = time.perf_counter()
            ct = pub.encrypt(payload, padding_obj)
            t1 = time.perf_counter()

            t2 = time.perf_counter()
            pt = priv.decrypt(ct, padding_obj)
            t3 = time.perf_counter()

            assert pt == payload

            enc_ms = (t1 - t0) * 1000.0
            dec_ms = (t3 - t2) * 1000.0
            enc_ms_list.append(enc_ms)
            dec_ms_list.append(dec_ms)
            total_ms_list.append(enc_ms + dec_ms)

        mean_total = statistics.mean(total_ms_list)
        throughput_mbps = (size_bytes / (1024 * 1024)) / (mean_total / 1000.0)

        supported_results.append({
            "label": label,
            "size_bytes": size_bytes,
            "status": "SUPPORTED",
            "mean_enc_ms": statistics.mean(enc_ms_list),
            "mean_dec_ms": statistics.mean(dec_ms_list),
            "mean_total_ms": mean_total,
            "std_total_ms": statistics.stdev(total_ms_list) if len(total_ms_list) > 1 else 0.0,
            "throughput_mb_s": throughput_mbps,
        })

    # 2. Uji Ukuran Melebihi Batas (>= 190 B)
    for label, size_bytes in RSA_UNSUPPORTED_SIZES:
        payload = os.urandom(size_bytes)
        failed_as_expected = False
        error_name = ""
        error_msg = ""

        try:
            pub.encrypt(payload, padding_obj)
        except ValueError as exc:
            failed_as_expected = True
            error_name = type(exc).__name__
            error_msg = str(exc)

        unsupported_results.append({
            "label": label,
            "size_bytes": size_bytes,
            "status": "UNSUPPORTED_EXCEEDS_CAPACITY",
            "failed_as_expected": failed_as_expected,
            "error_type": error_name,
            "reason": f"Ukuran payload {size_bytes}B >= batas maksimum {max_allowed}B untuk RSA-2048 OAEP SHA-256.",
        })

    return {
        "max_allowed_payload_bytes": max_allowed,
        "supported": supported_results,
        "unsupported": unsupported_results,
    }


if __name__ == "__main__":
    import pprint
    res = run_rsa_only_benchmark(iterations=10)
    pprint.pprint(res)
