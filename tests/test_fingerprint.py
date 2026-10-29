"""
Unit Test untuk Perhitungan dan Verifikasi Fingerprint Kunci Publik SHA-256.
"""

from src.crypto.fingerprint import calculate_fingerprint, verify_fingerprint
from src.crypto.rsa_oaep import generate_rsa_keypair


class TestFingerprint:
    def test_calculate_fingerprint_format(self):
        _, pub = generate_rsa_keypair(key_size=2048)
        fp = calculate_fingerprint(pub)

        # Harus berupa 32 pasang heksadesimal kapital yang dipisahkan titik dua
        parts = fp.split(":")
        assert len(parts) == 32
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # Memastikan valid hex
            assert part == part.upper()  # Memastikan huruf kapital

    def test_verify_fingerprint_matching(self):
        _, pub = generate_rsa_keypair(key_size=2048)
        fp = calculate_fingerprint(pub)

        # Verifikasi dengan string yang identik
        assert verify_fingerprint(pub, fp) is True

        # Verifikasi harus kebal terhadap huruf kecil dan spasi/titik dua
        lowercase_fp = fp.lower()
        assert verify_fingerprint(pub, lowercase_fp) is True

        no_colons_fp = fp.replace(":", "")
        assert verify_fingerprint(pub, no_colons_fp) is True

    def test_verify_fingerprint_mismatch(self):
        _, pub1 = generate_rsa_keypair(key_size=2048)
        _, pub2 = generate_rsa_keypair(key_size=2048)

        fp1 = calculate_fingerprint(pub1)
        fp2 = calculate_fingerprint(pub2)

        assert fp1 != fp2
        # Kunci 1 dicocokkan dengan fingerprint Kunci 2 harus False (mencegah MITM)
        assert verify_fingerprint(pub1, fp2) is False
