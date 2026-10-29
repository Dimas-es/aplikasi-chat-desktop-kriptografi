# Menjalankan Sistem Lokal (Setup & Demo)

Dokumen ini menyediakan panduan langkah-demi-langkah untuk menyiapkan lingkungan pengembangan, menginstal dependensi, menjalankan relay server dan klien chat desktop, memverifikasi pengujian unit resmi, serta mengeksekusi simulasi serangan dan benchmark kinerja pada mesin lokal.

---

## Prasyarat Lingkungan

- **Python 3.10+** (direkomendasikan Python 3.11 atau 3.12).
- **pip** (Python package installer).
- **Git** (version control).
- Sistem Operasi: Windows 10/11, macOS, atau Linux.

---

## 1. Persiapan Lingkungan & Instalasi Dependensi

Buka terminal pada direktori root proyek `kripto`:

```bash
# Navigasi ke direktori root proyek
cd kripto
```

### Membuat dan Mengaktifkan Virtual Environment

- **Pengguna Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  ```
- **Pengguna Linux / macOS (Bash/Zsh):**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### Menginstal Pustaka Dependensi

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> [!NOTE]
> Pustaka inti yang diinstal meliputi `cryptography` (implementasi OpenSSL/Rust untuk AES-GCM dan RSA-OAEP), `PyQt6` atau `customtkinter` (antarmuka desktop & visualizer), `pytest` (pengujian otomatis), dan `matplotlib` (visualisasi grafik benchmark).

---

## 2. Menjalankan Relay Server (Opsional / Perantara Komunikasi)

Relay server bertindak sebagai perantara transfer paket ciphertext zero-knowledge dan direktori kunci publik pada jaringan lokal:

**Terminal 1 (Relay Server):**
```bash
python -m relay.server --host 127.0.0.1 --port 8000
```
Output konfirmasi:
```text
[RELAY] Relay server berjalan di 127.0.0.1:8000
[RELAY] Menunggu koneksi klien...
```

---

## 3. Menjalankan Klien Chat Desktop

Untuk mendemonstrasikan percakapan dua arah secara lokal, jalankan dua jendela klien terpisah:

### Menjalankan Klien 1 (Alice)
**Terminal 2:**
```bash
python -m client.main --user alice --port 9001
```

### Menjalankan Klien 2 (Bob)
**Terminal 3:**
```bash
python -m client.main --user bob --port 9002
```

### Langkah Awal Klien:
1. **Inisialisasi Identitas:** Masukkan Display Name dan Passphrase untuk mengamankan kunci privat RSA-2048 di keystore lokal (`identity`).
2. **Pertukaran Public Key:** 
   - Pada mode relay: Klien otomatis mengunggah kunci publik (`PUBLISH_KEY`) dan mengambil kunci publik lawan bicara (`GET_KEY`).
   - Pada mode socket langsung: Kunci dipertukarkan saat handshake inisial sesi.
3. **Verifikasi Fingerprint:** Cocokkan nilai fingerprint SHA-256 yang tampil di UI Alice dan Bob untuk memastikan tidak ada manipulasi perantara (mitigasi MITM out-of-band).

---

## 4. Alur Panduan Demo & Evaluasi Akademik

1. **Buka Panel Visualizer:** Pada jendela Klien Alice, aktifkan panel **Visualizer (Hex & Byte Inspector)** di sisi kanan antarmuka.
2. **Kirim Pesan:** Ketik pesan teks (misalnya: *"Halo Bob, ini pesan rahasia tugas kriptografi! 🚀"*), lalu klik **Kirim**.
3. **Amati Transformasi Kriptografi di Pengirim (Alice):**
   - **Stage 1 (Plaintext):** Karakter string dikonversi ke stream byte UTF-8.
   - **Stage 2 (Kunci Simetris & Nonce):** Terlihat $K_{AES}$ acak 256-bit (64 karakter Hex) dan Nonce acak 96-bit (24 karakter Hex).
   - **Stage 3 (AAD):** Metadata kanonikal `alice:bob:1` terikat ke operasi autentikasi.
   - **Stage 4 (AES-GCM):** Ciphertext heksadesimal dan Authentication Tag 128-bit (16 byte Hex).
   - **Stage 5 (RSA-OAEP Wrap):** Kunci AES terbungkus menjadi 256 byte (512 karakter Hex) menggunakan kunci publik Bob (SHA-256 & MGF1-SHA-256).
   - **Stage 6 (Paket JSON):** Paket terserialisasi siap kirim.
4. **Amati Verifikasi dan Dekripsi di Penerima (Bob):**
   - Counter paket ($N=1$) diperiksa terhadap counter tertinggi sebelumnya ($N=0$). Lolos filter.
   - Kunci privat Bob membuka `wrapped_key` via RSA-OAEP $\to$ $K_{AES}$ dipulihkan.
   - Tag autentikasi dan AAD diverifikasi secara matematis $\to$ status `valid`.
   - Pesan didekripsi dan muncul di gelembung obrolan Bob dengan tanda centang verifikasi hijau.
   - Counter tertinggi Bob diperbarui secara persisten ke $N=1$.
5. **Uji Serangan Cepat Langsung dari GUI:**
   - **Tombol `🔁 Uji Replay`:** Menguji filter anti-replay secara instan. Paket yang pernah diproses akan langsung ditolak di **Tahap 1 (Anti-Replay)** dengan status `🚨 SERANGAN REPLAY DITOLAK!`. Jika terhubung ke Relay Server, duplikat paket juga dikirimkan ke lawan bicara untuk memicu penolakan di sisi penerima.
   - **Tombol `⚡ Tamper 1-Byte`:** Menguji pertahanan integritas AES-GCM dengan membalik 1 bit ciphertext. Sistem akan menolak paket di **Tahap 4 (AES-GCM Tag)** dengan status `⚠️ PERINGATAN INTEGRITAS GAGAL!`.

---

## 5. Menjalankan Pengujian Unit & Validasi NIST

Jalankan rangkaian tes otomatis untuk memverifikasi kebenaran algoritma terhadap vektor uji resmi *National Institute of Standards and Technology* (NIST SP 800-38D):

```bash
pytest tests/ -v
```

Hasil yang diharapkan (seluruh 66 test suite lolos):
```text
tests/test_crypto_aes.py::TestAESGCMCorrectness::test_encrypt_and_decrypt_standard PASSED
tests/test_crypto_aes.py::TestNISTKnownAnswerTests::test_nist_case_16_with_aad PASSED
tests/test_crypto_rsa.py::TestRSAOAEPExplicit::test_rsa_oaep_explicit_sha256_params PASSED
tests/test_crypto_rsa.py::TestRSAOAEPExplicit::test_rsa_oaep_max_payload_exact_190_bytes PASSED
tests/test_kdf.py::test_passphrase_key_derivation_deterministic PASSED
tests/test_storage.py::TestCounterStoreAntiReplay::test_anti_replay_verification_and_commit PASSED
tests/test_packet_schema.py::test_json_roundtrip_serialization PASSED
```

---

## 6. Menjalankan Simulasi Skenario Serangan

Untuk menguji ketahanan skema terhadap ancaman aktif, jalankan runner simulasi serangan dari terminal:

```bash
python -m simulation.runner
```

Pengujian mencakup:
1. **Tampering Ciphertext/Tag:** Mengubah 1 byte ciphertext/tag secara acak $\to$ AES-GCM melempar eksepsi verifikasi tag; status `gagal_verifikasi`.
2. **Wrong Private Key:** Mencoba unwrap kunci dengan private key pihak ketiga $\to$ RSA-OAEP padding check gagal; status `gagal_unwrap`.
3. **Replay Injection:** Mengirimkan ulang paket counter lama $\to$ filter anti-replay langsung menolak sebelum operasi RSA; status `ditolak_replay`.
4. **Nonce Reuse Demo (Bonus):** Menunjukkan bagaimana penggunaan nonce dan kunci yang sama pada AES-GCM membocorkan XOR dari dua plaintext yang berbeda.

Seluruh hasil simulasi terekam otomatis pada tabel evaluasi `attack_results`.

---

## 7. Menjalankan Suite Benchmark Kinerja

Untuk menghasilkan perbandingan empiris antara skema **Hybrid (AES-GCM + RSA-OAEP)** dan skema **RSA-Only (RSA-OAEP murni)**:

```bash
python -m benchmark.benchmark_runner
```

Proses benchmark akan:
1. Menguji variasi ukuran pesan: 64 Byte, 1 KB, 10 KB, 100 KB, dan 1 MB.
2. Melakukan pengulangan 10 hingga 30 kali per ukuran.
3. Mencatat rata-rata (*mean*), deviasi standar (*std dev*), dan *throughput* (KB/s).
4. Mendemonstrasikan bahwa skema RSA-Only mengalami *overflow error* pada ukuran $\ge 190$ byte.
5. Mengekspor grafik visual perbandingan ke `benchmark_results/performance_comparison.png`.

---

## Catatan Penelitian & Batasan Keamanan

- **Bukan Sistem Produksi:** Seluruh pengujian dijalankan pada localhost atau jaringan lokal (LAN) untuk tujuan evaluasi akademis dan demonstrasi perkuliahan.
- **Ketiadaan PKI:** Keaslian kunci publik bergantung pada verifikasi manual fingerprint SHA-256 out-of-band antar-pengguna.
- **Ketiadaan Forward Secrecy:** Kunci privat RSA jangka panjang harus dijaga kerahasiaannya; jika kunci ini terekspos, seluruh arsip ciphertext lama dapat dibuka.
- **Pembersihan State Pengujian:** Untuk mereset seluruh identitas, kontak, dan riwayat counter ke kondisi awal, hapus berkas penyimpanan lokal uji di folder `data/` sebelum memulai sesi baru.
