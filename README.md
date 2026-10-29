# Simulasi Enkripsi Hybrid (AES-256-GCM & RSA-2048-OAEP SHA-256)

Prototipe aplikasi chat desktop berbasis Python dengan keamanan kriptografi hybrid yang menggabungkan efisiensi **AES-256-GCM** untuk kerahasiaan & integritas isi pesan serta **RSA-2048-OAEP (SHA-256 & MGF1-SHA-256)** untuk pembungkusan (*key wrapping*) kunci simetris secara asimetris. Dilengkapi dengan **Mode Visualizer (Hex & Byte Inspector)**, server perantara **Zero-Knowledge Relay**, skenario simulasi serangan aktif, serta suite benchmark empiris.

---

## 🚀 Fitur Utama

1. **Skema Enkripsi Hybrid End-to-End:**
   - Kunci simetris $K_{AES}$ (256-bit) dan Nonce (96-bit) acak unik per pesan (*one-time key*).
   - Enkripsi konten dengan **AES-256-GCM** yang menghasilkan Ciphertext dan Authentication Tag 128-bit.
   - Pengikatan metadata kanonikal *Associated Authenticated Data* (AAD: `sender:receiver:counter`).
   - Pembungkusan kunci simetris (*key wrapping*) dengan **RSA-2048-OAEP** menggunakan hash SHA-256 dan MGF1 SHA-256.
2. **Pertahanan Anti-Replay Berbasis Counter Monotonik:**
   - Filter urutan counter masuk yang persisten pada basis data SQLite lokal (`counter_state`).
   - Penolakan dini paket usang/duplikat sebelum memicu operasi RSA yang mahal secara komputasi (mitigasi DoS).
3. **Mode Visualisasi Interaktif (Hex & Byte Inspector):**
   - Transparansi audit per tahap matematis kriptografi (Plaintext, Kunci, Nonce, AAD, Ciphertext, Tag, Wrapped Key).
4. **Relay Server Zero-Knowledge:**
   - Server perantara jaringan lokal yang hanya meneruskan muatan terenkripsi JSON v1 tanpa memegang private key atau plaintext pengguna.
5. **Simulasi Serangan Cepat & Otomasi Pengujian:**
   - Uji tamper 1-byte, wrong private key, replay attack, dan demonstrasi kelemahan nonce reuse.
   - 100% lulus 66 unit test resmi termasuk verifikasi vektor uji NIST SP 800-38D.

---

## 📂 Struktur Direktori Proyek

```text
kripto/
├── README.md               # Dokumentasi utama proyek
├── requirements.txt        # Daftar pustaka dependensi Python
├── client/                 # Antarmuka desktop GUI (CustomTkinter) & controller
├── src/                    # Modul kriptografi inti, skema pesan, database, & jaringan
├── relay/                  # Zero-knowledge relay server & router
├── simulation/             # Otomasi skenario simulasi serangan keamanan
├── benchmark/              # Pengujian performa komparatif Hybrid vs RSA-only
├── tests/                  # Rangkaian pengujian unit pytest (66 test suite)
└── docs/                   # Dokumentasi teknis & akademik lengkap
```

---

## ⚡ Panduan Cepat Menjalankan Sistem

### 1. Persiapan Lingkungan

```powershell
# Buat dan aktifkan virtual environment (Windows PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Instal dependensi
pip install -r requirements.txt
```

### 2. Menjalankan Relay Server (Terminal 1)

```powershell
python -m relay.server --host 127.0.0.1 --port 8000
```

### 3. Menjalankan Klien Chat

- **Klien Alice (Terminal 2):**
  ```powershell
  python -m client.main --user alice --port 9001
  ```
- **Klien Bob (Terminal 3):**
  ```powershell
  python -m client.main --user bob --port 9002
  ```

---

## 🧪 Pengujian Unit & Simulasi

```powershell
# Menjalankan seluruh pengujian unit (73 test passed 100%)
pytest tests/ -v

# Menjalankan runner simulasi serangan kriptografi
python -m simulation.runner

# Menjalankan benchmark performa (Hybrid vs RSA-only)
python -m benchmark.benchmark_runner

# Mengompilasi menjadi berkas mandiri Windows (.EXE) portabel
python build_exe.py
```

---

## 📚 Indeks Dokumentasi Lengkap (`docs/`)

| Berkas | Judul & Deskripsi |
| :--- | :--- |
| [01-PRD.md](file:///c:/Users/dimaa/Documents/kripto/docs/01-PRD.md) | Spesifikasi Persyaratan Produk & Kebutuhan Fungsional (FR-01 s/d FR-17) |
| [02 - PENELITIAN.md](file:///c:/Users/dimaa/Documents/kripto/docs/02%20-%20PENELITIAN.md) | Latar Belakang Ilmiah, Landasan Teori, & Posisi Penelitian |
| [03 - GOALS.md](file:///c:/Users/dimaa/Documents/kripto/docs/03%20-%20GOALS.md) | Sasaran Kritis, Batasan Sistem, & Definisi Sukses |
| [04 - ARSITEKTUR.md](file:///c:/Users/dimaa/Documents/kripto/docs/04%20-%20ARSITEKTUR.md) | Arsitektur Sistem Modular, Lapisan Jaringan, & Relay Server |
| [05 - PERANCANGAN SISTEM.md](file:///c:/Users/dimaa/Documents/kripto/docs/05%20-%20PERANCANGAN%20SISTEM.md) | Skema Basis Data SQLite Lokal & Format Paket JSON v1 |
| [06 - WORKFLOW.md](file:///c:/Users/dimaa/Documents/kripto/docs/06%20-%20WORKFLOW.md) | Diagram Alur Eksekusi Kriptografi, Handshake, & Verifikasi Pesan |
| [07 - STRUKTUR PROYEK.md](file:///c:/Users/dimaa/Documents/kripto/docs/07%20-%20STRUKTUR%20PROYEK.md) | Rincian Struktur Direktori & Pembagian Tanggung Jawab Modul |
| [08 - TEKNOLOGI.md](file:///c:/Users/dimaa/Documents/kripto/docs/08%20-%20TEKNOLOGI.md) | Pemilihan Stack Teknologi, Pustaka Kriptografi, & Justifikasi Desain |
| [09 - KEAMANAN.md](file:///c:/Users/dimaa/Documents/kripto/docs/09%20-%20KEAMANAN.md) | Model Ancaman (*Threat Model*), Mitigasi Keamanan, & Batasan Sistem |
| [10 - ROADMAP.md](file:///c:/Users/dimaa/Documents/kripto/docs/10%20-%20ROADMAP.md) | Roadmap Pengembangan Fase 1 s/d Fase 5 |
| [11 - SETUP LOKAL.md](file:///c:/Users/dimaa/Documents/kripto/docs/11%20-%20SETUP%20LOKAL.md) | Panduan Langkah-demi-Langkah Pengaturan Lingkungan & Demo Interaktif |
| [12 - HASIL PENGUJIAN.md](file:///c:/Users/dimaa/Documents/kripto/docs/12%20-%20HASIL%20PENGUJIAN.md) | Laporan Hasil Validasi NIST, Simulasi Serangan, & Benchmark Empiris |
| [13 - RENCANA KOMUNIKASI MULTI-DEVICE LAN.md](file:///c:/Users/dimaa/Documents/kripto/docs/13%20-%20RENCANA%20KOMUNIKASI%20MULTI-DEVICE%20LAN.md) | Rencana & Panduan Komunikasi Antar-Perangkat Fisik pada Jaringan Wi-Fi/LAN |
| [14 - PANDUAN PACKAGING DAN DISTRIBUSI EXE.md](file:///c:/Users/dimaa/Documents/kripto/docs/14%20-%20PANDUAN%20PACKAGING%20DAN%20DISTRIBUSI%20EXE.md) | Panduan Pengemasan Aplikasi Menjadi Berkas Mandiri (.EXE) & Installer Windows |
| [15 - PENINGKATAN DIGITAL SIGNATURE RSA-PSS.md](file:///c:/Users/dimaa/Documents/kripto/docs/15%20-%20PENINGKATAN%20DIGITAL%20SIGNATURE%20RSA-PSS.md) | Spesifikasi Integrasi Tanda Tangan Digital RSA-PSS (Authenticity & Non-Repudiation) |
