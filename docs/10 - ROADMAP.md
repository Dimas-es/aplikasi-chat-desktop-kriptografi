# Roadmap Pengembangan

Dokumen ini memetakan tahapan pengembangan, sasaran pencapaian (*milestones*), indikator penyelesaian (*exit criteria*), serta status progres pembangunan prototipe aplikasi chat desktop enkripsi hybrid AES-256-GCM dan RSA-OAEP SHA-256.

---

## Phase 1 — Fondasi Kriptografi Inti dan Pengujian Unit

**Status:** Selesai 100% (Terverifikasi 31/31 pengujian otomatis).

- [x] Pembangkitan pasangan kunci RSA-2048 bit (`src/crypto/rsa_oaep.py`).
- [x] Implementasi pembungkusan (*wrapping*) dan pembukaan (*unwrapping*) kunci AES dengan RSA-OAEP parameter eksplisit (SHA-256 untuk hash utama dan MGF1 SHA-256).
- [x] Implementasi enkripsi dan dekripsi simetris AES-256-GCM (`src/crypto/aes_gcm.py`) dengan pembangkitan nonce 96-bit acak per pesan dan autentikasi tag 128-bit.
- [x] Pengikatan data terautentikasi tambahan (*Additional Authenticated Data* / AAD) kanonikal (`sender:receiver:counter`).
- [x] Implementasi fungsi derivasi kunci passphrase PBKDF2/Argon2id + salt acak 128-bit (`src/crypto/kdf.py`) untuk melindungi private key saat istirahat.
- [x] Perhitungan dan pemformatan nilai fingerprint public key dengan SHA-256 (`src/crypto/fingerprint.py`).
- [x] Validasi kebenaran matematis terhadap *Known Answer Test* (KAT) resmi NIST SP 800-38D.
- [x] Pengujian unit mandiri dan pengujian interoperabilitas parameter OAEP (`tests/test_crypto_*.py`).

**Exit criteria:** Seluruh unit test kriptografi lolos 100%, implementasi AES-GCM terbukti mematuhi test vector resmi NIST, dan parameter RSA-OAEP SHA-256 terbukti konsisten tanpa ambigu. (TERPENUHI)

---

## Phase 2 — Messaging, Persistensi Lokal, dan Mekanisme Anti-Replay

**Status:** Selesai 100% (Terverifikasi 51/51 pengujian otomatis).

- [x] Implementasi parser dan serializer paket data JSON v1 (`src/messaging/packet.py`) dengan payload biner terenkode Base64.
- [x] Penyusunan format kanonikal string AAD (`src/messaging/aad.py`).
- [x] Manajemen status siklus hidup pesan: `terkirim`, `valid`, `ditolak_replay`, `gagal_unwrap`, dan `gagal_verifikasi`.
- [x] Implementasi penyimpanan lokal identitas dan private key terenkripsi (`src/storage/keystore.py`).
- [x] Implementasi buku kontak, penyimpanan public key lawan bicara, dan status verifikasi fingerprint (`src/storage/contact_store.py`).
- [x] Implementasi penyimpanan atomik counter anti-replay (`src/storage/counter_store.py`).
- [x] Penerapan aturan konsistensi: `highest_received_counter` hanya di-commit ke disk setelah verifikasi tag AES-GCM sukses.

**Exit criteria:** Pesan dapat dikemas dan didekripsi antar-komponen penyimpanan; paket lama yang diinjeksi ulang berhasil dideteksi dan ditolak sebelum memicu operasi RSA. (TERPENUHI)

---

## Phase 3 — Antarmuka Desktop (UI) dan Mode Visualisasi

**Status:** Selesai 100% (Terverifikasi 55/55 pengujian otomatis).

- [x] Inisialisasi aplikasi desktop klien (PyQt6 / CustomTkinter di `client/`).
- [x] Desain antarmuka percakapan chat 1-ke-1 (daftar kontak, gelembung percakapan, input pesan, dan status badge).
- [x] Dialog pembuatan identitas, input passphrase pembuka kunci, dan pencocokan fingerprint visual out-of-band.
- [x] Pembangunan panel **Visualizer (Hex & Byte Inspector)**:
  - Inspeksi pengirim: Plaintext $\to$ Kunci AES (Hex) $\to$ Nonce (Hex) $\to$ AAD kanonikal $\to$ Ciphertext + Tag $\to$ Wrapped Key $\to$ Paket JSON.
  - Inspeksi penerima: Paket Masuk $\to$ Counter Check $\to$ Unwrap RSA $\to$ AAD Match $\to$ Tag Verification $\to$ Plaintext Output.
- [x] Penghubung controller aplikasi (`client/controllers/`) dengan modul core kriptografi dan storage.

**Exit criteria:** Pengguna (Alice dan Bob) dapat mengirim dan menerima teks percakapan melalui antarmuka desktop; panel visualizer menampilkan nilai heksadesimal dari seluruh tahapan kripto secara real-time. (TERPENUHI)

---

## Phase 4 — Lapisan Jaringan (Socket P2P & Relay Server)

**Status:** Selesai 100% (Terverifikasi 59/59 pengujian otomatis).

- [x] Implementasi transportasi soket TCP langsung (`src/network/socket_client.py`) untuk skenario koneksi peer-to-peer pada jaringan lokal (LAN/localhost).
- [x] Pembangunan relay server perantara zero-knowledge (`relay/`):
  - Handler direktori public key sederhana (`PUBLISH_KEY` dan `GET_KEY`).
  - Handler antrean paket ciphertext (`SEND` dan `FETCH`) untuk pesan tertunda (`relay_queue`).
- [x] Pengujian transmisi paket data melalui Wireshark / integration test untuk memastikan tidak ada plaintext maupun kunci AES yang bocor di jaringan.
- [x] Penanganan kondisi jaringan terputus (antrean lokal dan mekanisme retry).

**Exit criteria:** Dua klien dapat berkomunikasi lancar baik secara direct socket maupun via relay; capture traffic jaringan membuktikan 100% muatan pesan dan kunci terenkripsi. (TERPENUHI)

---

## Phase 5 — Simulasi Serangan, Benchmark Kinerja, dan Evaluasi

**Status:** Selesai 100% (Terverifikasi 66/66 pengujian otomatis).

- [x] Implementasi modul otomasi skenario serangan (`simulation/scenarios/`):
  - Skenario 1: Modifikasi 1 byte ciphertext, tag, atau nonce $\to$ pembuktian deteksi kegagalan integritas oleh AES-GCM (`gagal_verifikasi`).
  - Skenario 2: Percobaan unwrap dengan private key salah $\to$ pembuktian kegagalan padding OAEP (`gagal_unwrap`).
  - Skenario 3: Injeksi ulang paket dengan counter kadaluarsa $\to$ pembuktian filter anti-replay (`ditolak_replay`).
  - Skenario 4 (Bonus): Demonstrasi kebocoran informasi akibat *nonce reuse* pada AES-GCM (keystream cancellation $C_1 \oplus C_2 = P_1 \oplus P_2$ dan crib-dragging).
- [x] Pembangunan suite benchmark kinerja empiris (`benchmark/`):
  - Pengukuran latensi enkripsi dan dekripsi skema Hybrid vs RSA-Only pada variasi ukuran pesan (64B, 1KB, 10KB, 100KB, 1MB) dengan repetisi terkonfigurasi.
  - Pembuktian matematis kegagalan RSA-Only pada payload $> 190$ byte (RSA-2048 OAEP SHA-256 limit: 190 byte).
  - Pembangkitan tabel statistik (mean, standard deviation, throughput MB/s), laporan Markdown (`benchmark/BENCHMARK_REPORT.md`), data JSON (`benchmark/benchmark_results.json`), dan grafik perbandingan resolusi tinggi Matplotlib (`benchmark/benchmark_comparison.png`).
- [x] Penyusunan laporan evaluasi, analisis keterbatasan akademik, dan dokumentasi panduan setup lokal.

**Exit criteria:** Seluruh skenario serangan terbukti ditolak secara akurat tanpa membuat aplikasi crash; data benchmark terukur dan dapat direproduksi (*reproducible*); dokumentasi pengujian lengkap untuk evaluasi dosen/penilai. (TERPENUHI)

---

## Status Keseluruhan Proyek

Seluruh fase pengembangan (Phase 1 hingga Phase 5)—mencakup fondasi kriptografi murni, skema pertukaran pesan & anti-replay, aplikasi desktop GUI CustomTkinter dengan mode visualizer hex/byte inspector, lapisan jaringan socket P2P dan relay server, simulasi skenario serangan, serta benchmark evaluasi kinerja komparatif—telah berhasil dibangun, diuji, dan diverifikasi 100% (66/66 unit test lolos).

