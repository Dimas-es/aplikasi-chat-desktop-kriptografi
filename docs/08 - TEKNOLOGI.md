# Teknologi yang Digunakan

Dokumen ini merinci tumpukan teknologi (*technology stack*), pustaka kriptografi, komponen antarmuka, serta modul pengujian yang digunakan dalam membangun prototipe aplikasi chat desktop enkripsi hybrid AES-256-GCM dan RSA-OAEP SHA-256.

| Teknologi | Peran | Alasan pemilihan / catatan |
|---|---|---|
| Python 3.10+ | Bahasa pemrograman utama | Bersih, modular, dan memiliki dukungan pustaka kriptografi standar industri yang mapan |
| `cryptography` (PyCA) | Pustaka kriptografi inti | Pustaka standar de-facto berbasis binding OpenSSL/Rust; menjamin implementasi primitif tahan terhadap *side-channel/timing attacks* |
| AES-256-GCM | Enkripsi simetris pesan | Menyediakan kerahasiaan dan integritas (AEAD) dengan autentikasi AAD dan tag 128-bit; efisien untuk pesan panjang |
| RSA-OAEP (2048-bit) | Pembungkusan kunci (*Key Wrapping*) | Melindungi kunci AES simetris; parameter diset eksplisit ke SHA-256 (hash utama & MGF1) sesuai RFC 8017 |
| PBKDF2 / Argon2id | *Key Derivation Function* (KDF) | Menurunkan kunci enkripsi dari passphrase pengguna dengan salt acak 128-bit untuk melindungi private key di disk |
| SHA-256 (Fingerprint) | Hash integritas kunci publik | Menghasilkan nilai fingerprint heksadesimal dari public key untuk verifikasi manual out-of-band (mitigasi MITM) |
| PyQt6 / CustomTkinter | Framework UI Desktop | Menyediakan widget antarmuka chat 1-ke-1 dan panel visualisasi proses kriptografi (Hex & Byte Inspector) |
| Python Socket (`asyncio` / TCP) | Transportasi jaringan | Komunikasi socket P2P langsung antar-klien atau penghubung ke relay server pada jaringan lokal (LAN) |
| JSON + Base64 | Serialisasi paket data | Format paket v1 yang terstruktur dan mudah diinspeksi; data biner (ciphertext, tag, nonce, wrapped key) dienkode Base64 |
| SQLite3 | Basis data lokal klien | Menyimpan profil identitas, buku kontak, status verifikasi fingerprint, dan counter anti-replay secara persisten |
| `pytest` | Kerangka pengujian otomatis | Menjalankan unit testing modul kripto, uji negatif serangan, dan validasi Known Answer Test (KAT) NIST SP 800-38D |
| `matplotlib` | Visualisasi benchmark | Menghasilkan grafik komparasi performa latensi dan throughput antara skema Hybrid vs RSA-Only |
| Git / GitHub | *Version control* | Pelacakan perubahan kode, kolaborasi, dan rekam jejak dokumentasi penelitian |

---

## Integrasi teknologi

- **AES-256-GCM** mengenkripsi isi pesan (teks, emoji, data panjang) secara simetris dan menghasilkan *authentication tag* 128-bit yang mengikat metadata pengiriman (*Additional Authenticated Data* / AAD: pengirim, penerima, dan counter).
- **RSA-OAEP SHA-256** membungkus (*wrapping*) kunci simetris AES 256-bit yang dibangkitkan baru untuk setiap pesan, sehingga hanya dapat dibuka oleh pemegang *private key* RSA penerima yang sah.
- **PBKDF2/Argon2id** mengamankan *private key* RSA di media penyimpanan lokal dengan mengenkripsinya menggunakan kunci turunan dari passphrase pengguna, mencegah kebocoran kunci jika berkas identitas tersalin.
- **UI Desktop (PyQt/CustomTkinter)** menyajikan dialog percakapan dan panel visualisasi yang membaca variabel perantara (*intermediate cryptographic states*) langsung dari memori untuk edukasi dan audit proses matematis.
- **Relay Server & Socket TCP** menangani transportasi paket JSON v1 tanpa pernah memiliki akses ke plaintext maupun kunci sesi (*zero-knowledge relay*).
- **Pytest & Matplotlib** memverifikasi kebenaran algoritma terhadap vektor uji resmi NIST dan memvisualisasikan data benchmark komparatif secara terukur.

---

## Hal yang belum boleh diklaim

- **Bukan sistem pesan siap produksi:** Prototipe ini dirancang untuk simulasi, visualisasi edukatif, dan evaluasi akademis pada lingkungan lokal/LAN.
- **Belum memiliki Forward Secrecy:** Kunci AES dibungkus menggunakan kunci RSA jangka panjang; jika *private key* RSA penerima bocor di masa depan, seluruh rekaman paket ciphertext lama dapat didekripsi.
- **Belum memiliki Autentikasi Pengirim (Digital Signature):** Skema RSA-OAEP murni hanya menjamin kerahasiaan (*confidentiality*); siapapun yang memegang public key Bob dapat mengirim pesan atas nama Alice kecuali ditambahkan tanda tangan digital (RSA-PSS).
- **Distribusi Kunci Rentan MITM tanpa PKI:** Tidak digunakannya infrastruktur sertifikat digital (X.509/CA) berarti keaslian public key bergantung sepenuhnya pada kecermatan pengguna saat mencocokkan *fingerprint* secara manual out-of-band.
- **Keamanan Penyimpanan Lokal Terbatas:** Prototipe tidak menggunakan *hardware security module* (HSM) atau *secure enclave*; perlindungan private key bergantung pada kekuatan passphrase dan fungsi KDF di tingkat perangkat lunak.

---

## Teknologi yang masih diputuskan

- **Framework UI Desktop:** Finalisasi antara PyQt6 (keunggulan ekosistem widget yang matang dan kaya fitur inspeksi) atau CustomTkinter (keunggulan kesederhanaan dependensi dan tampilan modern).
- **Skema Penyimpanan Lokal:** Pemilihan antara satu berkas SQLite3 per profil klien atau penyimpanan berkas JSON terisolasi dengan enkripsi at-rest.
- **Peluang Penguatan Protokol (Future Work):**
  - Penerapan tanda tangan digital RSA-PSS untuk autentikasi identitas pengirim (FR-16).
  - Transisi ke skema KEM modern seperti ECDH X25519 untuk mendukung *Ephemeral Key Exchange*.
  - Eksplorasi protokol *Double Ratchet* untuk menghadirkan *Perfect Forward Secrecy* (PFS) dan *Post-Compromise Security* (PCS).
