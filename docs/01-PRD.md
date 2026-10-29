# Product Requirements Document (PRD)

**Produk:** Simulasi Metode Enkripsi Hybrid Menggunakan AES-GCM dan RSA-OAEP SHA-256 dalam Aplikasi Chat Berbasis Desktop\
**Tahap:** tugas akhir semester mata kuliah Kriptografi / prototipe simulasi\
**Status:** kebutuhan target; belum ada implementasi

## 1. Visi Produk

Aplikasi chat desktop minimal yang memperagakan secara transparan bagaimana enkripsi hybrid bekerja: AES-256-GCM melindungi isi pesan, RSA-OAEP dengan SHA-256 melindungi kunci AES. Aplikasi dilengkapi mode visualisasi proses, simulasi serangan, dan benchmark, sehingga ketahanan dan batas skema dapat ditunjukkan dengan bukti, bukan hanya klaim. Batas keamanan prototipe dinyatakan secara jujur.

## 2. Masalah Pengguna

Mahasiswa dan penilai ingin memahami dan memverifikasi bahwa skema hybrid benar-benar menjaga kerahasiaan dan integritas pesan. Pengguna chat ingin pesannya tidak terbaca oleh penyadap atau server perantara. Penguji ingin melihat apa yang terjadi saat ciphertext diubah, kunci salah dipakai, atau paket lama dikirim ulang. Selama ini penelitian serupa lebih banyak berbentuk web atau mobile dan jarang menampilkan simulasi serangan pada aplikasi desktop.

## 3. Aktor dan Kebutuhan

| Aktor | Kebutuhan |
| --- | --- |
| Pengguna (Alice dan Bob) | Membuat kunci, bertukar public key, mengirim dan menerima pesan terenkripsi, melihat status verifikasi pesan |
| Penguji / penyerang simulasi | Menjalankan skenario serangan (ubah ciphertext, kunci salah, replay) dan melihat hasilnya |
| Penilai (dosen) | Melihat tiap tahap proses kripto, hasil pengujian, dan hasil benchmark |
| Relay server (opsional) | Meneruskan paket ciphertext tanpa pernah memegang kunci atau plaintext |

## 4. Kebutuhan Fungsional

| ID | Kebutuhan | Prioritas | Status saat ini |
| --- | --- | --- | --- |
| FR-01 | Generate pasangan kunci RSA-2048 untuk tiap pengguna | P0 | **Terverifikasi (Lolos)** |
| FR-02 | Simpan private key terenkripsi passphrase (PBKDF2 atau Argon2), bukan plaintext | P1 | **Terverifikasi (Lolos)** |
| FR-03 | Pertukaran public key antar klien (manual atau via relay) | P0 | **Terverifikasi (Lolos)** |
| FR-04 | Enkripsi pesan: kunci AES-256 acak per pesan, AES-GCM dengan nonce 96-bit unik, AAD berisi pengirim, penerima, dan counter | P0 | **Terverifikasi (Lolos)** |
| FR-05 | Bungkus kunci AES dengan RSA-OAEP, hash SHA-256 dan MGF1 SHA-256 diset eksplisit | P0 | **Terverifikasi (Lolos)** |
| FR-06 | Dekripsi pesan: unwrap kunci, verifikasi authentication tag, lalu dekripsi | P0 | **Terverifikasi (Lolos)** |
| FR-07 | Format paket pesan (JSON: wrapped\_key, nonce, ciphertext+tag, sender, receiver, counter) | P0 | **Terverifikasi (Lolos)** |
| FR-08 | Antarmuka chat desktop untuk dua klien, kirim dan terima teks 1-ke-1 | P0 | **Terverifikasi (Lolos)** |
| FR-09 | Mode visualisasi proses: tampilkan kunci, nonce, ciphertext, tag, dan wrapped key dalam hex di tiap tahap | P0 | **Terverifikasi (Lolos)** |
| FR-10 | Simulasi serangan 1: ubah 1 byte ciphertext/tag/nonce, verifikasi GCM harus gagal | P0 | **Terverifikasi (Lolos)** |
| FR-11 | Simulasi serangan 2: dekripsi dengan private key yang salah, unwrap harus gagal | P0 | **Terverifikasi (Lolos)** |
| FR-12 | Simulasi serangan 3: replay paket lama, ditolak berdasarkan counter | P0 | **Terverifikasi (Lolos)** |
| FR-13 | Benchmark hybrid vs RSA-only pada beberapa ukuran pesan, rata-rata dari 10-30 percobaan | P0 | **Terverifikasi (Lolos)** |
| FR-14 | Validasi implementasi AES-GCM dengan test vector resmi NIST | P1 | **Terverifikasi (Lolos)** |
| FR-15 | Demo nonce reuse pada GCM dan dampaknya | P2 (bonus) | **Terverifikasi (Lolos)** |
| FR-16 | Tanda tangan digital RSA-PSS untuk autentikasi pengirim | P2 (bonus) | Terencana (Ekstensi) |
| FR-17 | Verifikasi fingerprint public key untuk mendeteksi MITM | P2 (bonus) | **Terverifikasi (Lolos)** |

## 5. User Stories

- **US-01:** Sebagai pengguna, saya ingin membuat pasangan kunci agar dapat menerima pesan terenkripsi.
- **US-02:** Sebagai pengguna, saya ingin bertukar public key dengan lawan bicara agar dapat saling mengirim pesan.
- **US-03:** Sebagai pengguna, saya ingin pesan saya terenkripsi sebelum meninggalkan aplikasi agar tidak terbaca penyadap atau server.
- **US-04:** Sebagai pengguna, saya ingin pesan yang dimodifikasi di tengah jalan ditolak dan ditandai agar saya tahu pesan itu tidak tepercaya.
- **US-05:** Sebagai penguji, saya ingin menjalankan skenario serangan dengan satu aksi agar hasilnya mudah didokumentasikan.
- **US-06:** Sebagai penilai, saya ingin melihat tiap tahap proses kripto dan hasil benchmark agar dapat menilai pemahaman dan ketepatan implementasi.

## 6. Acceptance Criteria

1. Pasangan kunci dapat dibuat dan public key dapat dipertukarkan antar dua klien.
2. Pesan teks (termasuk emoji dan pesan panjang) terenkripsi, terkirim, dan terdekripsi identik dengan plaintext asal.
3. Capture traffic jaringan hanya menampilkan ciphertext, tanpa plaintext dan tanpa kunci AES.
4. Perubahan 1 byte pada ciphertext, tag, atau nonce menyebabkan verifikasi GCM gagal dan pesan tidak ditampilkan.
5. Dekripsi dengan private key yang salah gagal pada tahap unwrap.
6. Paket yang sama yang dikirim ulang (replay) ditolak.
7. Implementasi lolos test vector AES-GCM resmi dan parameter OAEP (SHA-256 untuk hash dan MGF1) konsisten.
8. Mode visualisasi menampilkan seluruh tahap proses kirim dan terima.
9. Hasil benchmark hybrid vs RSA-only disajikan dalam tabel dan grafik, termasuk ukuran pesan yang membuat RSA-only gagal.
10. Dokumentasi menyatakan secara jelas batas keamanan prototipe.

## 7. Kebutuhan Nonfungsional

- **Keamanan:** hanya memakai library kriptografi mapan (tidak membuat primitif sendiri), RSA minimal 2048 bit, nonce tidak pernah dipakai ulang dengan kunci yang sama, private key tidak disimpan plaintext, tidak ada rahasia di log.
- **Keandalan:** pesan rusak atau tidak valid ditangani tanpa membuat aplikasi crash.
- **Kinerja:** benchmark waktu enkripsi dan dekripsi serta overhead ukuran ciphertext diukur sebelum menyimpulkan; tidak ada target SLO tetap.
- **Maintainability:** modul kripto dipisah dari UI dan jaringan, disertai unit test untuk modul kripto.
- **Observability:** log proses terstruktur (tanpa rahasia) yang dapat ditampilkan pada mode visualisasi.

## 8. Tidak Termasuk Cakupan

Chat grup, pengiriman file, riwayat chat permanen, forward secrecy, infrastruktur PKI atau sertifikat, multi-device, enkripsi metadata, dan deployment produksi. Hal-hal ini disebut sebagai keterbatasan dan saran pengembangan lanjutan (misalnya ECDH X25519 ephemeral dan Double Ratchet).

## 9. Risiko dan Dependensi

- **Parameter OAEP tidak konsisten:** sebagian library memakai MGF1 SHA-1 secara default, sehingga enkripsi dan dekripsi bisa gagal atau tidak sesuai judul. Mitigasi: set eksplisit dan uji interoperabilitas.
- **Nonce reuse:** menghancurkan keamanan GCM. Mitigasi: kunci AES baru per pesan dan nonce acak 96-bit.
- **Tanpa autentikasi pengirim:** OAEP hanya menjamin kerahasiaan. Mitigasi: dicatat sebagai keterbatasan, atau tambah RSA-PSS (FR-16).
- **Distribusi public key rawan MITM:** tanpa PKI. Mitigasi: fingerprint (FR-17) atau dicatat sebagai keterbatasan.
- **Penyimpanan private key:** risiko bocor jika plaintext. Mitigasi: FR-02.
- **Dependensi:** bahasa pemrograman dan library kripto belum diputuskan (Python `cryptography`, Java JCA, atau C#/.NET).

## 10. Keputusan Terbuka

- Bahasa pemrograman dan framework UI desktop.
- Arsitektur komunikasi: dua klien dengan relay server, atau langsung via socket.
- Dikerjakan individu atau kelompok, yang menentukan apakah bonus FR-15 sampai FR-17 diambil.
