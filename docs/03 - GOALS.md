# Goals dan Indikator Keberhasilan

## Visi

Membangun simulasi aplikasi chat desktop yang **kriptografinya benar dan dapat diamati**, **ketahanannya terhadap serangan yang dimodelkan dapat diuji**, dan **kinerjanya terukur**, tanpa menyamakan kemampuan prototipe dengan keamanan siap produksi.

| ID | Goal | Indikator keberhasilan | Terkait PRD | Tahap |
| --- | --- | --- | --- | --- |
| G-01 | Alur hybrid berfungsi | Pesan teks (pendek, emoji, panjang) terenkripsi, terkirim, dan terdekripsi identik dengan plaintext asal antar dua klien | FR-01, FR-03 s.d. FR-08 | Direncanakan |
| G-02 | Kerahasiaan terjaga | Capture traffic hanya menampilkan ciphertext; tidak ada plaintext maupun kunci AES yang terlihat | FR-04, FR-05 | Direncanakan |
| G-03 | Integritas dan kunci salah ditolak | Perubahan 1 byte pada ciphertext, tag, atau nonce selalu gagal verifikasi; private key salah selalu gagal unwrap | FR-10, FR-11 | Direncanakan |
| G-04 | Anti-replay | Paket yang dikirim ulang ditolak berdasarkan counter | FR-12 | Direncanakan |
| G-05 | Implementasi kriptografi benar | Lolos test vector AES-GCM resmi; parameter OAEP (SHA-256 dan MGF1 SHA-256) konsisten dan lolos uji interoperabilitas | FR-05, FR-14 | Direncanakan |
| G-06 | Proses kriptografi transparan | Mode visualisasi menampilkan seluruh tahap kirim dan terima (kunci, nonce, ciphertext, tag, wrapped key) | FR-09 | Direncanakan |
| G-07 | Kinerja terukur | Benchmark hybrid vs RSA-only pada beberapa ukuran pesan, 10-30 pengulangan, rata-rata dan simpangan baku, dalam tabel dan grafik; dapat direproduksi | FR-13 | Direncanakan |
| G-08 | Keterbatasan terdokumentasi | Laporan menyatakan batas skema (tanpa forward secrecy, tanpa autentikasi pengirim, tanpa PKI) dan arah pengembangan lanjutan | Bagian 8 dan 9 PRD | Direncanakan |
| G-09 | Penguatan opsional | Salah satu dari demo nonce reuse, RSA-PSS, atau verifikasi fingerprint berjalan dan teruji | FR-15 s.d. FR-17 | Opsional |

## Prioritas pengerjaan

**P0:** kebenaran kriptografi (G-01, G-05), kerahasiaan dan integritas (G-02, G-03), anti-replay (G-04), benchmark (G-07), mode visualisasi (G-06).\
**P1:** penyimpanan private key terenkripsi passphrase (FR-02), validasi test vector (FR-14), dokumentasi keterbatasan (G-08).\
**P2:** penguatan opsional (G-09), seperti demo nonce reuse, tanda tangan RSA-PSS, dan fingerprint public key.

## Definisi selesai

Sebuah goal dianggap selesai hanya jika implementasi, pengujian positif dan negatif, dokumentasi, dan bukti hasilnya (screenshot, log, atau tabel) tersedia. Satu demo pengiriman pesan yang berhasil bukan bukti skema aman atau siap produksi.
