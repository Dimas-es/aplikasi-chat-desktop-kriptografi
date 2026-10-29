# Dasar Penelitian

## Judul

**Simulasi Metode Enkripsi Hybrid Menggunakan AES-GCM dan RSA-OAEP SHA-256 dalam Aplikasi Chat Berbasis Desktop**

Judul ini adalah **arah penelitian**. Kata “simulasi” berarti aplikasi memperagakan alur kriptografi secara transparan dan menguji ketahanannya terhadap skenario serangan yang dimodelkan; frasa tersebut **belum merupakan klaim bahwa sistem aman untuk penggunaan produksi**.

## 1. Latar Belakang

Aplikasi chat digunakan secara luas untuk bertukar informasi, termasuk informasi yang bersifat pribadi. Pesan yang dikirim melalui jaringan dapat disadap, diubah, atau dikirim ulang oleh pihak yang tidak berwenang, dan server perantara tidak selalu dapat dipercaya. Enkripsi diperlukan agar isi pesan hanya dapat dibaca oleh pengirim dan penerima.

Enkripsi simetris seperti AES cepat dan efisien untuk data berukuran besar, tetapi menimbulkan masalah distribusi kunci. Enkripsi asimetris seperti RSA mengatasi distribusi kunci, tetapi lambat dan hanya dapat mengenkripsi data yang ukurannya terbatas. Pendekatan hybrid menggabungkan keduanya: AES-GCM mengenkripsi isi pesan sekaligus menjamin integritasnya melalui authentication tag, sedangkan RSA-OAEP dengan SHA-256 melindungi kunci AES yang dikirim bersama pesan.

Penelitian terdahulu pada aplikasi chat banyak memakai kombinasi AES dan RSA pada platform web atau mobile. Contohnya aplikasi chat mobile HiChat dengan hybrid cryptosystem AES dan RSA, aplikasi chat Android dengan RSA dan AES, serta penelitian chat web yang memakai AES dan RSA-OAEP untuk mensimulasikan mekanisme KEM. Untuk platform desktop, ditemukan aplikasi chat dan voice-call berbasis RSA pada jaringan lokal. Penelitian yang secara khusus memakai AES-GCM dan RSA-OAEP SHA-256 pada aplikasi desktop, disertai simulasi serangan dan pengukuran kinerja, jarang ditemukan.

Implementasi hybrid juga memiliki tantangan praktis: konsistensi parameter OAEP (hash utama dan MGF1), pengelolaan nonce agar tidak dipakai ulang pada GCM, pengikatan metadata pesan melalui associated data, pencegahan replay, serta penyimpanan private key. Proyek ini mengembangkan aplikasi chat desktop minimal sebagai wadah simulasi, lalu mengevaluasi tantangan tersebut secara terukur.

## 2. Rumusan Masalah

1. Bagaimana merancang arsitektur aplikasi chat desktop yang menerapkan enkripsi hybrid AES-GCM dan RSA-OAEP SHA-256?
2. Bagaimana mengimplementasikan alur pembuatan kunci, enkripsi, pembungkusan kunci, pengiriman, dan dekripsi pesan secara benar dan konsisten?
3. Bagaimana menampilkan proses kriptografi tiap tahap sehingga dapat diamati dan dipahami?
4. Bagaimana skema menjaga kerahasiaan dan integritas pesan terhadap penyadapan, modifikasi ciphertext, penggunaan kunci yang salah, dan serangan replay?
5. Bagaimana perbandingan kinerja enkripsi hybrid dengan RSA saja pada berbagai ukuran pesan?
6. Apa saja keterbatasan keamanan skema ini, dan bagaimana arah pengembangan lanjutannya?

## 3. Tujuan Penelitian

- Merancang dan mengimplementasikan prototipe aplikasi chat desktop dengan enkripsi hybrid AES-GCM dan RSA-OAEP SHA-256.
- Menerapkan parameter kriptografi secara eksplisit dan konsisten (AES-256, nonce 96-bit, OAEP dengan SHA-256 dan MGF1 SHA-256).
- Membangun mode visualisasi yang menampilkan tiap tahap proses kriptografi.
- Menguji ketahanan skema terhadap modifikasi ciphertext, kunci salah, dan replay.
- Mengukur dan membandingkan waktu proses enkripsi dan dekripsi pada hybrid dan RSA saja.
- Menganalisis keterbatasan skema, yaitu tanpa forward secrecy, tanpa autentikasi pengirim, dan distribusi public key tanpa PKI.

## 4. Batasan Masalah

1. Komunikasi teks satu-ke-satu antara dua pengguna; chat grup dan pengiriman file tidak termasuk.
2. Parameter utama: RSA 2048 bit, AES 256 bit, nonce 96 bit, authentication tag 128 bit.
3. Implementasi dan pengujian dilakukan pada localhost atau jaringan lokal (LAN), bukan jaringan publik.
4. Distribusi public key dilakukan sederhana tanpa PKI atau sertifikat; karena itu skema rentan terhadap penggantian public key (MITM) kecuali fingerprint diverifikasi secara terpisah.
5. Skema ini menjamin kerahasiaan dan integritas pesan, tetapi **belum mengautentikasi pengirim** dan **tidak memiliki forward secrecy**: kebocoran private key RSA membuka seluruh pesan lama yang tersimpan atau tertangkap.
6. Library kriptografi yang sudah mapan digunakan; penelitian tidak membuat primitif kriptografi sendiri dan bukan audit formal terhadap library tersebut.
7. Manajemen kunci pada level prototipe; belum ada key custody produksi atau perlindungan terhadap malware pada perangkat pengguna.
8. Pengujian serangan dilakukan dalam lingkungan simulasi yang dikendalikan sendiri.

## 5. Manfaat dan Kontribusi yang Diharapkan

- Referensi praktis cara kerja enkripsi hybrid beserta batasannya pada aplikasi desktop.
- Prototipe dengan mode visualisasi yang dapat dipakai sebagai media pembelajaran kriptografi.
- Hasil pengujian serangan yang terdokumentasi (modifikasi ciphertext, kunci salah, replay).
- Data empiris perbandingan kinerja hybrid dan RSA saja pada berbagai ukuran pesan.
- Analisis kesenjangan keamanan antara prototipe ini dan protokol pesan modern (ECDH ephemeral, tanda tangan digital, Double Ratchet).

## 6. Metode Evaluasi

Uji correctness (plaintext hasil dekripsi identik dengan plaintext asal untuk teks pendek, emoji, dan pesan panjang; validasi AES-GCM dengan test vector resmi), uji negatif (modifikasi 1 byte pada ciphertext, tag, atau nonce; private key salah; replay paket lama), uji kerahasiaan (capture traffic jaringan untuk memastikan tidak ada plaintext maupun kunci AES yang terlihat), uji interoperabilitas parameter OAEP, serta benchmark waktu enkripsi dan dekripsi pada beberapa ukuran pesan dengan 10-30 kali pengulangan per kondisi (dilaporkan sebagai rata-rata dan simpangan baku) serta pengukuran overhead ukuran ciphertext. Setiap klaim keamanan harus dinilai terhadap pihak yang dapat mengamati data: penyadap jaringan, relay server, pemegang kunci, dan penyerang aktif yang dapat mengubah atau mengirim ulang paket.

## 7. Penelitian Terkait dan Referensi Awal

**Penelitian implementasi:**

- Anshary (2022), aplikasi chatting dan voice-call dengan RSA pada LAN berbasis desktop (Java, SQLite3), STMIK Widya Cipta Dharma.
- Penerapan AES dan Kyber pada chatting website, Universitas Jenderal Soedirman, dengan RSA-OAEP sebagai simulasi KEM.
- HiChat: secure mobile chat menggunakan hybrid cryptosystem AES dan RSA, Jurnal Ilmiah Teknologi dan Rekayasa, Universitas Gunadarma.
- Pratiwi dkk., implementasi kriptografi RSA pada aplikasi chat berbasis Android, Politeknik Negeri Ujung Pandang.
- Skripsi Universitas Budi Luhur tentang hybrid encryption AES-256-GCM dan ECC X25519 pada web chat dan berbagi file.

**Landasan teori dan standar (perlu diverifikasi detail terbitannya sebelum disitasi):**

- NIST SP 800-38D, spesifikasi Galois/Counter Mode.
- RFC 8017, PKCS #1 v2.2, mendefinisikan RSAES-OAEP.
- Bellare dan Rogaway, “Optimal Asymmetric Encryption”, Eurocrypt 1994.

**Acuan pengembangan lanjutan (forward secrecy dan autentikasi):**

- Cohn-Gordon dkk., “A Formal Security Analysis of the Signal Messaging Protocol”, IEEE EuroS&P 2017.
- “A More Complete Analysis of the Signal Double Ratchet Algorithm”, CRYPTO 2022.
