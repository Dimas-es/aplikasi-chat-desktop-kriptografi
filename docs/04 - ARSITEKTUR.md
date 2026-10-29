# Arsitektur Sistem

## 1. Arsitektur logis

&#91;embedded content: arsitektur logis · 2 klien, relay opsional, modul simulasi serangan\]

Implementasi masih dalam rencana; bahasa pemrograman dan framework UI belum diputuskan, sehingga nama komponen bersifat logis. Pengujian dilakukan pada localhost atau LAN.

## 2. Tanggung jawab komponen

- **UI chat:** menerima input pesan, menampilkan pesan terdekripsi, status verifikasi, dan mode visualisasi proses.
- **Modul kripto:** mengorkestrasi proses kripto: membuat kunci AES per pesan, memanggil enkripsi dan dekripsi, membungkus dan membuka kunci, serta mencatat tiap tahap untuk visualisasi.
- **AES-256-GCM:** enkripsi dan dekripsi isi pesan dengan nonce 96-bit dan AAD berisi sender, receiver, dan counter.
- **RSA-OAEP SHA-256:** pembungkusan dan pembukaan kunci AES; hash SHA-256 dan MGF1 SHA-256 diset eksplisit.
- **Key store lokal:** private key terenkripsi passphrase (PBKDF2 atau Argon2) dan public key lawan bicara.
- **Penjaga counter:** menyimpan counter tertinggi per pasangan pengirim-penerima untuk menolak replay.
- **Modul jaringan:** mengirim dan menerima paket, langsung via socket atau melalui relay.
- **Relay server (opsional):** meneruskan dan menyimpan paket ciphertext; tidak pernah memegang private key, kunci AES, maupun plaintext.
- **Simulasi serangan:** menjalankan skenario modifikasi ciphertext, kunci salah, dan replay; hanya aktif pada lingkungan uji.
- **Benchmark:** mengukur waktu enkripsi dan dekripsi hybrid dibandingkan RSA saja.

## 3. Trust boundaries

1. **Pengguna → Klien:** plaintext hanya ada di dalam klien; perlu validasi input dan perlindungan tampilan.
2. **Klien → Jaringan/Relay:** tidak tepercaya; penyerang pasif dapat membaca, penyerang aktif dapat mengubah atau mengirim ulang paket. Relay hanya melihat ciphertext dan metadata (sender, receiver, counter, ukuran).
3. **Klien → Key store:** private key RSA adalah rahasia sensitif; tidak boleh tersimpan plaintext dan tidak boleh masuk log.
4. **Pertukaran public key:** tanpa PKI, public key dapat diganti oleh pihak di tengah (MITM) kecuali fingerprint diverifikasi lewat jalur terpisah.
5. **Modul simulasi serangan:** hanya berjalan pada lingkungan uji dan tidak boleh aktif pada mode normal.

## 4. Catatan desain kriptografi

Kunci AES dibuat baru untuk setiap pesan sehingga nonce tidak berisiko dipakai ulang pada kunci yang sama. Parameter OAEP diset eksplisit: hash SHA-256, MGF1 SHA-256, label kosong; ini penting karena sebagian library memakai MGF1 SHA-1 secara default sehingga dua sisi bisa tidak kompatibel. Authentication tag memastikan integritas ciphertext, dan AAD mengikat metadata ke ciphertext sehingga penukaran sender, receiver, atau counter terdeteksi. Skema belum memiliki tanda tangan digital, sehingga pengirim tidak diautentikasi, dan tidak memiliki forward secrecy karena seluruh kunci AES dibungkus dengan kunci RSA jangka panjang penerima. Pengirim juga tidak dapat membuka kembali pesan yang ia kirim kecuali kunci AES dibungkus juga untuk dirinya atau plaintext disimpan lokal.

## 5. Risiko dan keputusan terbuka

- **Penyimpanan counter:** jika counter hilang saat aplikasi restart, replay lama dapat lolos; counter perlu disimpan persisten.
- **Ketidakcocokan parameter OAEP** antar library perlu diuji dengan uji interoperabilitas.
- **Relay server tidak tepercaya:** relay dapat menghapus, menunda, atau mengatur ulang urutan paket; ketahanan terhadap hal ini dibahas sebagai keterbatasan.
- **Arsitektur komunikasi:** dua klien dengan relay atau langsung via socket belum diputuskan.
- **Bahasa pemrograman dan library kripto:** belum diputuskan dan menentukan detail penerapan.

Alur kirim dan terima, format paket, skenario serangan, dan penanganan kegagalan dirinci pada [06 - WORKFLOW.md](06%20-%20WORKFLOW.md).

