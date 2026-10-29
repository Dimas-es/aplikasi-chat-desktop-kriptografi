# Keamanan, Threat Model, dan Keterbatasan

Dokumen ini mendefinisikan model ancaman (*threat model*), batas kepercayaan (*trust boundaries*), sifat keamanan yang dijamin, kesenjangan kritis, serta batasan operasional prototipe aplikasi chat desktop dengan enkripsi hybrid AES-256-GCM dan RSA-OAEP SHA-256.

---

## 1. Pihak dan Kemampuan (Threat Actors & Vantage Points)

- **Penyadap Jaringan Pasif (*Passive Eavesdropper / Sniffer*):**
  - Mengamati lalu lintas data pada socket lokal atau segmen jaringan LAN/Wi-Fi (misalnya menggunakan Wireshark).
  - Dapat melihat metadata paket JSON v1 (`sender`, `receiver`, `counter`, dan perkiraan panjang pesan).
  - Tidak memiliki kunci privat penerima maupun kunci simetris AES; hanya melihat string acak terenkode Base64 (`wrapped_key`, `nonce`, `ciphertext+tag`).
- **Penyerang Jaringan Aktif (*Active Attacker / Man-in-the-Middle*):**
  - Mampu mencegat, memodifikasi bit data, membuang paket, menukar urutan paket, atau menginjeksi paket lama (*replay attack*).
  - Dapat berupaya mengganti kunci publik saat proses pertukaran kunci awal jika tidak diverifikasi secara out-of-band.
- **Relay Server (*Semi-Honest / Untrusted Server*):**
  - Mengelola antrean pengiriman dan bertindak sebagai direktori kunci publik sederhana.
  - Mengetahui waktu pengiriman, frekuensi pesan, dan identitas pengirim-penerima.
  - Bersifat *zero-knowledge* terhadap isi percakapan: relay tidak memiliki akses ke kunci privat, kunci AES, maupun plaintext. Dapat melakukan *Denial of Service* (DoS) dengan menghapus paket, tetapi tidak dapat memalsukan pesan yang lolos verifikasi integritas.
- **Pihak Ketiga Tak Terotorisasi (*Unauthorized Recipient*):**
  - Mengakses paket ciphertext yang ditujukan untuk orang lain dan mencoba membukanya menggunakan kunci privat miliknya sendiri.
- **Penyerang Lokal Perangkat (*Local Device Attacker*):**
  - Memiliki akses membaca media penyimpanan lokal klien (*file system access*).
  - Berupaya mengekstrak berkas identitas dan kunci privat pengguna.

---

## 2. Sifat yang Dijamin dan Didemonstrasikan

- **Kerahasiaan Muatan (*Confidentiality*):** Plaintext pesan dienkripsi dengan AES-256-GCM menggunakan kunci 256-bit segar per pesan. Kunci AES dilindungi enkripsi asimetris RSA-OAEP 2048-bit, sehingga hanya dapat didekripsi oleh pemegang kunci privat penerima yang sah.
- **Integritas dan Keaslian Muatan (*Integrity & Authenticity*):** Penerapan Galois/Counter Mode (GCM) menghasilkan *authentication tag* 128-bit yang mengikat ciphertext dan *Additional Authenticated Data* (AAD: `sender`, `receiver`, `counter`). Perubahan sekecil 1 bit pada ciphertext, tag, nonce, maupun metadata AAD menyebabkan verifikasi tag gagal total.
- **Ketahanan terhadap Replay (*Anti-Replay Resistance*):** Penerima memvalidasi nilai counter secara ketat (`counter > highest_received_counter`). Paket sah yang ditangkap penyerang dan dikirimkan ulang akan langsung ditolak pada lapisan pemeriksaan sebelum operasi kriptografi berat dieksekusi.
- **Perlindungan terhadap Nonce Reuse:** Kunci AES-256 dibangkitkan baru untuk setiap pesan tunggal (*one-time session key*), mengeliminasi risiko bencana kriptografi akibat penggunaan ulang kombinasi kunci dan nonce pada AES-GCM.
- **Perlindungan Kunci Privat saat Istirahat (*At-Rest Protection*):** Kunci privat RSA tidak pernah ditulis dalam format plaintext ke media penyimpanan; kunci selalu dienkripsi menggunakan fungsi derivasi berkekuatan tinggi (PBKDF2/Argon2id) berbasis passphrase pengguna dan salt acak 128-bit.

---

## 3. Kesenjangan Kritis (Critical Gaps & Trade-offs)

- **Ketiadaan *Forward Secrecy* (PFS):**
  - Kunci AES dibungkus (*wrapped*) menggunakan kunci RSA jangka panjang penerima.
  - Jika kunci privat RSA penerima berhasil dicuri atau bocor di masa depan, penyerang yang telah merekam seluruh lalu lintas ciphertext di masa lalu dapat mendekripsi semua pesan lama tersebut secara retroaktif.
- **Ketiadaan Autentikasi Kriptografis Pengirim (*No Digital Signature*):**
  - Skema RSA-OAEP murni adalah mekanisme enkripsi untuk menjamin kerahasiaan (*confidentiality*), bukan tanda tangan digital (*authenticity of origin*).
  - Siapapun yang memiliki kunci publik Bob dapat menyusun paket JSON dengan mencantumkan `sender: "alice"` dan mengenkripsinya ke Bob. Bob tahu pesan itu ditujukan untuk dirinya dan integritasnya utuh, tetapi tidak dapat membuktikan secara matematis bahwa Alice adalah pembuat pesan sebenarnya tanpa penambahan tanda tangan digital (misalnya RSA-PSS).
- **Distribusi Kunci Publik Rentan MITM tanpa PKI:**
  - Ketiadaan *Public Key Infrastructure* (PKI) atau Certificate Authority (CA) berarti kunci publik didistribusikan tanpa bukti keabsahan pihak ketiga tepercaya.
  - Penyerang aktif di jaringan dapat memotong request `GET_KEY` dan menyuntikkan kunci publik palsu. Keamanan otentikasi kunci sepenuhnya bergantung pada kecermatan pengguna memverifikasi nilai *fingerprint* SHA-256 lewat jalur komunikasi terpisah (*out-of-band*).
- **Kebocoran Metadata dan Analisis Lalu Lintas (*Traffic Analysis*):**
  - Header paket JSON (`version`, `sender`, `receiver`, `counter`) serta ukuran muatan paket dikirimkan secara terbuka (tidak dienkripsi), memungkinkan penyadap jaringan memetakan grafik komunikasi antar-pengguna.
- **Batas Keamanan Titik Akhir (*Endpoint Security*):**
  - Sistem tidak memiliki perlindungan berbasis perangkat keras (*Hardware Security Module* / TPM / Secure Enclave). Jika mesin lokal pengguna terinfeksi malware pembaca memori (*keylogger* atau *memory dumper*), kunci sesi dan plaintext aktif di RAM dapat dicuri.

---

## 4. Kebijakan Penanganan Kunci dan Data Sensitif

1. **Prinsip Non-Plaintext Storage:** Kunci privat RSA wajib dienkripsi dengan KDF passphrase sebelum ditulis ke berkas `identity`. Berkas `.identity`, `.key`, dan database lokal tidak boleh dimasukkan ke dalam version control (*Git*).
2. **Pembersihan Memori dan Log Bersih:**
   - Variabel plaintext dan kunci AES hanya hidup sementara di memori selama eksekusi fungsi enkripsi/dekripsi.
   - Panel visualizer hanya membaca variabel perantara dari memori sesi aktif untuk keperluan demonstrasi visual di UI.
   - Berkas log sistem **dilarang keras** mencatat plaintext, kunci AES, maupun passphrase pengguna. Log hanya diperbolehkan merekam *security events* (misalnya timestamp, status penolakan `ditolak_replay`, `gagal_unwrap`, atau `gagal_verifikasi`).
3. **Penyimpanan State Counter Atomik:** State counter penerima disimpan secara atomik ke disk lokal hanya setelah verifikasi tag GCM berhasil, mencegah desinkronisasi state saat terjadi pemadaman listrik atau *crash*.

---

## 5. Pengujian Keamanan yang Direncanakan

Pengujian keamanan dieksekusi secara otomatis dan tercatat pada tabel `attack_results`:

| Skenario Uji | Vektor Serangan | Ekspektasi Keamanan | Kriteria Lolos (*Pass*) |
|---|---|---|---|
| **Ciphertext Tampering** | Mengubah 1 byte acak pada ciphertext Base64 | Verifikasi tag AES-GCM mendeteksi kerusakan data | Eksepsi autentikasi muncul, pesan tidak didekripsi, status `gagal_verifikasi` |
| **Tag Tampering** | Mengubah 1 byte acak pada tag autentikasi 128-bit | Verifikasi keaslian AES-GCM menolak paket | Verifikasi gagal sebelum plaintext diserahkan ke memori |
| **AAD Metadata Tampering** | Mengubah nama `sender` atau nilai `counter` di JSON | AAD saat dekripsi tidak cocok dengan AAD saat enkripsi | Tag verification gagal seketika |
| **Wrong Key Unwrap** | Mendekripsi `wrapped_key` dengan private key pihak ketiga | Skema RSA-OAEP mendeteksi ketidaksesuaian kunci/padding | Dekripsi OAEP melempar error padding, eksekusi berhenti, status `gagal_unwrap` |
| **Replay Injection** | Mengirimkan ulang paket sah yang counter-nya $\le$ highest counter | Lapisan filter anti-replay menolak paket | Paket dibuang di awal tanpa memicu operasi RSA yang mahal, status `ditolak_replay` |
| **KAT NIST Verification** | Validasi implementasi AES-GCM terhadap NIST SP 800-38D | Memastikan kepatuhan matematis standar resmi | Seluruh test vector resmi menghasilkan output identik |
| **Interoperabilitas OAEP** | Validasi parameter hash SHA-256 dan MGF1 SHA-256 eksplisit | Memastikan konsistensi lintas pustaka kripto | Klien pengirim dan penerima dapat saling buka tanpa error padding |
| **Nonce Reuse Demo (Bonus)**| Menggunakan $K_{AES}$ dan Nonce yang sama pada 2 pesan berbeda | Memperagakan kebocoran informasi akibat pelanggaran aturan | Nilai XOR plaintext dapat dipulihkan, membuktikan bahaya reuse |

---

## 6. Batas Penggunaan

Prototipe aplikasi chat ini dikembangkan **semata-mata untuk tujuan simulasi akademis, demonstrasi perkuliahan kriptografi, dan evaluasi empiris**.

Aplikasi ini **TIDAK BOLEH** digunakan untuk:
- Mengirimkan data sensitif, informasi rahasia, atau kredensial nyata di jaringan publik.
- Mengklaim perlindungan anonimitas penuh atau jaminan keamanan tingkat produksi (*production-grade messaging*).
- Menggantikan aplikasi pesan berstandar industri (seperti Signal Protocol) sebelum kelemahan fundamental (ketiadaan Forward Secrecy, ketiadaan tanda tangan digital pengirim, dan ketiadaan PKI) diatasi secara menyeluruh.
