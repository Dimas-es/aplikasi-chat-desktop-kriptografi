# Workflow dan Alur Proses

Dokumen ini mendefinisikan alur kerja operasional, proses kriptografi langkah-demi-langkah, penanganan verifikasi dan anti-replay, mode visualisasi, simulasi serangan, hingga benchmark kinerja pada prototipe aplikasi chat desktop dengan enkripsi hybrid AES-256-GCM dan RSA-OAEP SHA-256.

---

## 1. Bootstrap Akun dan Manajemen Kunci

Pada aplikasi chat desktop ini, identitas pengguna dan pasangan kunci RSA dibuat secara lokal di sisi klien. Private key dilindungi menggunakan enkripsi simetris berbasis passphrase pengguna (KDF: PBKDF2 atau Argon2) sebelum disimpan ke penyimpanan lokal (`identity`).

Public key dipertukarkan antar pengguna, baik secara langsung (mode socket peer-to-peer) maupun melalui perantara relay server (`PUBLISH_KEY` dan `GET_KEY`).

```mermaid
sequenceDiagram
  autonumber
  actor U as Pengguna (Alice)
  participant W as UI Desktop
  participant KM as Modul Key Management
  participant KS as Key Store Lokal (identity)
  participant R as Relay Server (Opsional)
  
  U->>W: Input display name & passphrase
  W->>KM: Request pembuatan identitas
  KM->>KM: Generate pasangan kunci RSA-2048
  KM->>KM: Derivasi KDF Key dari passphrase (Salt acak)
  KM->>KM: Enkripsi Private Key dengan KDF Key
  KM->>KS: Simpan (user_id, display_name, public_key, encrypted_priv_key, salt)
  KS-->>W: Identitas lokal berhasil dibuat
  
  opt Jika Menggunakan Relay Server
    W->>R: PUBLISH_KEY (user_id, public_key)
    R-->>W: Acknowledgment (Key terdaftar)
  end
```

### Pertukaran Public Key Lawan Bicara

```mermaid
sequenceDiagram
  autonumber
  actor A as Alice (Klien A)
  participant R as Relay Server / Bob
  participant CS as Contact Store (contacts)
  actor B as Bob (Klien B)
  
  A->>R: GET_KEY (user_id: "bob")
  R-->>A: Public Key Bob
  A->>A: Hitung Fingerprint SHA-256 dari Public Key
  A->>CS: Simpan kontak (contact_id, public_key, fingerprint, verified=false)
  
  opt Verifikasi Jalur Terpisah (Out-of-band)
    A->>B: Cocokkan fingerprint secara visual / lisan
    A->>CS: Set status verified = true
  end
```

> [!NOTE]
> Karena sistem tidak menggunakan Public Key Infrastructure (PKI) atau Certificate Authority (CA), verifikasi fingerprint secara out-of-band adalah satu-satunya mekanisme verifikasi keaslian public key untuk mendeteksi serangan Man-in-the-Middle (MITM).

---

## 2. Alur Pengiriman Pesan (Enkripsi Hybrid)

Pengiriman pesan menerapkan enkripsi hybrid:
1. Isi pesan dienkripsi dengan **AES-256-GCM** menggunakan kunci simetris yang dibangkitkan baru untuk setiap pesan.
2. Kunci AES tersebut dibungkus (**wrapped**) menggunakan **RSA-OAEP SHA-256** dengan public key penerima.
3. Metadata pengiriman (`sender`, `receiver`, `counter`) diikat sebagai *Additional Authenticated Data* (AAD) pada AES-GCM.

```mermaid
sequenceDiagram
  autonumber
  actor U as Pengirim (Alice)
  participant UI as UI Chat & Visualizer
  participant M as Messaging Service
  participant C as Crypto Engine
  participant S as Counter State
  participant N as Network / Relay

  U->>UI: Ketik pesan teks & klik "Kirim"
  UI->>M: Kirim pesan (text, receiver: "bob")
  M->>S: Ambil & naikkan last_sent_counter
  S-->>M: counter = N
  
  M->>C: Request Enkripsi Hybrid(plaintext, bob_pub_key, sender, receiver, counter)
  
  rect rgb(240, 248, 255)
    Note over C: Proses Kriptografi Pengirim
    C->>C: Generate K_AES acak (256-bit / 32 byte)
    C->>C: Generate Nonce acak (96-bit / 12 byte)
    C->>C: Susun AAD kanonikal (sender + receiver + counter)
    C->>C: AES-GCM Encrypt(plaintext, K_AES, Nonce, AAD) -> ciphertext + tag (128-bit)
    C->>C: RSA-OAEP Wrap(K_AES, bob_pub_key, SHA-256, MGF1-SHA256) -> wrapped_key (256 byte)
  end

  C-->>M: Paket data terenkripsi (wrapped_key, nonce, ciphertext+tag)
  M->>UI: Simpan log data per tahap (Hex visualizer)
  M->>N: SEND (paket JSON v1)
  N-->>M: Status terkirim
  M->>UI: Update status pesan: "terkirim"
```

### Rincian Pembentukan Paket Pesan

- **Kunci AES ($K_{AES}$):** 32 byte pseudorandom dibangkitkan segar per pesan. Menghilangkan risiko penggunaan ulang nonce pada kunci yang sama (*nonce reuse*).
- **Nonce GCM:** 12 byte (96 bit) pseudorandom sesuai rekomendasi NIST SP 800-38D.
- **AAD (Associated Data):** Representasi kanonikal `sender + ":" + receiver + ":" + counter`. Mengikat identitas pengirim, penerima, dan urutan pesan secara kriptografis tanpa mengekspos isi pesan.
- **Wrapped Key:** Kunci AES 32 byte dienkripsi dengan RSA-OAEP parameter SHA-256 (panjang output 256 byte untuk RSA-2048).

---

## 3. Alur Penerimaan dan Dekripsi Pesan

Sisi penerima memvalidasi paket secara ketat melalui tahapan berjenjang:
1. Pengecekan counter anti-replay.
2. Pembukaan (*unwrapping*) kunci AES menggunakan private key RSA penerima.
3. Verifikasi integritas AAD dan tag autentikasi AES-GCM, dilanjutkan dekripsi isi pesan.
4. Pembaruan state counter hanya jika seluruh tahap verifikasi berhasil.

```mermaid
sequenceDiagram
  autonumber
  participant N as Network / Relay
  participant M as Messaging Service
  participant S as Counter State
  participant C as Crypto Engine
  participant KS as Key Store (identity)
  participant UI as UI Chat & Visualizer

  N->>M: Paket masuk (JSON v1)
  M->>M: Parse format & field paket
  
  M->>S: Validasi counter terhadap highest_received_counter
  alt counter <= highest_received_counter (Replay Terdeteksi)
    S-->>M: Tidak valid (Replay)
    M->>UI: Catat status: "ditolak_replay" & buang paket
  else counter > highest_received_counter (Counter Valid)
    S-->>M: Counter sah
    M->>KS: Ambil Private Key Bob (RSA-2048)
    KS-->>M: Private Key (in-memory)
    
    M->>C: Request Dekripsi Hybrid(wrapped_key, nonce, ciphertext_tag, AAD, priv_key)
    
    rect rgb(255, 250, 240)
      Note over C: Proses Kriptografi Penerima
      C->>C: RSA-OAEP Unwrap(wrapped_key, priv_key, SHA-256, MGF1-SHA256)
      alt Unwrap Gagal (Kunci salah / Padding corrupt)
        C-->>M: Error OAEP Decryption
        M->>UI: Catat status: "gagal_unwrap" & buang paket
      else Unwrap Berhasil
        C->>C: Dapatkan K_AES (32 byte)
        C->>C: Rekonstruksi AAD kanonikal (sender + receiver + counter)
        C->>C: AES-GCM Decrypt & Verify(ciphertext, tag, K_AES, Nonce, AAD)
        alt Tag / AAD Tidak Cocok (Integritas Rusak)
          C-->>M: Error GCM Tag Mismatch
          M->>UI: Catat status: "gagal_verifikasi" & beri alert integritas
        else Tag & AAD Valid
          C-->>M: Plaintext (UTF-8)
        end
      end
    end

    alt Seluruh Kriptografi Sukses
      M->>S: Commit highest_received_counter = counter paket
      S-->>M: Counter tersimpan persisten
      M->>UI: Tampilkan pesan di chat & log visualisasi (status: "valid")
    end
  end
```

---

## 4. Alur Validasi Idempotency, State Counter, dan Anti-Replay

Pengelolaan status counter mencegah serangan replay dan memastikan konsistensi state. Diagram berikut menggambarkan alur pengambilan keputusan pada setiap pesan yang diterima:

```mermaid
flowchart TD
  A[Paket Pesan Diterima] --> B{Format JSON & skema valid?}
  B -- Tidak --> B1[Buang paket / log format error]
  B -- Ya --> C{counter > highest_received_counter?}
  
  C -- Tidak --> D[Status: ditolak_replay]
  D --> D1[Catat security event & buang paket]
  
  C -- Ya --> E[Unwrap RSA-OAEP dengan Private Key]
  E --> F{Unwrap berhasil?}
  F -- Tidak --> G[Status: gagal_unwrap]
  G --> G1[Hentikan proses & buang paket]
  
  F -- Ya --> H[Ekstrak K_AES]
  H --> I[Rekonstruksi AAD sender:receiver:counter]
  I --> J[AES-GCM Decrypt & Tag Verification]
  
  J --> K{Tag & AAD Cocok?}
  K -- Tidak --> L[Status: gagal_verifikasi]
  L --> L1[Peringatan manipulasi data & buang paket]
  
  K -- Ya --> M[Ekstrak Plaintext UTF-8]
  M --> N[Simpan highest_received_counter ke Disk]
  N --> O[Status: valid]
  O --> P[Render pesan di UI Chat]
```

### Aturan Kritis Pembaruan Counter
> [!IMPORTANT]
> `highest_received_counter` **hanya diperbarui secara persisten setelah verifikasi tag AES-GCM berhasil**. 
> Jika counter dinaikkan sebelum verifikasi tag selesai, penyerang dapat melancarkan serangan *Denial of Service* (DoS) sederhana: mengirim paket palsu dengan nilai counter sangat besar ($N = 999999$). Bila counter dinaikkan prematur, semua pesan sah berikutnya dari pengirim asli akan ditolak permanen sebagai replay.

---

## 5. Alur Mode Visualisasi Kriptografi

Mode visualisasi dirancang untuk kepentingan edukasi dan transparansi audit pada pengujian akademik. Mode ini mengekstrak nilai heksadesimal dari variabel kriptografi di setiap tahap pemrosesan tanpa membocorkannya ke disk atau log permanen.

```mermaid
sequenceDiagram
  participant UI as Tampilan UI Visualizer
  participant Core as Core Engine
  participant Mem as In-Memory State Inspector

  Core->>Mem: Catat Stage 1: Plaintext & UTF-8 bytes
  Core->>Mem: Catat Stage 2: K_AES (32 Byte Hex) & Nonce (12 Byte Hex)
  Core->>Mem: Catat Stage 3: AAD kanonikal ("alice:bob:7")
  Core->>Mem: Catat Stage 4: AES-GCM Output (Ciphertext Hex & Tag Hex 16 Byte)
  Core->>Mem: Catat Stage 5: RSA-OAEP Output (Wrapped Key Hex 256 Byte)
  Core->>Mem: Catat Stage 6: Final Packet JSON
  
  Mem-->>UI: Render Data Pipeline Hex Viewer
  Note over UI: Pengguna dapat mengklik tiap tahap<br/>untuk melihat transformasi matematis
```

### Parameter yang Ditampilkan pada Mode Visualisasi

| Tahap | Parameter | Tipe Representasi | Keterangan |
| --- | --- | --- | --- |
| 1. Input | Plaintext | String / UTF-8 Hex | Isi pesan asli sebelum diamankan |
| 2. Kunci Simetris | $K_{AES}$ | 64 karakter Hex (256-bit) | Kunci acak unik per pesan |
| 3. Inisialisasi IV | Nonce GCM | 24 karakter Hex (96-bit) | Nonce acak unik per pesan |
| 4. Pengikatan Metadata | AAD | ASCII String & Byte Hex | `sender:receiver:counter` |
| 5. Enkripsi Data | Ciphertext + Tag | Hex stream + Tag 16 Byte Hex | Bukti kerahasiaan dan integritas |
| 6. Pembungkusan Kunci | Wrapped Key | 512 karakter Hex (2048-bit) | $K_{AES}$ dienkripsi RSA-OAEP Bob |
| 7. Verifikasi & Unwrap | Unwrap & Tag Status | Status badge (`OK` / `FAIL`) | Hasil pemeriksaan integritas penerima |

---

## 6. Alur Simulasi Skenario Serangan

Simulasi serangan dijalankan di lingkungan uji untuk membuktikan ketahanan sistem terhadap ancaman aktif secara empiris.

```mermaid
flowchart TD
  subgraph Skenario_1 [Skenario 1: Modifikasi Ciphertext / Tag]
    S1A[Paket Asli] --> S1B[Flip 1 Bit / Modifikasi 1 Byte Ciphertext/Tag/Nonce]
    S1B --> S1C[Penerima: Eksekusi AES-GCM Tag Verify]
    S1C --> S1D{Tag Valid?}
    S1D -- Tidak --> S1E[PASS: Verifikasi Gagal, Paket Ditolak]
    S1D -- Ya --> S1F[FAIL: Sistem Tidak Aman]
  end

  subgraph Skenario_2 [Skenario 2: Private Key Salah]
    S2A[Paket untuk Bob] --> S2B[Penerima mencoba buka dengan Private Key Eve]
    S2B --> S2C[Penerima: Eksekusi RSA-OAEP Decrypt]
    S2C --> S2D{Unwrap Berhasil?}
    S2D -- Tidak --> S2E[PASS: OAEP Padding Check Gagal, Eksekusi Berhenti]
    S2D -- Ya --> S2F[FAIL: Kunci Tidak Sesuai Berhasil Dekripsi]
  end

  subgraph Skenario_3 [Skenario 3: Serangan Replay]
    S3A[Paket counter N Berhasil Diterima] --> S3B[Injeksi Ulang Paket N yang Sama]
    S3B --> S3C[Penerima: Periksa counter <= highest_received_counter]
    S3C --> S3D{Lolos Filter?}
    S3D -- Tidak --> S3E[PASS: Ditolak di Lapisan Awal Sebelum Kripto]
    S3D -- Ya --> S3F[FAIL: Replay Diterima]
  end
```

### Matriks Pengujian Simulasi Serangan

| ID Uji | Skenario | Titik Serangan | Perilaku yang Diharapkan | Hasil / Status |
| --- | --- | --- | --- | --- |
| ATK-01 | Bit-flipping Ciphertext | 1 byte diubah pada ciphertext | AES-GCM tag verification gagal; status `gagal_verifikasi` | Lolos uji negatif |
| ATK-02 | Tag Tampering | 1 byte diubah pada authentication tag | GCM tag mismatch; pesan ditolak | Lolos uji negatif |
| ATK-03 | AAD Tampering | Field `sender` atau `counter` diubah di JSON | Tag verification gagal karena AAD tidak cocok | Lolos uji negatif |
| ATK-04 | Wrong Private Key | Dekripsi dengan private key pihak ketiga | RSA-OAEP unwrap gagal; status `gagal_unwrap` | Lolos uji negatif |
| ATK-05 | Replay Attack | Mengirim ulang paket yang sudah diproses | Ditolak oleh rule `counter <= highest`; status `ditolak_replay` | Lolos uji negatif |
| ATK-06 | Nonce Reuse Demo (Bonus) | Enkripsi 2 pesan berbeda dengan K_AES & Nonce sama | Menunjukkan kebocoran XOR plaintext & kegagalan keaslian | Lolos demonstrasi |

---

## 7. Alur Pengujian Benchmark Kinerja

Benchmark membandingkan efisiensi waktu pemrosesan dan batasan muatan (*payload limit*) antara skema **Enkripsi Hybrid (AES-GCM + RSA-OAEP)** dan skema **RSA-Only (RSA-OAEP murni)**.

```mermaid
flowchart TD
  A[Mulai Benchmark Kinerja] --> B[Siapkan Dataset Ukuran Pesan: 64B, 1KB, 10KB, 100KB, 1MB]
  B --> C[Set Iterasi: 10 s.d. 30 Pengulangan per Ukuran]
  
  C --> D[Uji Skema Hybrid]
  D --> D1[Ukur Waktu Enkripsi: AES Encrypt + OAEP Wrap]
  D1 --> D2[Ukur Waktu Dekripsi: OAEP Unwrap + AES Decrypt]
  D2 --> D3[Ukur Ukuran Paket & Overhead Ciphertext]
  D3 --> D4[Catat Mean & Simpangan Baku]
  
  C --> E[Uji Skema RSA-Only]
  E --> E1{Ukuran Pesan <= 190 Byte?}
  E1 -- Ya --> E2[Ukur Waktu Enkripsi & Dekripsi RSA-OAEP]
  E2 --> E4[Catat Mean & Simpangan Baku]
  E1 -- Tidak --> E3[Catat Failure: Exceeds RSA Maximum Payload Size]
  
  D4 --> F[Agregasi Statistik & Ekspor Tabel / Grafik Komparasi]
  E4 --> F
  E3 --> F
```

### Catatan Penting Batasan RSA-Only:
Pada kunci RSA-2048 bit dengan padding RSA-OAEP SHA-256:
$$\text{Max Payload} = \text{KeySize} - 2 \cdot hLen - 2 = 256 - 2(32) - 2 = 190 \text{ byte}$$
Untuk ukuran pesan $\ge 190$ byte, skema RSA-Only secara matematis mengalami kegagalan (*overflow exception*), membuktikan kebutuhan mutlak terhadap enkripsi hybrid untuk aplikasi komunikasi data riil.

---

## 8. Penanganan Kegagalan, Recovery, dan Edge Cases

```mermaid
flowchart TD
  A[Pemicu Gangguan / Kegagalan] --> B{Jenis Gangguan}
  
  B -- Relay Putus / Jaringan Down --> C[Antrean Lokal Offline Queue]
  C --> C1[Retry dengan Exponential Backoff saat Koneksi Pulih]
  
  B -- Aplikasi Crash / Mati Mendadak --> D[Pulihkan State dari Disk]
  D --> D1[Muat highest_received_counter Terakhir yang Terverifikasi]
  
  B -- Paket Out-of-Order --> E{counter > highest_received_counter?}
  E -- Ya --> E1[Terima & Update Counter ke Nilai Baru]
  E -- Tidak --> E2[Tolak Paket yang Datang Terlambat]
  
  B -- Passphrase Salah saat Unlock --> F[Tolak Pembukaan Private Key]
  F --> F1[Beri Kesempatan Input Ulang tanpa Merusak Key File]
```

### Ringkasan Strategi Pemulihan

1. **Jaringan Terputus:** Pesan yang belum terkirim ditampung dalam antrean memori lokal klien dan dikirim ulang saat socket terhubung kembali.
2. **Crash Consistency:** State counter disimpan secara atomik pada database/berkas lokal sesaat setelah verifikasi tag sukses, mencegah pemutaran ulang counter saat aplikasi dimulai kembali (*restart*).
3. **Ketidakcocokan Parameter OAEP:** Jika dua klien menggunakan hash berbeda (misalnya salah satu memakai default MGF1-SHA1), modul kripto mengembalikan error deskriptif eksplisit (`INVALID_PADDING_OR_HASH_MISMATCH`) dan tidak membiarkan crash tanpa penanganan.

---

## 9. Kondisi Akhir yang Diinginkan

Implementasi alur kerja sistem harus memenuhi kriteria berikut:

1. **Kebenaran Fungsional (*Correctness*):** Pesan teks pendek, pesan panjang berukuran megabyte, dan karakter Unicode/emoji terenkripsi dan terdekripsi 100% identik dengan teks asal.
2. **Kerahasiaan Mutlak di Transit (*Confidentiality*):** Inspeksi paket jaringan melalui sniffer (misal Wireshark) hanya memperlihatkan ciphertext acak dan metadata paket; tidak ada plaintext maupun kunci AES yang terekspos.
3. **Integritas Tak Terkompromi (*Integrity*):** Perubahan 1 bit tunggal pada ciphertext, tag, nonce, maupun metadata AAD selalu ditolak oleh verifikasi AES-GCM.
4. **Ketahanan Replay Teruji (*Anti-Replay*):** Paket lama yang dikirim ulang selalu ditolak sebelum masuk ke proses dekripsi kunci asimetris.
5. **Observabilitas Transparan:** Mode visualisasi menyediakan representasi hex terstruktur pada setiap tahapan untuk keperluan edukasi dan pengujian dosen/penilai.
6. **Kinerja Terukur dan Terdokumentasi:** Hasil benchmark menunjukkan efisiensi skema hybrid dibandingkan RSA-only, lengkap dengan data rata-rata, deviasi standar, dan grafik komparasi.
