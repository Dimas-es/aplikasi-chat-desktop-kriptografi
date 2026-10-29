# Perancangan Sistem

## 1. Modul utama

- **UI chat:** input pesan, daftar kontak, tampilan pesan terverifikasi, status verifikasi, dan mode visualisasi proses.
- **Key management:** pembuatan pasangan kunci RSA-2048, enkripsi private key dengan passphrase (PBKDF2 atau Argon2), pengelolaan public key kontak dan fingerprint.
- **Cryptography:** AES-256-GCM (nonce 96-bit, AAD berisi sender, receiver, dan counter) dan RSA-OAEP dengan SHA-256, MGF1 SHA-256, dan label kosong; hanya memakai library kriptografi mapan.
- **Messaging:** menyusun dan mem-parse paket, menaikkan dan memeriksa counter, menghasilkan status pesan.
- **Network:** koneksi socket langsung atau ke relay; pengiriman dan penerimaan paket.
- **Persistence:** penyimpanan lokal identitas, kontak, dan counter; relay menyimpan antrean paket ciphertext.
- **Simulation:** skenario serangan dan benchmark hybrid vs RSA-only, hanya pada lingkungan uji.

## 2. Entitas data

Mekanisme penyimpanan belum diputuskan (berkas terenkripsi atau SQLite); nama di bawah bersifat logis.

| Entitas | Data penting | Keterangan |
| --- | --- | --- |
| `identity` | user\_id, display\_name, public\_key, private\_key\_terenkripsi, kdf\_salt, kdf\_params | Identitas lokal dan kunci RSA pengguna |
| `contacts` | contact\_id, display\_name, public\_key, fingerprint, verified | Public key lawan bicara dan status verifikasi fingerprint |
| `counter_state` | contact\_id, last\_sent\_counter, highest\_received\_counter | Counter anti-replay; harus persisten |
| `relay_queue` | queue\_id, receiver\_id, packet, received\_at | Antrean paket ciphertext; hanya ada pada relay |
| `attack_results` | scenario, expected, actual, passed, executed\_at | Hasil simulasi serangan |
| `benchmark_results` | scenario, message\_size, runs, mean\_ms, std\_ms, created\_at | Hasil pengukuran kinerja |

## 3. Relasi data

&#91;embedded content: relasi data · 6 entitas, 3 relasi\]

Tabel hasil uji tidak diberi foreign key karena hanya merekam hasil pengujian dan harus tetap terbaca ketika kontak atau identitas dihapus. Kebijakan retensi dan perlindungan berkas `identity`, yang berisi private key terenkripsi, tetap perlu dirancang.

## 4. Antarmuka protokol

| Tipe | Arah | Tujuan |
| --- | --- | --- |
| `PUBLISH_KEY` | klien → relay | Mengunggah user\_id dan public key |
| `GET_KEY` | klien → relay | Mengambil public key lawan bicara |
| `SEND` | klien → relay atau klien lain | Mengirim paket pesan terenkripsi |
| `FETCH` | klien → relay | Mengambil paket tertunda untuk user\_id |

Pada mode langsung via socket hanya `SEND` yang dipakai, dan public key ditukar di awal sesi. Tipe di atas bersifat usulan dan mengikuti keputusan arsitektur komunikasi. Relay tidak mengautentikasi pengguna pada tingkat prototipe, sehingga siapa pun dapat mengunggah public key atas nama sebuah user\_id; hal ini dicatat sebagai keterbatasan.

## 5. Format paket pesan

```json
{
  "version": 1,
  "sender": "alice",
  "receiver": "bob",
  "counter": 7,
  "wrapped_key": "<base64, 256 byte untuk RSA-2048>",
  "nonce": "<base64, 12 byte>",
  "ciphertext": "<base64, termasuk tag 16 byte di akhir>"
}
```

Nilai di atas merupakan ilustrasi struktur paket, bukan ciphertext valid. Field `sender`, `receiver`, dan `counter` terikat sebagai AAD; perubahan pada salah satunya membuat verifikasi GCM gagal. Perubahan format menaikkan nilai `version`.

## 6. Status pesan

| Status | Pihak | Kondisi | Tindakan |
| --- | --- | --- | --- |
| `terkirim` | Pengirim | Paket sudah dikirim ke jaringan atau relay | Counter pengirim bertambah |
| `valid` | Penerima | Counter lebih besar dari yang tertinggi, unwrap berhasil, tag valid | Pesan ditampilkan; counter tertinggi diperbarui |
| `ditolak_replay` | Penerima | Counter tidak lebih besar dari yang tertinggi | Paket dibuang dan kejadian dicatat |
| `gagal_unwrap` | Penerima | Unwrap RSA-OAEP gagal | Proses dihentikan sebelum dekripsi |
| `gagal_verifikasi` | Penerima | Authentication tag GCM tidak cocok | Paket dibuang dan ditandai tidak tepercaya |

## 7. Aturan konsistensi

- Setiap pesan memakai kunci AES dan nonce baru; nonce tidak pernah dipakai ulang dengan kunci yang sama.
- AAD saat enkripsi dan dekripsi harus identik (sender, receiver, counter).
- Parameter OAEP (SHA-256 untuk hash dan MGF1, label kosong) sama pada pengirim dan penerima, dan diuji interoperabilitasnya.
- Counter tertinggi disimpan persisten dan hanya diperbarui setelah tag terverifikasi, agar paket palsu dengan counter besar tidak memblokir pesan sah.
- Private key tidak pernah ditulis plaintext ke disk, log, atau paket.
- Log persisten tidak memuat kunci AES maupun plaintext; nilai hex pada mode visualisasi hanya ditampilkan di UI.
- Perubahan format paket menaikkan `version` dan tidak mengubah arti versi sebelumnya.
