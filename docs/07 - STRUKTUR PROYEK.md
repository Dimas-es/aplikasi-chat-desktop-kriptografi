# Struktur Proyek dan Tanggung Jawab Direktori

Struktur di bawah adalah **pemetaan komponen yang diketahui dan struktur dokumentasi yang disarankan**, bukan hasil inspeksi menyeluruh seluruh repository.

```text
kripto/
├── README.md
├── docs/
│   ├── 01-PRD.md
│   ├── 02 - PENELITIAN.md
│   ├── 03 - GOALS.md
│   ├── 04 - ARSITEKTUR.md
│   ├── 05 - PERANCANGAN SISTEM.md
│   ├── 06 - WORKFLOW.md
│   ├── 07 - STRUKTUR PROYEK.md
│   ├── 08 - TEKNOLOGI.md
│   ├── 09 - KEAMANAN.md
│   ├── 10 - ROADMAP.md
│   ├── 11 - SETUP LOKAL.md
│   ├── 12 - HASIL PENGUJIAN.md
│   ├── 13 - RENCANA KOMUNIKASI MULTI-DEVICE LAN.md
│   ├── 14 - PANDUAN PACKAGING DAN DISTRIBUSI EXE.md
│   └── 15 - PENINGKATAN DIGITAL SIGNATURE RSA-PSS.md
├── client/
│   ├── main.py
│   ├── app.py
│   ├── eve_hacker.py
│   ├── ui/
│   │   ├── chat_window.py
│   │   ├── visualizer_panel.py
│   │   └── key_dialog.py
│   └── controllers/
│       ├── chat_controller.py
│       └── visualizer_controller.py
├── src/
│   ├── crypto/
│   │   ├── aes_gcm.py
│   │   ├── rsa_oaep.py
│   │   ├── rsa_pss.py
│   │   ├── kdf.py
│   │   └── fingerprint.py
│   ├── messaging/
│   │   ├── packet.py
│   │   ├── aad.py
│   │   └── status.py
│   ├── storage/
│   │   ├── db.py
│   │   ├── keystore.py
│   │   ├── contact_store.py
│   │   └── counter_store.py
│   └── network/
│       ├── socket_client.py
│       └── relay_client.py
├── relay/
│   ├── server.py
│   ├── router.py
│   ├── queue.py
│   └── registry.py
├── simulation/
│   ├── runner.py
│   └── scenarios/
│       ├── tampering.py
│       ├── wrong_key.py
│       ├── replay.py
│       ├── nonce_reuse_demo.py
│       └── spoofing.py
├── benchmark/
│   ├── benchmark_runner.py
│   ├── hybrid_bench.py
│   ├── rsa_only_bench.py
│   └── visualizer.py
└── tests/
    ├── test_aad.py
    ├── test_benchmark.py
    ├── test_controller.py
    ├── test_crypto_aes.py
    ├── test_crypto_rsa.py
    ├── test_fingerprint.py
    ├── test_hybrid.py
    ├── test_kdf.py
    ├── test_network.py
    ├── test_packet_schema.py
    ├── test_signature.py
    ├── test_simulation.py
    └── test_storage.py
├── build_exe.py
├── installer.iss
```

## Tanggung jawab

- `client`: antarmuka chat desktop, konsol penyadapan/penyerang independen Eve (`eve_hacker.py`), panel visualisasi proses kriptografi (hex & byte inspector), dialog pembuatan kunci/passphrase, dan controller aplikasi.
- `src/crypto`: implementasi primitif kriptografi murni (AES-256-GCM, RSA-OAEP SHA-256, derivasi kunci passphrase PBKDF2/Argon2, dan fingerprint).
- `src/messaging`: serializer/deserializer format paket JSON v1, pengikat AAD kanonikal, dan manajemen status pesan.
- `src/storage`: penyimpanan lokal identitas dan private key terenkripsi (`identity`), kontak lawan bicara (`contacts`), dan state counter anti-replay persisten (`counter_state`).
- `src/network`: transportasi data socket P2P dan protokol klien relay (`PUBLISH_KEY`, `GET_KEY`, `SEND`, `FETCH`).
- `relay`: server perantara zero-knowledge untuk antrean paket ciphertext dan direktori public key tanpa akses ke plaintext atau private key.
- `simulation`: skrip otomasi skenario serangan (modifikasi ciphertext/tag, private key salah, replay attack, dan demonstrasi nonce reuse).
- `benchmark`: pengujian empiris komparasi performa Hybrid vs RSA-only, pengukuran latensi/throughput, pembuktian batas ukuran payload RSA-2048 (<190B), dan visualisasi grafik hasil.
- `tests`: pengujian unit kebenaran algoritma, validasi NIST test vectors, dan uji interoperabilitas.
- `docs`: spesifikasi produk, penelitian, sasaran, arsitektur, perancangan sistem, alur proses, struktur proyek, teknologi, keamanan, roadmap pengembangan, dan panduan setup lokal.

**Penting:** file `.env`, private key (unencrypted), file identitas lokal (`*.identity`, `*.key`), dan database pengujian tidak boleh dikomit ke repository. Seluruh dokumen spesifikasi disimpan langsung di dalam folder `docs/` tanpa subfolder.
