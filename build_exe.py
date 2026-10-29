"""
Skrip Otomatisasi Kompilasi PyInstaller ke Executable (.EXE) Windows.

Penggunaan:
    python build_exe.py
"""

import sys
import os
import shutil
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "dist")
BUILD_DIR = os.path.join(BASE_DIR, "build")


def clean_previous_builds():
    """Membersihkan folder build/ dan dist/ sebelumnya."""
    print("[*] Membersihkan artefak kompilasi sebelumnya...")
    for folder in [DIST_DIR, BUILD_DIR]:
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
                print(f"    - Menghapus {folder}")
            except Exception as exc:
                print(f"    [!] Gagal menghapus {folder}: {exc}")


def build_cryptochat():
    """Mengompilasi aplikasi klien GUI CryptoChat.exe."""
    print("\n" + "=" * 60)
    print("[*] Memulai kompilasi Klien GUI: CryptoChat.exe")
    print("=" * 60)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconsole",
        "--onedir",
        "--name",
        "CryptoChat",
        "--collect-all",
        "customtkinter",
        "--collect-all",
        "cryptography",
        "--collect-all",
        "cffi",
        "--hidden-import",
        "darkdetect",
        "--hidden-import",
        "PIL",
        "--clean",
        os.path.join(BASE_DIR, "client", "main.py"),
    ]

    print(f"[*] Menjalankan perintah: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode != 0:
        print("[!] Gagal mengompilasi CryptoChat.exe!")
        return False
    print("[+] Berhasil mengompilasi CryptoChat.exe!")
    return True


def build_relay_server():
    """Mengompilasi aplikasi server perantara RelayServer.exe."""
    print("\n" + "=" * 60)
    print("[*] Memulai kompilasi Server: RelayServer.exe")
    print("=" * 60)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--console",
        "--onedir",
        "--name",
        "RelayServer",
        "--clean",
        os.path.join(BASE_DIR, "relay", "server.py"),
    ]

    print(f"[*] Menjalankan perintah: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode != 0:
        print("[!] Gagal mengompilasi RelayServer.exe!")
        return False
    print("[+] Berhasil mengompilasi RelayServer.exe!")
    return True


def create_portable_bundle():
    """Menggabungkan CryptoChat dan RelayServer ke dalam satu bundel portabel siap pakai."""
    print("\n" + "=" * 60)
    print("[*] Membuat paket distribusi portabel siap bagi (CryptoChat_Portable)...")
    print("=" * 60)

    portable_dir = os.path.join(DIST_DIR, "CryptoChat_Portable")
    os.makedirs(portable_dir, exist_ok=True)

    # 1. Salin folder CryptoChat jika ada
    src_client = os.path.join(DIST_DIR, "CryptoChat")
    if os.path.exists(src_client):
        dst_client = os.path.join(portable_dir, "App")
        if os.path.exists(dst_client):
            shutil.rmtree(dst_client)
        shutil.copytree(src_client, dst_client)

    # 2. Salin RelayServer jika ada
    src_relay = os.path.join(DIST_DIR, "RelayServer")
    if os.path.exists(src_relay):
        dst_relay = os.path.join(portable_dir, "Relay")
        if os.path.exists(dst_relay):
            shutil.rmtree(dst_relay)
        shutil.copytree(src_relay, dst_relay)

    # 3. Buat launcher script batch untuk kemudahan pengguna non-teknis
    launcher_alice_bat = os.path.join(portable_dir, "JALANKAN_ALICE.bat")
    with open(launcher_alice_bat, "w") as f:
        f.write("@echo off\n")
        f.write('start "" "%~dp0App\\CryptoChat.exe" --user alice --relay-host 127.0.0.1\n')

    launcher_bob_bat = os.path.join(portable_dir, "JALANKAN_BOB.bat")
    with open(launcher_bob_bat, "w") as f:
        f.write("@echo off\n")
        f.write('start "" "%~dp0App\\CryptoChat.exe" --user bob --relay-host 127.0.0.1\n')

    launcher_relay_bat = os.path.join(portable_dir, "JALANKAN_RELAY_SERVER.bat")
    with open(launcher_relay_bat, "w") as f:
        f.write("@echo off\n")
        f.write('title TrustGive Zero-Knowledge Relay Server\n')
        f.write('"%~dp0Relay\\RelayServer.exe" --host 0.0.0.0 --port 8000\n')
        f.write("pause\n")

    # 4. Berkas Panduan Singkat
    readme_txt = os.path.join(portable_dir, "PETUNJUK_PENGGUNAAN.txt")
    with open(readme_txt, "w", encoding="utf-8") as f:
        f.write("============================================================\n")
        f.write("PANDUAN PEMAKAIAN APLIKASI CHAT KRIPTOGRAFI PORTABEL (.EXE)\n")
        f.write("============================================================\n\n")
        f.write("Aplikasi ini sudah mandiri dan TIDAK MEMERLUKAN Python.\n\n")
        f.write("A. UJI COBA PADA 1 LAPTOP YANG SAMA:\n")
        f.write("1. Dobel-klik 'JALANKAN_RELAY_SERVER.bat'.\n")
        f.write("2. Dobel-klik 'JALANKAN_ALICE.bat'.\n")
        f.write("3. Dobel-klik 'JALANKAN_BOB.bat'.\n")
        f.write("4. Keduanya dapat langsung saling berkirim pesan terenkripsi!\n\n")
        f.write("B. UJI COBA ANTAR-LAPTOP DI WI-FI / LAN YANG SAMA:\n")
        f.write("1. Pada Laptop Host (Penyedia Server):\n")
        f.write("   - Dobel-klik 'JALANKAN_RELAY_SERVER.bat'.\n")
        f.write("   - Catat alamat IP LAN Host yang tampil (contoh: 192.168.1.10).\n")
        f.write("   - Dobel-klik 'JALANKAN_ALICE.bat'.\n\n")
        f.write("2. Pada Laptop Tamu (Klien Bob):\n")
        f.write("   - Salin folder 'CryptoChat_Portable' ini ke flashdisk/laptop tamu.\n")
        f.write("   - Buka folder 'App', lalu dobel-klik 'CryptoChat.exe'.\n")
        f.write("   - Masukkan User ID: bob.\n")
        f.write("   - Pada kolom 'IP Host / Komputer Relay', ketikkan IP Laptop Host (misal: 192.168.1.10).\n")
        f.write("   - Klik 'Buka Kunci & Hubungkan'.\n")
        f.write("   - Selamat! Anda sekarang terhubung secara real-time via LAN!\n\n")

    print(f"[+] Bundel portabel berhasil dibuat di:\n    {portable_dir}")


def main():
    clean_previous_builds()
    ok_client = build_cryptochat()
    ok_relay = build_relay_server()

    if ok_client and ok_relay:
        create_portable_bundle()
        print("\n" + "=" * 60)
        print("[OK] SELURUH PROSES BUILD SUKSES 100%!")
        print(f"[*] Berkas eksekusi siap di: {os.path.join(DIST_DIR, 'CryptoChat_Portable')}")
        print("=" * 60)
    else:
        print("\n[!] Terjadi kesalahan pada proses kompilasi.")


if __name__ == "__main__":
    main()
