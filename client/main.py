"""
Entrypoint Aplikasi Chat Desktop Kriptografi.

Penggunaan:
    python -m client.main --user alice
    python -m client.main --user bob
"""

import sys
import os
import argparse
from client.app import CryptoChatApp


def get_base_dir() -> str:
    """Mengembalikan direktori permanen tempat file .exe atau skrip python berada."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def main():
    parser = argparse.ArgumentParser(
        description="Aplikasi Chat Desktop Simulasi Enkripsi Hybrid (AES-GCM & RSA-OAEP SHA-256)"
    )
    parser.add_argument(
        "--user",
        "-u",
        type=str,
        default="alice",
        help="Nama akun lokal (contoh: alice, bob, eve). Default: alice",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path custom berkas database SQLite lokal. Default: data/<user>.db",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Nomor port lokal (opsional untuk listener socket jaringan)",
    )
    parser.add_argument(
        "--relay-host",
        type=str,
        default="127.0.0.1",
        help="Alamat IP Relay Server LAN (contoh: 192.168.1.10). Default: 127.0.0.1",
    )
    parser.add_argument(
        "--relay-port",
        type=int,
        default=8000,
        help="Nomor port Relay Server (default: 8000)",
    )

    args = parser.parse_args()

    db_path = args.db
    if not db_path:
        db_path = os.path.join(get_base_dir(), "data", f"{args.user.lower()}.db")

    print(f"[*] Memulai aplikasi chat untuk pengguna: {args.user.upper()}...")
    print(f"[*] Menargetkan Relay Server di {args.relay_host}:{args.relay_port}...")
    print(f"[*] Menggunakan basis data: {db_path}")
    app = CryptoChatApp(
        user_id=args.user.lower(),
        db_path=db_path,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
    )
    app.run()


if __name__ == "__main__":
    main()
