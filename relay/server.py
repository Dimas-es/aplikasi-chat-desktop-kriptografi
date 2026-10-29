"""
Server Perantara Zero-Knowledge (Relay Server).

Menyediakan transportasi paket ciphertext dan direktori public key sederhana.
Mendukung multi-client threading dengan protokol line-delimited JSON.

Penggunaan:
    python -m relay.server --host 127.0.0.1 --port 8000
"""

import sys
import json
import socket
import socketserver
import argparse
import threading
from typing import Optional

from relay.router import RelayRouter


class RelayTCPHandler(socketserver.BaseRequestHandler):
    """Handler koneksi soket per klien."""

    def handle(self):
        client_address = self.client_address
        print(f"[+] Klien terhubung dari {client_address}")
        server: RelayServer = self.server  # type: ignore
        router = server.router

        identified_user: Optional[str] = None

        def send_to_client(data_str: str):
            try:
                self.request.sendall(data_str.encode("utf-8"))
            except Exception as exc:
                print(f"[!] Gagal mengirim ke {identified_user or client_address}: {exc}")

        # Buffer pembacaan per baris (line-delimited JSON)
        buffer = ""
        try:
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8")

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    # Periksa jika ada aksi identifikasi
                    try:
                        parsed = json.loads(line)
                        if parsed.get("action") == "IDENTIFY":
                            identified_user = parsed.get("user_id", "").strip().lower()
                    except Exception:
                        pass

                    response = router.handle_request(line, client_sender_fn=send_to_client)
                    response_str = json.dumps(response) + "\n"
                    send_to_client(response_str)

        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if identified_user:
                router.unregister_client_session(identified_user)
                print(f"[-] Sesi pengguna '{identified_user}' terputus.")
            print(f"[-] Koneksi ditutup dari {client_address}")


class RelayServer(socketserver.ThreadingTCPServer):
    """Server TCP multi-threaded dengan integrasi router relay."""
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.router = RelayRouter()


def get_local_ip() -> str:
    """Mendeteksi IP LAN aktif mesin ini untuk koneksi antar-perangkat."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_relay_server(host: str = "0.0.0.0", port: int = 8000):
    """Menjalankan server relay."""
    server_address = (host, port)
    local_lan_ip = get_local_ip()
    print("=" * 60)
    print(f"[*] TRUSTGIVE ZERO-KNOWLEDGE RELAY SERVER")
    print(f"[*] Berjalan pada antarmuka: {host}:{port}")
    if host in ("0.0.0.0", ""):
        print(f"[*] Alamat IP LAN Host ini: {local_lan_ip}:{port}")
        print(f"[*] Perangkat lain di LAN dapat terhubung ke: {local_lan_ip}:{port}")
    print(f"[*] Meneruskan ciphertext JSON v1 dan direktori public key.")
    print("=" * 60)

    server = RelayServer(server_address, RelayTCPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Mematikan relay server...")
    finally:
        server.shutdown()
        server.server_close()
        print("[*] Server berhasil dimatikan.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrustGive Zero-Knowledge Relay Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port nomor (default: 8000)")
    args = parser.parse_args()

    run_relay_server(host=args.host, port=args.port)
