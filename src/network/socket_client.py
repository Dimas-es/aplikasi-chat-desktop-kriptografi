"""
Komunikasi Soket Peer-to-Peer Langsung Antar-Klien (P2P Socket).

Digunakan pada mode direct-socket (tanpa relay server) pada jaringan lokal (LAN).
"""

import json
import socket
import threading
from typing import Optional, Callable

from src.messaging.packet import MessagePacket


class P2PListener:
    """Listener TCP peer-to-peer yang berjalan di latar belakang klien."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9001,
        on_packet_received: Optional[Callable[[MessagePacket], None]] = None,
    ):
        self.host = host
        self.port = port
        self.on_packet_received = on_packet_received

        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    def start(self) -> bool:
        """Memulai listener socket di port yang ditentukan."""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(5)
            self._is_running = True

            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            print(f"[P2P] Listener aktif pada {self.host}:{self.port}")
            return True
        except Exception as exc:
            print(f"[!] Gagal memulai P2P listener di {self.host}:{self.port}: {exc}")
            return False

    def stop(self) -> None:
        """Menghentikan listener socket."""
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

    def _accept_loop(self) -> None:
        while self._is_running and self._server_sock:
            try:
                client_sock, _ = self._server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        with client_sock:
            buffer = ""
            try:
                while self._is_running:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk.decode("utf-8")

                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue

                        packet = MessagePacket.from_json(line)
                        if self.on_packet_received:
                            self.on_packet_received(packet)

                        # Kirim ACK
                        client_sock.sendall(b'{"status":"OK"}\n')
            except Exception as exc:
                print(f"[!] P2P Client error: {exc}")


def send_p2p_packet(host: str, port: int, packet: MessagePacket, timeout: float = 5.0) -> bool:
    """Mengirim paket langsung ke listener P2P klien tujuan."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            line = packet.to_json() + "\n"
            sock.sendall(line.encode("utf-8"))
            resp = sock.recv(1024)
            return b"OK" in resp
    except Exception as exc:
        print(f"[!] Gagal mengirim paket P2P ke {host}:{port}: {exc}")
        return False
