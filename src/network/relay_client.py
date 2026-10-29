"""
Klien Jaringan Penghubung ke Relay Server (RelayClient).

Menyediakan komunikasi asinkron berbasis socket TCP:
- Publikasi kunci publik ke relay (PUBLISH_KEY).
- Pengambilan kunci publik lawan bicara (GET_KEY).
- Pengiriman paket ciphertext real-time atau ke antrean (SEND).
- Pendengar background (Background Listener Thread) untuk memproses paket masuk (INCOMING_PACKET).
"""

import json
import socket
import threading
import queue
from typing import Optional, Callable, Dict, Any, List

from src.messaging.packet import MessagePacket


class RelayClient:
    """Klien TCP untuk berinteraksi dengan Relay Server."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        user_id: str = "alice",
        on_incoming_packet: Optional[Callable[[MessagePacket], None]] = None,
    ):
        self.host = host
        self.port = port
        self.user_id = user_id.strip().lower()
        self.on_incoming_packet = on_incoming_packet

        self.sock: Optional[socket.socket] = None
        self.is_connected = False
        self._listener_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Antrean untuk sinkronisasi respons permintaan (Request-Response matching)
        self._response_queue: queue.Queue = queue.Queue()
        self._send_lock = threading.Lock()

    def connect(self, timeout: float = 5.0) -> bool:
        """Membuka koneksi ke Relay Server dan mengidentifikasi user_id sesi."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(None)  # Blocking mode untuk background thread
            self.is_connected = True
            self._stop_event.clear()

            # Mulai thread pembaca data dari relay
            self._listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._listener_thread.start()

            # Kirim perintah IDENTIFY agar relay mengetahui socket ini milik user_id kita
            self._send_raw({"action": "IDENTIFY", "user_id": self.user_id})
            resp = self._wait_for_response(timeout=3.0)
            return resp is not None and resp.get("status") == "OK"

        except Exception as exc:
            print(f"[!] Gagal terhubung ke relay server di {self.host}:{self.port}: {exc}")
            self.disconnect()
            return False

    def disconnect(self) -> None:
        """Memutuskan koneksi soket dan mematikan listener thread."""
        self._stop_event.set()
        self.is_connected = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send_raw(self, payload: Dict[str, Any]) -> None:
        """Mengirim string JSON berakhiran newline (\n) ke relay."""
        if not self.sock or not self.is_connected:
            raise ConnectionError("Klien tidak terhubung ke relay server.")
        line = json.dumps(payload) + "\n"
        with self._send_lock:
            self.sock.sendall(line.encode("utf-8"))

    def _wait_for_response(self, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Menunggu balasan respons spesifik dari antrean penerimaan."""
        try:
            return self._response_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _listen_loop(self) -> None:
        """Thread background yang terus membaca stream data dari relay server."""
        buffer = ""
        while not self._stop_event.is_set() and self.sock:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8")

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        msg = json.loads(line)
                    except Exception:
                        continue

                    # Jika pesan merupakan paket terusan masuk real-time
                    if msg.get("action") == "INCOMING_PACKET" and "packet" in msg:
                        if self.on_incoming_packet:
                            try:
                                packet = MessagePacket.from_dict(msg["packet"])
                                self.on_incoming_packet(packet)
                            except Exception as exc:
                                print(f"[!] Gagal memproses paket masuk: {exc}")
                    else:
                        # Respons perintah biasa diserahkan ke response_queue
                        self._response_queue.put(msg)

            except Exception:
                break

        self.is_connected = False

    def publish_key(self, public_key_pem: str) -> bool:
        """Mengunggah public key pengguna ke direktori relay."""
        self._send_raw({
            "action": "PUBLISH_KEY",
            "user_id": self.user_id,
            "public_key": public_key_pem,
        })
        resp = self._wait_for_response()
        return resp is not None and resp.get("status") == "OK"

    def get_key(self, target_user_id: str) -> Optional[str]:
        """Mengambil public key PEM dari user lain dari relay."""
        self._send_raw({
            "action": "GET_KEY",
            "user_id": target_user_id.strip().lower(),
        })
        resp = self._wait_for_response()
        if resp and resp.get("status") == "OK":
            return resp.get("public_key")
        return None

    def list_users(self) -> List[str]:
        """Mendaftar pengguna yang terdaftar di direktori relay."""
        self._send_raw({"action": "LIST_USERS"})
        resp = self._wait_for_response()
        if resp and resp.get("status") == "OK":
            return resp.get("users", [])
        return []

    def send_packet(self, packet: MessagePacket) -> bool:
        """Mengirimkan paket ciphertext ke relay untuk diteruskan ke penerima."""
        self._send_raw({
            "action": "SEND",
            "packet": packet.to_dict(),
        })
        resp = self._wait_for_response()
        return resp is not None and resp.get("status") == "OK"

    def fetch_pending(self) -> List[MessagePacket]:
        """Mengambil pesan tertunda secara manual."""
        self._send_raw({
            "action": "FETCH",
            "user_id": self.user_id,
        })
        resp = self._wait_for_response()
        packets = []
        if resp and resp.get("status") == "OK":
            for raw_p in resp.get("messages", []):
                try:
                    packets.append(MessagePacket.from_dict(raw_p))
                except Exception:
                    pass
        return packets
