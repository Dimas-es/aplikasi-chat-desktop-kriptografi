"""
Unit dan Integration Test untuk Lapisan Jaringan (Relay Server, Router, RelayClient, dan P2P Socket).
"""

import time
import socket
import pytest
import threading

from relay.router import RelayRouter
from relay.server import RelayServer, RelayTCPHandler
from src.network.relay_client import RelayClient
from src.network.socket_client import P2PListener, send_p2p_packet
from src.messaging.packet import MessagePacket


def get_free_port() -> int:
    """Mendapatkan port lokal bebas yang tersedia."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def relay_server():
    """Fixture untuk menjalankan RelayServer di port bebas dalam background thread."""
    port = get_free_port()
    server = RelayServer(("127.0.0.1", port), RelayTCPHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.1)  # Beri waktu socket bind

    yield {"host": "127.0.0.1", "port": port, "server": server}

    server.shutdown()
    server.server_close()


class TestRelayRouterLogic:
    def test_publish_and_get_key(self):
        router = RelayRouter()
        # Publish
        res_pub = router.handle_request('{"action": "PUBLISH_KEY", "user_id": "alice", "public_key": "PEM_ALICE"}')
        assert res_pub["status"] == "OK"

        # Get
        res_get = router.handle_request('{"action": "GET_KEY", "user_id": "alice"}')
        assert res_get["status"] == "OK"
        assert res_get["public_key"] == "PEM_ALICE"

        # List
        res_list = router.handle_request('{"action": "LIST_USERS"}')
        assert "alice" in res_list["users"]

    def test_queue_and_fetch_offline_packet(self):
        router = RelayRouter()
        packet_dict = {
            "version": 1,
            "sender": "alice",
            "receiver": "bob",
            "counter": 1,
            "wrapped_key": "KEY",
            "nonce": "NONCE",
            "ciphertext": "CT",
        }

        # Kirim pesan ke Bob saat Bob offline
        res_send = router.handle_request(f'{{"action": "SEND", "packet": {router.handle_request.__globals__["json"].dumps(packet_dict)}}}')
        assert res_send["status"] == "OK"
        assert res_send["queued"] is True

        # Bob melakukan FETCH
        res_fetch = router.handle_request('{"action": "FETCH", "user_id": "bob"}')
        assert res_fetch["status"] == "OK"
        assert res_fetch["count"] == 1
        assert res_fetch["messages"][0]["sender"] == "alice"


class TestRelayClientIntegration:
    @pytest.fixture
    def dummy_packet(self):
        return MessagePacket(
            version=1,
            sender="alice",
            receiver="bob",
            counter=1,
            wrapped_key=b"K" * 256,
            nonce=b"N" * 12,
            ciphertext=b"encrypted_data",
            tag=b"T" * 16,
        )

    def test_relay_realtime_end_to_end(self, relay_server, dummy_packet):
        host = relay_server["host"]
        port = relay_server["port"]

        received_packets = []

        def on_bob_receive(packet: MessagePacket):
            received_packets.append(packet)

        # Inisialisasi klien Alice dan Bob
        client_alice = RelayClient(host=host, port=port, user_id="alice")
        client_bob = RelayClient(host=host, port=port, user_id="bob", on_incoming_packet=on_bob_receive)

        try:
            assert client_alice.connect() is True
            assert client_bob.connect() is True

            # Alice publikasikan kunci
            assert client_alice.publish_key("PEM_ALICE_PUBLIC") is True

            # Bob mengambil kunci Alice
            alice_key = client_bob.get_key("alice")
            assert alice_key == "PEM_ALICE_PUBLIC"

            # Alice mengirim paket terenkripsi ke Bob
            success = client_alice.send_packet(dummy_packet)
            assert success is True

            # Tunggu real-time push ke Bob
            time.sleep(0.3)
            assert len(received_packets) == 1
            assert received_packets[0].sender == "alice"
            assert received_packets[0].counter == 1
            assert received_packets[0].combined_ciphertext == dummy_packet.combined_ciphertext

        finally:
            client_alice.disconnect()
            client_bob.disconnect()


class TestDirectP2PSocket:
    def test_p2p_listener_and_send(self):
        port = get_free_port()
        received = []

        def on_p2p_receive(packet: MessagePacket):
            received.append(packet)

        listener = P2PListener(host="127.0.0.1", port=port, on_packet_received=on_p2p_receive)
        try:
            assert listener.start() is True
            time.sleep(0.1)

            packet = MessagePacket(
                version=1,
                sender="alice",
                receiver="bob",
                counter=7,
                wrapped_key=b"W" * 256,
                nonce=b"N" * 12,
                ciphertext=b"p2p_direct_payload",
                tag=b"T" * 16,
            )

            # Kirim langsung P2P
            sent = send_p2p_packet("127.0.0.1", port, packet)
            assert sent is True

            time.sleep(0.2)
            assert len(received) == 1
            assert received[0].sender == "alice"
            assert received[0].counter == 7
            assert received[0].ciphertext == b"p2p_direct_payload"

        finally:
            listener.stop()
