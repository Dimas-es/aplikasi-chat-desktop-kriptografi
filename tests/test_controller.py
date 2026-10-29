"""
Unit dan Integration Test untuk ChatController dan VisualizerController.
"""

import os
import tempfile
import pytest

from client.controllers.chat_controller import ChatController
from src.messaging.status import MessageStatus


@pytest.fixture
def temp_environment():
    """Menyiapkan 2 controller (Alice dan Bob) dengan database terisolasi."""
    temp_dir = tempfile.mkdtemp()
    db_alice = os.path.join(temp_dir, "alice.db")
    db_bob = os.path.join(temp_dir, "bob.db")

    alice = ChatController(db_path=db_alice)
    bob = ChatController(db_path=db_bob)

    alice.register_identity("alice", "Alice Crypto", "pass_alice_123")
    bob.register_identity("bob", "Bob Peneliti", "pass_bob_123")

    # Pertukaran public key
    alice.add_contact("bob", "Bob Peneliti", bob.get_public_key_pem(), verified=True)
    bob.add_contact("alice", "Alice Crypto", alice.get_public_key_pem(), verified=True)

    yield {"alice": alice, "bob": bob, "temp_dir": temp_dir}

    # Cleanup
    for path in (db_alice, db_bob):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


class TestChatControllerFlow:
    def test_send_and_receive_valid_message(self, temp_environment):
        alice = temp_environment["alice"]
        bob = temp_environment["bob"]

        pesan = "Halo Bob, ini pengujian end-to-end controller! 🚀🔐"
        packet, send_trace = alice.send_message("bob", pesan)

        assert packet.sender == "alice"
        assert packet.receiver == "bob"
        assert packet.counter == 1
        assert send_trace.final_status == "terkirim"
        assert len(send_trace.stages) == 7

        # Bob menerima paket
        status, decrypted_text, recv_trace = bob.receive_message(packet)
        assert status == MessageStatus.VALID
        assert decrypted_text == pesan
        assert recv_trace.final_status == "valid"
        assert len(recv_trace.stages) == 6

    def test_replay_attack_rejected_by_controller(self, temp_environment):
        alice = temp_environment["alice"]
        bob = temp_environment["bob"]

        packet, _ = alice.send_message("bob", "Pesan pertama (counter 1)")
        status1, text1, _ = bob.receive_message(packet)
        assert status1 == MessageStatus.VALID
        assert text1 == "Pesan pertama (counter 1)"

        # Penyerang mengirimkan kembali packet counter 1 yang sama
        status_replay, text_replay, trace_replay = bob.receive_message(packet)
        assert status_replay == MessageStatus.REPLAY_REJECTED
        assert text_replay is None
        assert trace_replay.final_status == "ditolak_replay"

    def test_tampered_ciphertext_rejected_by_signature(self, temp_environment):
        alice = temp_environment["alice"]
        bob = temp_environment["bob"]

        packet, _ = alice.send_message("bob", "Pesan asli rahasia")
        
        # Manipulasi 1 byte ciphertext pada paket bertanda tangan
        corrupted_ct = bytearray(packet.ciphertext)
        corrupted_ct[0] ^= 0x55
        packet.ciphertext = bytes(corrupted_ct)

        status, text, trace = bob.receive_message(packet)
        assert status == MessageStatus.SIGNATURE_FAILED
        assert text is None
        assert trace.final_status == "gagal_signature"

        # Pastikan counter Bob TIDAK naik akibat paket manipulasi
        assert bob.counter_store.get_highest_received_counter("alice") == 0

    def test_tampered_ciphertext_rejected_by_aes_gcm(self, temp_environment):
        alice = temp_environment["alice"]
        bob = temp_environment["bob"]

        packet, _ = alice.send_message("bob", "Pesan asli rahasia v1 legacy")
        # Hapus signature untuk menguji deteksi lapisan AES-GCM murni
        packet.signature = None
        
        corrupted_ct = bytearray(packet.ciphertext)
        corrupted_ct[0] ^= 0x55
        packet.ciphertext = bytes(corrupted_ct)

        status, text, trace = bob.receive_message(packet)
        assert status == MessageStatus.VERIFICATION_FAILED
        assert text is None
        assert trace.final_status == "gagal_verifikasi"

        assert bob.counter_store.get_highest_received_counter("alice") == 0

    def test_unauthorized_recipient_unwrap_failure(self, temp_environment):
        alice = temp_environment["alice"]
        temp_dir = temp_environment["temp_dir"]
        
        # Klien ketiga: Eve
        eve = ChatController(db_path=os.path.join(temp_dir, "eve.db"))
        eve.register_identity("eve", "Eve Eavesdropper", "pass_eve_123")
        # Eve menambahkan Alice sebagai kontak agar verifikasi signature Alice lolos
        eve.add_contact("alice", "Alice", alice.get_public_key_pem())

        # Alice kirim pesan ke Bob (wrapped_key ditujukan untuk Bob)
        packet, _ = alice.send_message("bob", "Hanya untuk mata Bob")

        # Eve menyadap dan mencoba proses paket yang ditujukan ke Bob
        status, text, trace = eve.receive_message(packet)
        assert status == MessageStatus.UNWRAP_FAILED
        assert text is None
        assert trace.final_status == "gagal_unwrap"
