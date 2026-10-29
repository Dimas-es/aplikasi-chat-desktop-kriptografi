"""
Unit Test untuk Serialisasi, Deserialisasi, dan Validasi Skema JSON Paket Pesan v1.
"""

import json
import base64
import pytest
from src.messaging.packet import MessagePacket, PacketValidationError


class TestMessagePacketSchema:
    @pytest.fixture
    def valid_packet_data(self):
        return {
            "sender": "alice",
            "receiver": "bob",
            "counter": 5,
            "wrapped_key": b"K" * 256,  # 256 byte RSA-2048 wrapped key
            "nonce": b"N" * 12,        # 12 byte nonce GCM
            "ciphertext": b"encrypted_payload_data",
            "tag": b"T" * 16,          # 16 byte authentication tag
            "version": 1,
        }

    def test_create_valid_packet(self, valid_packet_data):
        packet = MessagePacket(**valid_packet_data)
        assert packet.sender == "alice"
        assert packet.receiver == "bob"
        assert packet.counter == 5
        assert len(packet.wrapped_key) == 256
        assert len(packet.nonce) == 12
        assert len(packet.tag) == 16
        assert packet.combined_ciphertext == b"encrypted_payload_data" + (b"T" * 16)

    def test_json_roundtrip_serialization(self, valid_packet_data):
        packet = MessagePacket(**valid_packet_data)
        json_str = packet.to_json()

        # Pastikan merupakan JSON valid
        parsed_dict = json.loads(json_str)
        assert parsed_dict["version"] == 1
        assert parsed_dict["sender"] == "alice"
        assert parsed_dict["receiver"] == "bob"
        assert parsed_dict["counter"] == 5

        # Reconstruct dari JSON
        restored = MessagePacket.from_json(json_str)
        assert restored.sender == packet.sender
        assert restored.receiver == packet.receiver
        assert restored.counter == packet.counter
        assert restored.wrapped_key == packet.wrapped_key
        assert restored.nonce == packet.nonce
        assert restored.ciphertext == packet.ciphertext
        assert restored.tag == packet.tag

    def test_invalid_version_rejection(self, valid_packet_data):
        valid_packet_data["version"] = 99
        with pytest.raises(PacketValidationError, match="Versi protokol tidak didukung"):
            MessagePacket(**valid_packet_data)

    def test_invalid_counter_rejection(self, valid_packet_data):
        valid_packet_data["counter"] = 0
        with pytest.raises(PacketValidationError, match="Field 'counter' harus bernilai positif"):
            MessagePacket(**valid_packet_data)

    def test_invalid_wrapped_key_length(self, valid_packet_data):
        valid_packet_data["wrapped_key"] = b"short_key"
        with pytest.raises(PacketValidationError, match="Panjang wrapped_key harus 256 byte"):
            MessagePacket(**valid_packet_data)

    def test_invalid_nonce_length(self, valid_packet_data):
        valid_packet_data["nonce"] = b"short_nonce"
        with pytest.raises(PacketValidationError, match="Panjang nonce GCM harus 12 byte"):
            MessagePacket(**valid_packet_data)

    def test_invalid_tag_length(self, valid_packet_data):
        valid_packet_data["tag"] = b"short_tag"
        with pytest.raises(PacketValidationError, match="Panjang authentication tag harus 16 byte"):
            MessagePacket(**valid_packet_data)

    def test_from_dict_missing_fields(self):
        incomplete_dict = {
            "version": 1,
            "sender": "alice",
            "receiver": "bob",
            # kurang counter, wrapped_key, nonce, ciphertext
        }
        with pytest.raises(PacketValidationError, match="Field paket tidak lengkap"):
            MessagePacket.from_dict(incomplete_dict)

    def test_from_json_corrupted_syntax(self):
        corrupted_json = '{"version": 1, "sender": "alice", ... invalid json ...'
        with pytest.raises(PacketValidationError, match="Format JSON tidak valid"):
            MessagePacket.from_json(corrupted_json)
