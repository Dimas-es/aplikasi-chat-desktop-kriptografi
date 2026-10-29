"""
Unit Test untuk Modul Persistensi Lokal (SQLite Database, KeyStore, ContactStore, CounterStore).
"""

import os
import tempfile
import pytest

from src.storage.db import DatabaseManager
from src.storage.keystore import KeyStoreManager
from src.storage.contact_store import ContactStore
from src.storage.counter_store import CounterStore
from src.crypto.rsa_oaep import generate_rsa_keypair, public_key_to_pem
from src.crypto.kdf import InvalidPassphraseError


@pytest.fixture
def temp_db():
    """Membuat database sementara dalam direktori temp terisolasi."""
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_client.db")
    db_manager = DatabaseManager(db_path=db_file)
    yield db_manager
    # Cleanup file temp
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass


class TestKeyStore:
    def test_save_and_load_identity(self, temp_db):
        keystore = KeyStoreManager(temp_db)
        priv, pub = generate_rsa_keypair(key_size=2048)
        passphrase = "super_secure_passphrase_2026!"

        assert keystore.has_identity("alice") is False
        keystore.save_identity("alice", "Alice Crypto", priv, passphrase)
        assert keystore.has_identity("alice") is True

        # Ambil public info tanpa passphrase
        public_info = keystore.get_public_identity("alice")
        assert public_info is not None
        assert public_info["user_id"] == "alice"
        assert public_info["display_name"] == "Alice Crypto"
        assert len(public_info["fingerprint"]) == 95  # 32 pasang hex + 31 titik dua = 95 karakter

        # Load private key dengan passphrase benar
        name, loaded_pub, loaded_priv = keystore.load_identity("alice", passphrase)
        assert name == "Alice Crypto"
        assert loaded_pub.key_size == 2048
        assert loaded_priv.key_size == 2048

    def test_load_identity_wrong_passphrase(self, temp_db):
        keystore = KeyStoreManager(temp_db)
        priv, _ = generate_rsa_keypair(key_size=2048)
        keystore.save_identity("alice", "Alice Crypto", priv, "correct_passphrase")

        with pytest.raises(InvalidPassphraseError):
            keystore.load_identity("alice", "wrong_passphrase")


class TestContactStore:
    def test_save_and_manage_contacts(self, temp_db):
        contact_store = ContactStore(temp_db)
        _, bob_pub = generate_rsa_keypair(key_size=2048)
        bob_pem = public_key_to_pem(bob_pub).decode("utf-8")

        # Simpan kontak
        fp = contact_store.save_contact("bob", "Bob Peneliti", bob_pem, verified=False)
        assert len(fp) == 95

        # Ambil kontak
        contact = contact_store.get_contact("bob")
        assert contact is not None
        assert contact["contact_id"] == "bob"
        assert contact["display_name"] == "Bob Peneliti"
        assert contact["verified"] is False
        assert contact["fingerprint"] == fp

        # Ambil RSA public key objek
        loaded_pub = contact_store.get_public_key("bob")
        assert loaded_pub.key_size == 2048

        # Update verified status
        contact_store.set_verified("bob", verified=True)
        assert contact_store.get_contact("bob")["verified"] is True

        # List contacts
        contacts = contact_store.list_contacts()
        assert len(contacts) == 1
        assert contacts[0]["contact_id"] == "bob"

        # Delete contact
        contact_store.delete_contact("bob")
        assert contact_store.get_contact("bob") is None


class TestCounterStoreAntiReplay:
    def test_send_counter_monotonicity(self, temp_db):
        counter_store = CounterStore(temp_db)

        # Counter pengiriman harus naik monotonik (1, 2, 3...)
        c1 = counter_store.get_next_sent_counter("bob")
        c2 = counter_store.get_next_sent_counter("bob")
        c3 = counter_store.get_next_sent_counter("bob")

        assert c1 == 1
        assert c2 == 2
        assert c3 == 3

    def test_anti_replay_verification_and_commit(self, temp_db):
        counter_store = CounterStore(temp_db)

        # Awal: highest_received_counter = 0
        assert counter_store.get_highest_received_counter("alice") == 0

        # Paket 1 masuk: counter 1 > 0 -> harus diterima
        assert counter_store.can_accept_counter("alice", 1) is True

        # Verifikasi sukses -> commit counter 1
        counter_store.commit_received_counter("alice", 1)
        assert counter_store.get_highest_received_counter("alice") == 1

        # SERANGAN REPLAY: Paket 1 diinjeksi ulang -> harus ditolak!
        assert counter_store.can_accept_counter("alice", 1) is False
        assert counter_store.can_accept_counter("alice", 0) is False

        # Paket 2 masuk: counter 2 > 1 -> harus diterima
        assert counter_store.can_accept_counter("alice", 2) is True
        counter_store.commit_received_counter("alice", 2)
        assert counter_store.get_highest_received_counter("alice") == 2

        # Paket kadaluarsa (misal counter 1 lagi atau counter 2) tetap ditolak
        assert counter_store.can_accept_counter("alice", 1) is False
        assert counter_store.can_accept_counter("alice", 2) is False

    def test_failed_verification_does_not_commit_counter(self, temp_db):
        counter_store = CounterStore(temp_db)

        # Awal: highest = 0
        assert counter_store.get_highest_received_counter("alice") == 0

        # Penyerang mengirim fake packet dengan counter raksasa (misal 999999)
        # Sistem mengecek can_accept_counter -> bernilai True karena 999999 > 0
        assert counter_store.can_accept_counter("alice", 999999) is True

        # KARENA DEKRIPSI GAGAL (Tag Mismatch), KITA TIDAK MEMANGGIL commit_received_counter!
        # Counter di disk harus tetap 0
        assert counter_store.get_highest_received_counter("alice") == 0

        # Paket asli nomor 1 yang sah berikutnya tetap bisa diterima!
        assert counter_store.can_accept_counter("alice", 1) is True
