"""
Pengendali Utama Logika Aplikasi Chat (ChatController).

Mengorkestrasi seluruh alur:
- Manajemen sesi pengguna dan pembukaan private key terenkripsi.
- Buku kontak dan verifikasi fingerprint out-of-band.
- Pengiriman pesan: Enkripsi AES-256-GCM + RSA-OAEP Wrap + Serialisasi Paket v1.
- Penerimaan pesan: Verifikasi Anti-Replay -> RSA-OAEP Unwrap -> Verifikasi Tag AES-GCM -> Commit Counter.
- Pencatatan seluruh tahapan secara transparan ke VisualizerController.
"""

from typing import Optional, Tuple, List, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa

from src.storage.db import DatabaseManager
from src.storage.keystore import KeyStoreManager
from src.storage.contact_store import ContactStore
from src.storage.counter_store import CounterStore
from src.messaging.packet import MessagePacket
from src.messaging.aad import build_canonical_aad
from src.messaging.status import MessageStatus
from src.crypto.aes_gcm import generate_aes_key, generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm, AuthenticationError
from src.crypto.rsa_oaep import generate_rsa_keypair, wrap_key, unwrap_key, public_key_to_pem, pem_to_public_key, KeyUnwrapError
from src.crypto.rsa_pss import sign_data, verify_signature
from src.crypto.fingerprint import calculate_fingerprint
from client.controllers.visualizer_controller import VisualizerController, PipelineTrace


class ChatController:
    """Pengendali orkestrator antarmuka chat desktop dan pipeline kriptografi."""

    def __init__(self, db_path: str = "data/client.db"):
        self.db = DatabaseManager(db_path=db_path)
        self.keystore = KeyStoreManager(self.db)
        self.contact_store = ContactStore(self.db)
        self.counter_store = CounterStore(self.db)
        self.visualizer = VisualizerController()

        # State sesi aktif pengguna
        self.user_id: Optional[str] = None
        self.display_name: Optional[str] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.fingerprint: Optional[str] = None

    @property
    def is_logged_in(self) -> bool:
        """Memeriksa apakah sesi pengguna aktif dan private key telah terbuka."""
        return self.private_key is not None and self.user_id is not None

    def close(self) -> None:
        """Menutup koneksi database dan membersihkan resource."""
        if hasattr(self, "db") and self.db:
            self.db.close()

    def register_identity(self, user_id: str, display_name: str, passphrase: str) -> str:
        """
        Membangkitkan pasangan kunci RSA-2048 baru dan menyimpannya terenkripsi ke keystore.
        """
        priv, pub = generate_rsa_keypair(key_size=2048)
        self.keystore.save_identity(user_id, display_name, priv, passphrase)
        
        # Set sesi aktif
        self.user_id = user_id
        self.display_name = display_name
        self.private_key = priv
        self.public_key = pub
        self.fingerprint = calculate_fingerprint(pub)
        return self.fingerprint

    def login_identity(self, user_id: str, passphrase: str) -> None:
        """
        Membuka kunci identitas lokal menggunakan passphrase.
        """
        display_name, pub, priv = self.keystore.load_identity(user_id, passphrase)
        self.user_id = user_id
        self.display_name = display_name
        self.public_key = pub
        self.private_key = priv
        self.fingerprint = calculate_fingerprint(pub)

    def logout(self) -> None:
        """Menghapus kunci privat dari memori aktif."""
        self.user_id = None
        self.display_name = None
        self.public_key = None
        self.private_key = None
        self.fingerprint = None

    def get_public_key_pem(self) -> str:
        """Mengambil public key pengguna saat ini dalam format string PEM."""
        if not self.public_key:
            raise RuntimeError("Pengguna belum login atau belum memiliki kunci.")
        return public_key_to_pem(self.public_key).decode("utf-8")

    def add_contact(self, contact_id: str, display_name: str, public_key_pem: str, verified: bool = False) -> str:
        """Menambahkan kontak baru ke buku kontak dan mengembalikan fingerprint-nya."""
        return self.contact_store.save_contact(contact_id, display_name, public_key_pem, verified=verified)

    def list_contacts(self) -> List[Dict[str, Any]]:
        """Mendaftar semua kontak yang tersimpan."""
        return self.contact_store.list_contacts()

    def set_contact_verified(self, contact_id: str, verified: bool = True) -> None:
        """Menyetel status verifikasi fingerprint out-of-band untuk kontak."""
        self.contact_store.set_verified(contact_id, verified=verified)

    def send_message(self, receiver_id: str, message_text: str) -> Tuple[MessagePacket, PipelineTrace]:
        """
        Mengenkripsi pesan teks menggunakan skema hybrid dan merekam proses ke visualizer.

        Returns:
            Tuple (packet, trace):
            - packet: Objek MessagePacket JSON v1 siap kirim.
            - trace: Rekam jejak seluruh tahapan heksadesimal untuk visualizer.
        """
        if not self.is_logged_in or not self.user_id:
            raise RuntimeError("Anda harus login dan membuka kunci terlebih dahulu sebelum mengirim pesan.")

        # 1. Ambil public key penerima
        receiver_pub_key = self.contact_store.get_public_key(receiver_id)

        # 2. Ambil counter pengiriman berikutnya secara atomik
        counter = self.counter_store.get_next_sent_counter(receiver_id)

        # 3. Bangkitkan K_AES (256-bit) dan Nonce (96-bit) segar
        k_aes = generate_aes_key()
        nonce = generate_nonce()

        # 4. Susun AAD kanonikal: sender:receiver:counter
        plaintext_bytes = message_text.encode("utf-8")
        aad = build_canonical_aad(self.user_id, receiver_id, counter)

        # 5. Enkripsi pesan dengan AES-256-GCM
        ciphertext, tag = encrypt_aes_gcm(plaintext_bytes, k_aes, nonce, associated_data=aad)

        # 6. Bungkus K_AES dengan RSA-OAEP menggunakan Public Key Penerima
        wrapped_key = wrap_key(k_aes, receiver_pub_key)

        # 7. Susun paket JSON
        packet = MessagePacket(
            version=2,
            sender=self.user_id,
            receiver=receiver_id,
            counter=counter,
            wrapped_key=wrapped_key,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

        # 7b. Bubuhkan tanda tangan digital RSA-PSS menggunakan Private Key pengirim
        sig_payload = packet.compute_signature_payload()
        signature = sign_data(self.private_key, sig_payload)
        packet.signature = signature

        # 8. Rekam seluruh tahapan ke VisualizerController
        trace = self.visualizer.record_send_pipeline(
            sender=self.user_id,
            receiver=receiver_id,
            counter=counter,
            plaintext=plaintext_bytes,
            k_aes=k_aes,
            nonce=nonce,
            aad=aad,
            ciphertext=ciphertext,
            tag=tag,
            wrapped_key=wrapped_key,
            signature=signature,
            packet_json=packet.to_json(indent=2),
        )

        return packet, trace

    def receive_message(self, packet: MessagePacket) -> Tuple[MessageStatus, Optional[str], PipelineTrace]:
        """
        Memproses paket pesan masuk melalui tahapan verifikasi berjenjang:
        1. Anti-Replay check
        2. Verifikasi Tanda Tangan Digital Pengirim (RSA-PSS)
        3. RSA-OAEP Unwrap
        4. Rekonstruksi AAD & Verifikasi Tag AES-GCM
        5. Commit Counter & Ekstraksi Plaintext

        Returns:
            Tuple (status, plaintext_or_none, trace)
        """
        if not self.is_logged_in or not self.private_key:
            raise RuntimeError("Klien belum login atau private key belum tersedia di memori.")

        sender = packet.sender
        receiver = packet.receiver
        counter = packet.counter

        # Ambil counter tertinggi saat ini untuk audit trace
        current_highest = self.counter_store.get_highest_received_counter(sender)

        # Tahap 1: Pemeriksaan Anti-Replay
        can_accept = self.counter_store.can_accept_counter(sender, counter)
        if not can_accept:
            trace = self.visualizer.record_receive_pipeline(
                sender=sender,
                receiver=receiver,
                counter=counter,
                can_accept_counter=False,
                current_highest_counter=current_highest,
                wrapped_key=packet.wrapped_key,
                nonce=packet.nonce,
                ciphertext=packet.ciphertext,
                tag=packet.tag,
                aad=build_canonical_aad(sender, receiver, counter),
                signature=packet.signature,
            )
            return MessageStatus.REPLAY_REJECTED, None, trace

        # Tahap 2: Verifikasi Tanda Tangan Digital RSA-PSS jika ada signature
        sig_valid = True
        sig_error = None
        if packet.signature:
            sender_contact = self.contact_store.get_contact(sender)
            if sender_contact:
                try:
                    sender_pub_key = pem_to_public_key(sender_contact["public_key_pem"].encode("utf-8"))
                    sig_payload = packet.compute_signature_payload()
                    sig_valid = verify_signature(sender_pub_key, sig_payload, packet.signature)
                    if not sig_valid:
                        sig_error = "Tanda tangan digital RSA-PSS tidak cocok dengan kunci publik pengirim!"
                except Exception as exc:
                    sig_valid = False
                    sig_error = f"Galat verifikasi tanda tangan: {exc}"
            else:
                sig_valid = False
                sig_error = f"Kontak pengirim '{sender}' belum terdaftar di buku kontak lokal."

        if not sig_valid:
            trace = self.visualizer.record_receive_pipeline(
                sender=sender,
                receiver=receiver,
                counter=counter,
                can_accept_counter=True,
                current_highest_counter=current_highest,
                wrapped_key=packet.wrapped_key,
                nonce=packet.nonce,
                ciphertext=packet.ciphertext,
                tag=packet.tag,
                aad=build_canonical_aad(sender, receiver, counter),
                signature=packet.signature,
                signature_valid=False,
                signature_error=sig_error,
            )
            return MessageStatus.SIGNATURE_FAILED, None, trace

        # Tahap 3: Buka Kunci K_AES dengan RSA-OAEP
        unwrapped_k_aes: Optional[bytes] = None
        unwrap_error: Optional[str] = None
        try:
            unwrapped_k_aes = unwrap_key(packet.wrapped_key, self.private_key)
        except KeyUnwrapError as exc:
            unwrap_error = str(exc)
            trace = self.visualizer.record_receive_pipeline(
                sender=sender,
                receiver=receiver,
                counter=counter,
                can_accept_counter=True,
                current_highest_counter=current_highest,
                wrapped_key=packet.wrapped_key,
                nonce=packet.nonce,
                ciphertext=packet.ciphertext,
                tag=packet.tag,
                aad=build_canonical_aad(sender, receiver, counter),
                signature=packet.signature,
                signature_valid=True,
                unwrap_error=unwrap_error,
            )
            return MessageStatus.UNWRAP_FAILED, None, trace

        # Tahap 4: Rekonstruksi AAD dan Verifikasi Tag AES-GCM
        aad = build_canonical_aad(sender, receiver, counter)
        plaintext_bytes: Optional[bytes] = None
        verify_error: Optional[str] = None
        try:
            plaintext_bytes = decrypt_aes_gcm(
                packet.ciphertext,
                packet.tag,
                unwrapped_k_aes,
                packet.nonce,
                associated_data=aad,
            )
        except AuthenticationError as exc:
            verify_error = str(exc)
            # PERHATIAN: Counter TIDAK dinaikkan saat verifikasi tag gagal!
            trace = self.visualizer.record_receive_pipeline(
                sender=sender,
                receiver=receiver,
                counter=counter,
                can_accept_counter=True,
                current_highest_counter=current_highest,
                wrapped_key=packet.wrapped_key,
                nonce=packet.nonce,
                ciphertext=packet.ciphertext,
                tag=packet.tag,
                aad=aad,
                signature=packet.signature,
                signature_valid=True,
                unwrapped_key=unwrapped_k_aes,
                verification_success=False,
                verification_error=verify_error,
            )
            return MessageStatus.VERIFICATION_FAILED, None, trace

        # Tahap 5: Seluruh Kriptografi Sukses -> COMMIT COUNTER SECARA PERSISTEN!
        self.counter_store.commit_received_counter(sender, counter)
        
        trace = self.visualizer.record_receive_pipeline(
            sender=sender,
            receiver=receiver,
            counter=counter,
            can_accept_counter=True,
            current_highest_counter=current_highest,
            wrapped_key=packet.wrapped_key,
            nonce=packet.nonce,
            ciphertext=packet.ciphertext,
            tag=packet.tag,
            aad=aad,
            signature=packet.signature,
            signature_valid=True,
            unwrapped_key=unwrapped_k_aes,
            verification_success=True,
            plaintext=plaintext_bytes,
        )

        plaintext_str = plaintext_bytes.decode("utf-8", errors="replace")
        return MessageStatus.VALID, plaintext_str, trace
