"""
Implementasi Struktur, Serialisasi, dan Validasi Format Paket Pesan v1.

Sesuai spesifikasi dokumen 05 - PERANCANGAN SISTEM:
```json
{
  "version": 1,
  "sender": "alice",
  "receiver": "bob",
  "counter": 7,
  "wrapped_key": "<base64, 256 byte untuk RSA-2048>",
  "nonce": "<base64, 12 byte>",
  "ciphertext": "<base64, termasuk tag 16 byte di akhir>"
}
```
"""

import json
import base64
from dataclasses import dataclass
from typing import Optional, Dict, Any


class PacketValidationError(Exception):
    """Dilempar ketika struktur paket JSON atau panjang field biner tidak valid."""
    pass


@dataclass
class MessagePacket:
    """Representasi objek paket pesan terenkripsi hybrid."""
    sender: str
    receiver: str
    counter: int
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    version: int = 1
    signature: Optional[bytes] = None

    def __post_init__(self):
        self.validate()

    def validate(self) -> None:
        """Memvalidasi integritas field dan kepatuhan terhadap spesifikasi protokol."""
        if self.version not in (1, 2):
            raise PacketValidationError(f"Versi protokol tidak didukung: {self.version} (hanya versi 1 atau 2).")
        if not self.sender or not self.sender.strip():
            raise PacketValidationError("Field 'sender' tidak boleh kosong.")
        if not self.receiver or not self.receiver.strip():
            raise PacketValidationError("Field 'receiver' tidak boleh kosong.")
        if self.counter <= 0:
            raise PacketValidationError(f"Field 'counter' harus bernilai positif (> 0), diterima: {self.counter}.")
        if len(self.wrapped_key) != 256:
            raise PacketValidationError(
                f"Panjang wrapped_key harus 256 byte (RSA-2048), diterima: {len(self.wrapped_key)} byte."
            )
        if len(self.nonce) != 12:
            raise PacketValidationError(
                f"Panjang nonce GCM harus 12 byte (96-bit), diterima: {len(self.nonce)} byte."
            )
        if len(self.tag) != 16:
            raise PacketValidationError(
                f"Panjang authentication tag harus 16 byte (128-bit), diterima: {len(self.tag)} byte."
            )
        if self.signature is not None and len(self.signature) != 256:
            raise PacketValidationError(
                f"Panjang signature harus 256 byte (RSA-2048-PSS), diterima: {len(self.signature)} byte."
            )

    @property
    def combined_ciphertext(self) -> bytes:
        """Mengembalikan data ciphertext yang digabungkan dengan tag 16-byte di akhir."""
        return self.ciphertext + self.tag

    def compute_signature_payload(self) -> bytes:
        """Menghitung byte payload kanonikal yang diikat oleh tanda tangan RSA-PSS."""
        parts = [
            str(self.version),
            self.sender.lower().strip(),
            self.receiver.lower().strip(),
            str(self.counter),
            self.wrapped_key.hex(),
            self.nonce.hex(),
            self.ciphertext.hex(),
            self.tag.hex(),
        ]
        return ":".join(parts).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        """Mengubah objek paket ke dictionary berformat string Base64 siap serialisasi JSON."""
        d = {
            "version": self.version,
            "sender": self.sender,
            "receiver": self.receiver,
            "counter": self.counter,
            "wrapped_key": base64.b64encode(self.wrapped_key).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.combined_ciphertext).decode("ascii"),
        }
        if self.signature:
            d["signature"] = base64.b64encode(self.signature).decode("ascii")
        return d

    def to_json(self, indent: Optional[int] = None) -> str:
        """Melakukan serialisasi objek paket ke string JSON v1/v2."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MessagePacket":
        """Membuat instance MessagePacket dari dictionary JSON dengan decoding Base64."""
        required_keys = {"version", "sender", "receiver", "counter", "wrapped_key", "nonce", "ciphertext"}
        missing_keys = required_keys - set(data.keys())
        if missing_keys:
            raise PacketValidationError(f"Field paket tidak lengkap! Kurang: {missing_keys}")

        try:
            version = int(data["version"])
            sender = str(data["sender"])
            receiver = str(data["receiver"])
            counter = int(data["counter"])

            wrapped_key = base64.b64decode(data["wrapped_key"])
            nonce = base64.b64decode(data["nonce"])
            combined_ct = base64.b64decode(data["ciphertext"])

            if len(combined_ct) < 16:
                raise PacketValidationError("Panjang ciphertext tidak valid: minimal harus 16 byte untuk tag.")

            ciphertext = combined_ct[:-16]
            tag = combined_ct[-16:]

            signature = None
            if "signature" in data and data["signature"]:
                signature = base64.b64decode(data["signature"])

            return cls(
                version=version,
                sender=sender,
                receiver=receiver,
                counter=counter,
                wrapped_key=wrapped_key,
                nonce=nonce,
                ciphertext=ciphertext,
                tag=tag,
                signature=signature,
            )
        except Exception as exc:
            if isinstance(exc, PacketValidationError):
                raise
            raise PacketValidationError(f"Gagal mem-parse dictionary paket: {exc}") from exc

    @classmethod
    def from_json(cls, json_str: str) -> "MessagePacket":
        """Mem-parse string JSON mentah menjadi instance MessagePacket yang terverifikasi."""
        try:
            data = json.loads(json_str)
            if not isinstance(data, dict):
                raise PacketValidationError("Payload JSON harus berupa objek/dictionary.")
            return cls.from_dict(data)
        except json.JSONDecodeError as exc:
            raise PacketValidationError(f"Format JSON tidak valid / sintaks rusak: {exc}") from exc
