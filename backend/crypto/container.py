import os
import struct
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

from backend.crypto.engine import CryptoEngine, DecryptionError


MAGIC = b"WKN1"
VERSION = 1

HEADER_FORMAT = ">4sH16sQ32sH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 64 bytes

SLOT_SIZE = 32_768
WRAPPED_DEK_SIZE = 72          # 24B nonce + 32B DEK + 16B Poly1305 MAC
PAYLOAD_NONCE_SIZE = 24
SLOT_CIPHERTEXT_SIZE = SLOT_SIZE - WRAPPED_DEK_SIZE - PAYLOAD_NONCE_SIZE  # 32,672 bytes
SLOT_PLAINTEXT_SIZE = SLOT_CIPHERTEXT_SIZE - CryptoEngine.TAG_SIZE        # 32,656 bytes
MAX_DATA_SIZE = SLOT_PLAINTEXT_SIZE - 4                                   # 32,652 bytes (4B length prefix)

UNSIGNED_CONTAINER_SIZE = HEADER_SIZE + (2 * SLOT_SIZE)  # 65,600 bytes


@dataclass
class VaultHeader:
    magic: bytes
    version: int
    salt: bytes
    seq_num: int
    prev_hash: bytes
    reserved: int = 0

    def to_bytes(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            self.salt,
            self.seq_num,
            self.prev_hash,
            self.reserved,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultHeader":
        if len(data) != HEADER_SIZE:
            raise ValueError(f"Header must be {HEADER_SIZE} bytes.")
        magic, version, salt, seq_num, prev_hash, reserved = struct.unpack(HEADER_FORMAT, data)
        if magic != MAGIC:
            raise DecryptionError("Invalid vault magic bytes.")
        if version != VERSION:
            raise DecryptionError(f"Unsupported vault version: {version}")
        return cls(magic, version, salt, seq_num, prev_hash, reserved)


class VaultContainer:
    """Packs and unpacks the fixed-size Dual-Slot binary container with IND-CPA Duress Mode."""

    def __init__(self, engine: Optional[CryptoEngine] = None) -> None:
        self.engine = engine or CryptoEngine()

    def _pack_slot(self, kek: bytes, dek: bytes, raw_data: bytes, header_aad: bytes) -> bytes:
        if len(raw_data) > MAX_DATA_SIZE:
            raise ValueError(f"Payload exceeds maximum slot capacity ({MAX_DATA_SIZE} bytes).")

        # 1. Wrap the 32B DEK with the KEK (bound to header AAD)
        wrapped_dek = self.engine.wrap_dek(kek, dek, header_aad)

        # 2. Length-prefix and pad payload to exact fixed size
        pad_len = MAX_DATA_SIZE - len(raw_data)
        padded_plaintext = struct.pack(">I", len(raw_data)) + raw_data + os.urandom(pad_len)

        # 3. Encrypt padded payload with the DEK (bound to header AAD)
        payload_nonce, ciphertext = self.engine.encrypt_aead(dek, padded_plaintext, aad=header_aad)

        slot = wrapped_dek + payload_nonce + ciphertext
        assert len(slot) == SLOT_SIZE
        return slot

    def _unpack_slot(self, dek: bytes, slot_bytes: bytes, header_aad: bytes) -> bytes:
        payload_nonce = slot_bytes[WRAPPED_DEK_SIZE : WRAPPED_DEK_SIZE + PAYLOAD_NONCE_SIZE]
        ciphertext = slot_bytes[WRAPPED_DEK_SIZE + PAYLOAD_NONCE_SIZE :]

        padded_plaintext = self.engine.decrypt_aead(dek, payload_nonce, ciphertext, aad=header_aad)
        data_len = struct.unpack(">I", padded_plaintext[:4])[0]
        if data_len > MAX_DATA_SIZE:
            raise DecryptionError("Corrupted payload length prefix.")

        return padded_plaintext[4 : 4 + data_len]

    def build(
        self,
        real_password: str,
        real_data: bytes,
        seq_num: int = 1,
        prev_hash: bytes = b"\x00" * 32,
        duress_password: Optional[str] = None,
        decoy_data: Optional[bytes] = None,
        real_dek: Optional[bytes] = None,
        decoy_dek: Optional[bytes] = None,
    ) -> bytes:
        """Creates a 65,600-byte unsigned container. Slot 2 is random noise if Duress Mode is off."""
        salt = self.engine.generate_salt()
        header = VaultHeader(MAGIC, VERSION, salt, seq_num, prev_hash)
        header_bytes = header.to_bytes()

        # Slot 1: Real Vault
        real_kek = self.engine.derive_kek(real_password, salt)
        r_dek = real_dek or self.engine.generate_dek()
        slot_1 = self._pack_slot(real_kek, r_dek, real_data, header_bytes)

        # Slot 2: Decoy Vault (or IND-CPA indistinguishable random noise)
        if duress_password is not None and decoy_data is not None:
            if duress_password == real_password:
                raise ValueError("Duress password must differ from the master password.")
            decoy_kek = self.engine.derive_kek(duress_password, salt)
            d_dek = decoy_dek or self.engine.generate_dek()
            slot_2 = self._pack_slot(decoy_kek, d_dek, decoy_data, header_bytes)
        else:
            slot_2 = os.urandom(SLOT_SIZE)

        return header_bytes + slot_1 + slot_2

    def unlock(
        self, password: str, container_bytes: bytes
    ) -> Tuple[Literal["real", "decoy"], VaultHeader, bytes, bytes]:
        """
        Unlocks the container in constant KDF time (1 Argon2id pass).
        Returns: (mode, header, dek, raw_data)
        """
        if len(container_bytes) < UNSIGNED_CONTAINER_SIZE:
            raise DecryptionError("Container is truncated or malformed.")

        header_bytes = container_bytes[:HEADER_SIZE]
        header = VaultHeader.from_bytes(header_bytes)

        slot_1 = container_bytes[HEADER_SIZE : HEADER_SIZE + SLOT_SIZE]
        slot_2 = container_bytes[HEADER_SIZE + SLOT_SIZE : UNSIGNED_CONTAINER_SIZE]

        # Single Argon2id derivation for both slots (eliminates 2x timing side-channel)
        candidate_kek = self.engine.derive_kek(password, header.salt)

        real_dek: Optional[bytes] = None
        decoy_dek: Optional[bytes] = None

        try:
            real_dek = self.engine.unwrap_dek(candidate_kek, slot_1[:WRAPPED_DEK_SIZE], header_bytes)
        except DecryptionError:
            pass

        try:
            decoy_dek = self.engine.unwrap_dek(candidate_kek, slot_2[:WRAPPED_DEK_SIZE], header_bytes)
        except DecryptionError:
            pass

        if real_dek is not None:
            return "real", header, real_dek, self._unpack_slot(real_dek, slot_1, header_bytes)
        if decoy_dek is not None:
            return "decoy", header, decoy_dek, self._unpack_slot(decoy_dek, slot_2, header_bytes)

        raise DecryptionError("Incorrect password or tampered vault.")