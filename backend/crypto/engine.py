import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError


class DecryptionError(Exception):
    """Raised when AEAD authentication fails (wrong key, tampered data, or AAD mismatch)."""


class CryptoEngine:
    """Core symmetric & KDF primitives for whoknows (Argon2id + XChaCha20-Poly1305)."""

    KEY_SIZE = 32      # 256-bit keys (KEK & DEK)
    SALT_SIZE = 16     # 128-bit Argon2id salt
    NONCE_SIZE = 24    # 192-bit XChaCha20 nonce (eliminates 2^32 birthday bound)
    TAG_SIZE = 16      # 128-bit Poly1305 MAC

    def __init__(self) -> None:
        if os.environ.get("TESTING") == "1":
            # Fast floor parameters for automated pytest runs
            self.iterations = 1
            self.memory_cost = 1024  # 1 MiB
            self.lanes = 1
        else:
            # RFC 9106 / OWASP memory-constrained production baseline
            self.iterations = 3
            self.memory_cost = 65536  # 64 MiB
            self.lanes = 4

    def generate_salt(self) -> bytes:
        return os.urandom(self.SALT_SIZE)

    def generate_dek(self) -> bytes:
        """Generates a fresh 256-bit Data Encryption Key (DEK)."""
        return os.urandom(self.KEY_SIZE)

    def derive_kek(self, password: str, salt: bytes) -> bytes:
        """Derives a 256-bit Key Encryption Key (KEK) from a master/duress password."""
        if len(salt) != self.SALT_SIZE:
            raise ValueError(f"Salt must be {self.SALT_SIZE} bytes.")

        kdf = Argon2id(
            salt=salt,
            length=self.KEY_SIZE,
            iterations=self.iterations,
            lanes=self.lanes,
            memory_cost=self.memory_cost,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_aead(self, key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        """Encrypts plaintext with a fresh 24-byte nonce (Generate-on-Write)."""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes.")

        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            message=plaintext,
            aad=aad,
            nonce=nonce,
            key=key,
        )
        return nonce, ciphertext

    def decrypt_aead(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Verifies Poly1305 tag & AAD before returning plaintext."""
        if len(key) != self.KEY_SIZE or len(nonce) != self.NONCE_SIZE:
            raise DecryptionError("Invalid key or nonce length.")

        try:
            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext=ciphertext,
                aad=aad,
                nonce=nonce,
                key=key,
            )
        except CryptoError as exc:
            raise DecryptionError("Authentication failed: invalid key, AAD, or tampered ciphertext.") from exc

    # --- Envelope Encryption Helpers ---

    def wrap_dek(self, kek: bytes, dek: bytes, header_aad: bytes) -> bytes:
        """Wraps a 32-byte DEK -> returns 72 bytes: [24B nonce || 48B wrapped DEK+tag]."""
        nonce, wrapped = self.encrypt_aead(kek, dek, aad=header_aad)
        return nonce + wrapped

    def unwrap_dek(self, kek: bytes, wrapped_blob: bytes, header_aad: bytes) -> bytes:
        """Unwraps a 72-byte wrapped DEK blob -> returns the 32-byte DEK."""
        if len(wrapped_blob) != self.NONCE_SIZE + self.KEY_SIZE + self.TAG_SIZE:
            raise DecryptionError("Malformed wrapped DEK block.")

        nonce = wrapped_blob[: self.NONCE_SIZE]
        ciphertext = wrapped_blob[self.NONCE_SIZE :]
        return self.decrypt_aead(kek, nonce, ciphertext, aad=header_aad)