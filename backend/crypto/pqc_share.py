import base64
import hashlib
from dataclasses import dataclass
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.crypto.engine import CryptoEngine, DecryptionError


X25519_PUB_SIZE = 32
MLKEM768_PUB_SIZE = 1184
X25519_PRIV_SIZE = 32
MLKEM768_SEED_SIZE = 64
PUB_PREFIX = "wk_pub_"
HKDF_INFO = b"whoknows-hybrid-x25519-mlkem768-v1"


@dataclass
class HybridKeypair:
    """User's long-term hybrid asymmetric identity, persisted in vault meta under `pqc_keypair`."""

    x25519_private: X25519PrivateKey
    mlkem_private: MLKEM768PrivateKey

    @classmethod
    def generate(cls) -> "HybridKeypair":
        return cls(
            x25519_private=X25519PrivateKey.generate(),
            mlkem_private=MLKEM768PrivateKey.generate(),
        )

    def to_bytes(self) -> bytes:
        """96 bytes: X25519 raw private key (32B) || ML-KEM-768 private seed (64B)."""
        x_priv = self.x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return x_priv + self.mlkem_private.private_bytes_raw()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridKeypair":
        if len(data) != X25519_PRIV_SIZE + MLKEM768_SEED_SIZE:
            raise ValueError("Malformed hybrid keypair bytes.")
        return cls(
            x25519_private=X25519PrivateKey.from_private_bytes(data[:X25519_PRIV_SIZE]),
            mlkem_private=MLKEM768PrivateKey.from_seed_bytes(data[X25519_PRIV_SIZE:]),
        )

    def public_bundle_bytes(self) -> bytes:
        x_pub = self.x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pq_pub = self.mlkem_private.public_key().public_bytes_raw()
        return x_pub + pq_pub  # 32B + 1,184B = 1,216B

    def export_public_bundle(self) -> str:
        """Exports a shareable public key string (wk_pub_...)."""
        encoded = base64.urlsafe_b64encode(self.public_bundle_bytes()).decode("ascii")
        return f"{PUB_PREFIX}{encoded}"


class HybridShareEngine:
    """Zero-knowledge credential sharing using X25519 + ML-KEM-768 + XChaCha20-Poly1305."""

    def __init__(self) -> None:
        self.crypto = CryptoEngine()

    @staticmethod
    def _parse_public_bundle(bundle_str: str) -> tuple[X25519PublicKey, MLKEM768PublicKey, bytes]:
        if not bundle_str.startswith(PUB_PREFIX):
            raise ValueError("Invalid public key bundle prefix.")
        raw = base64.urlsafe_b64decode(bundle_str[len(PUB_PREFIX) :])
        if len(raw) != X25519_PUB_SIZE + MLKEM768_PUB_SIZE:
            raise ValueError("Malformed hybrid public key bundle length.")

        x_pub_bytes = raw[:X25519_PUB_SIZE]
        pq_pub_bytes = raw[X25519_PUB_SIZE:]
        return (
            X25519PublicKey.from_public_bytes(x_pub_bytes),
            MLKEM768PublicKey.from_public_bytes(pq_pub_bytes),
            x_pub_bytes,
        )

    @staticmethod
    def _derive_hybrid_key(
        ss_classical: bytes,
        ss_pq: bytes,
        eph_x_pub: bytes,
        recip_x_pub: bytes,
        mlkem_ct: bytes,
    ) -> bytes:
        """Combines classical + PQ shared secrets with transcript binding via HKDF-SHA256."""
        transcript_salt = hashlib.sha256(eph_x_pub + recip_x_pub + mlkem_ct).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CryptoEngine.KEY_SIZE,
            salt=transcript_salt,
            info=HKDF_INFO,
        )
        return hkdf.derive(ss_classical + ss_pq)

    def encrypt_share(self, recipient_bundle: str, payload: bytes) -> Dict[str, str]:
        """Encapsulates a one-time hybrid key and encrypts the credential payload."""
        recip_x_pub, recip_pq_pub, recip_x_bytes = self._parse_public_bundle(recipient_bundle)

        # 1. Classical leg: ephemeral X25519 ECDH
        eph_x_priv = X25519PrivateKey.generate()
        eph_x_pub_bytes = eph_x_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ss_classical = eph_x_priv.exchange(recip_x_pub)

        # 2. Post-quantum leg: ML-KEM-768 encapsulation
        ss_pq, mlkem_ct = recip_pq_pub.encapsulate()

        # 3. Hybrid combiner -> 256-bit symmetric key
        share_key = self._derive_hybrid_key(
            ss_classical, ss_pq, eph_x_pub_bytes, recip_x_bytes, mlkem_ct
        )

        # 4. AEAD encryption bound to both ephemeral keys/ciphertexts as AAD
        aad = eph_x_pub_bytes + mlkem_ct
        nonce, ciphertext = self.crypto.encrypt_aead(share_key, payload, aad=aad)

        return {
            "version": "1",
            "alg": "X25519-MLKEM768-XChaCha20Poly1305",
            "ephemeral_x25519_pub": base64.b64encode(eph_x_pub_bytes).decode("ascii"),
            "mlkem_ciphertext": base64.b64encode(mlkem_ct).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def decrypt_share(self, recipient_keypair: HybridKeypair, envelope: Dict[str, str]) -> bytes:
        """Decapsulates the hybrid key and decrypts the one-time credential payload."""
        # Any malformed envelope (missing keys, bad base64, wrong key/ciphertext lengths,
        # non-string values) must surface as DecryptionError, never as an unhandled crash.
        try:
            return self._decrypt_share(recipient_keypair, envelope)
        except (KeyError, ValueError, TypeError) as exc:
            raise DecryptionError("Malformed hybrid share envelope.") from exc

    def _decrypt_share(self, recipient_keypair: HybridKeypair, envelope: Dict[str, str]) -> bytes:
        eph_x_pub_bytes = base64.b64decode(envelope["ephemeral_x25519_pub"])
        mlkem_ct = base64.b64decode(envelope["mlkem_ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        recip_x_bytes = recipient_keypair.x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # 1. Recover classical + PQ shared secrets
        ss_classical = recipient_keypair.x25519_private.exchange(
            X25519PublicKey.from_public_bytes(eph_x_pub_bytes)
        )
        ss_pq = recipient_keypair.mlkem_private.decapsulate(mlkem_ct)

        # 2. Re-derive symmetric key and decrypt
        share_key = self._derive_hybrid_key(
            ss_classical, ss_pq, eph_x_pub_bytes, recip_x_bytes, mlkem_ct
        )
        aad = eph_x_pub_bytes + mlkem_ct
        return self.crypto.decrypt_aead(share_key, nonce, ciphertext, aad=aad)