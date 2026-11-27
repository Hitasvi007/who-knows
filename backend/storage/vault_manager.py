import functools
import os
import secrets
import threading
from pathlib import Path
from typing import Literal, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)

from backend.crypto.container import VaultContainer
from backend.crypto.rollback import RollbackGuard
from backend.storage.db import VaultDB


class VaultLockedError(Exception):
    """Raised when an operation requires an unlocked vault session."""


class VaultExistsError(Exception):
    """Raised when create_vault would overwrite an existing vault or key file."""


def _synchronized(fn):
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self.mutex:
            return fn(self, *args, **kwargs)

    return wrapper


class VaultManager:
    """Orchestrates VaultDB, VaultContainer, RollbackGuard, and atomic .vault disk I/O."""

    def __init__(
        self,
        vault_path: str | Path,
        vault_id: Optional[str] = None,
        container: Optional[VaultContainer] = None,
        guard: Optional[RollbackGuard] = None,
    ) -> None:
        self.vault_path = Path(vault_path)
        self.pub_path = Path(f"{self.vault_path}.pub")
        self.vault_id = vault_id or self.vault_path.name
        self.container = container or VaultContainer()
        self.guard = guard or RollbackGuard()
        # Serializes unlock/save/lock; API callers also hold it across "mutate DB + save".
        self.mutex = threading.RLock()

        # Active in-memory session state
        self.db: Optional[VaultDB] = None
        self.mode: Optional[Literal["real", "decoy"]] = None
        self._password: Optional[str] = None
        self._dek: Optional[bytes] = None
        self._seq_num: int = 0
        self._state_hash: bytes = b"\x00" * 32

    @property
    def is_unlocked(self) -> bool:
        return self.db is not None

    def _atomic_write(self, path: Path, data: bytes) -> None:
        tmp_path = Path(f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)

    @_synchronized
    def create_vault(
        self,
        real_password: str,
        duress_password: Optional[str] = None,
    ) -> None:
        """Initializes a new signed 68,909-byte .vault file and anchors seq 1."""
        if self.vault_path.exists() or self.pub_path.exists():
            raise VaultExistsError("A vault already exists at this path; refusing to overwrite it.")
        real_db = VaultDB()
        sk, pk = self.guard.generate_signing_keypair()

        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        real_db.set_meta("mldsa_priv", sk_bytes)

        decoy_bytes: Optional[bytes] = None
        if duress_password is not None:
            decoy_db = VaultDB()
            decoy_db.add_entry(
                title="Local Wi-Fi",
                username="guest",
                password="changeme123",
                notes="Home guest network",
            )
            decoy_bytes = decoy_db.export_bytes()
            decoy_db.close()

            # Real vault retains decoy snapshot so future Real saves re-bind Slot 2 to new header AAD
            real_db.set_meta("duress_pw", duress_password.encode("utf-8"))
            real_db.set_meta("decoy_snapshot", decoy_bytes)

        unsigned = self.container.build(
            real_password=real_password,
            real_data=real_db.export_bytes(),
            seq_num=1,
            prev_hash=b"\x00" * 32,
            duress_password=duress_password,
            decoy_data=decoy_bytes,
        )
        state_hash = self.guard.compute_state_hash(unsigned)
        signed = self.guard.sign_container(unsigned, sk)

        self._atomic_write(self.pub_path, pk_bytes)
        self._atomic_write(self.vault_path, signed)
        self.guard.commit_state(self.vault_id, 1, state_hash)

        # Keep session unlocked
        self.db = real_db
        self.mode = "real"
        self._password = real_password
        self._seq_num = 1
        self._state_hash = state_hash

    @_synchronized
    def unlock(self, password: str) -> Literal["real", "decoy"]:
        """Verifies ML-DSA-65 signature + rollback anchor, then unlocks in constant KDF time."""
        if not self.vault_path.exists() or not self.pub_path.exists():
            raise FileNotFoundError("Vault or public verification key not found.")

        signed_bytes = self.vault_path.read_bytes()
        verify_key = MLDSA65PublicKey.from_public_bytes(self.pub_path.read_bytes())

        # 1. Verify signature and rollback/fork state BEFORE running Argon2id
        unsigned, header, state_hash = self.guard.verify_container(
            signed_bytes, verify_key, self.vault_id
        )

        # 2. Constant-time dual-slot unlock
        mode, _, dek, raw_data = self.container.unlock(password, unsigned)

        self.db = VaultDB.from_bytes(raw_data)
        self.mode = mode
        self._password = password
        self._dek = dek
        self._seq_num = header.seq_num
        self._state_hash = state_hash
        return mode

    @_synchronized
    def save(self) -> int:
        """Increments seq_num, re-encrypts, signs with ML-DSA-65, and anchors the new state."""
        if not self.is_unlocked or self.db is None or self._password is None:
            raise VaultLockedError("Vault must be unlocked before saving.")

        # Duress sessions stay ephemeral in RAM to avoid corrupting Slot 1 on disk
        if self.mode == "decoy":
            return self._seq_num

        sk_bytes = self.db.get_meta("mldsa_priv")
        if not sk_bytes:
            raise RuntimeError("Missing ML-DSA-65 signing key in vault metadata.")
        sk = MLDSA65PrivateKey.from_seed_bytes(sk_bytes)

        duress_pw_bytes = self.db.get_meta("duress_pw")
        decoy_snapshot = self.db.get_meta("decoy_snapshot")
        duress_pw = duress_pw_bytes.decode("utf-8") if duress_pw_bytes else None

        next_seq = self._seq_num + 1
        unsigned = self.container.build(
            real_password=self._password,
            real_data=self.db.export_bytes(),
            seq_num=next_seq,
            prev_hash=self._state_hash,
            duress_password=duress_pw,
            decoy_data=decoy_snapshot,
            real_dek=self._dek,
        )
        new_hash = self.guard.compute_state_hash(unsigned)
        signed = self.guard.sign_container(unsigned, sk)

        self._atomic_write(self.vault_path, signed)
        self.guard.commit_state(self.vault_id, next_seq, new_hash)

        self._seq_num = next_seq
        self._state_hash = new_hash
        return next_seq

    @_synchronized
    def lock(self) -> None:
        """Closes the in-memory SQLite DB and clears session secrets from RAM."""
        if self.db is not None:
            self.db.close()
        self.db = None
        self.mode = None
        self._password = None
        self._dek = None
        self._seq_num = 0
        self._state_hash = b"\x00" * 32