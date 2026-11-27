import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Optional, Protocol, Tuple

import httpx
import keyring
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)

from backend.crypto.container import HEADER_SIZE, UNSIGNED_CONTAINER_SIZE, VaultHeader


MLDSA65_SIG_SIZE = 3309
SIGNED_CONTAINER_SIZE = UNSIGNED_CONTAINER_SIZE + MLDSA65_SIG_SIZE  # 68,909 bytes
KEYRING_SERVICE = "whoknows-rollback-anchor"


class SignatureError(Exception):
    """Raised when the ML-DSA-65 container signature is missing or invalid."""


class RollbackDetectedError(Exception):
    """Raised when the vault's sequence number or state hash conflicts with the anchor."""


@dataclass
class AnchorState:
    seq_num: int
    state_hash: str  # hex-encoded SHA-256


class StateAnchor(Protocol):
    def get_latest(self, vault_id: str) -> Optional[AnchorState]: ...
    def set_latest(self, vault_id: str, state: AnchorState) -> None: ...


class KeyringAnchor:
    """Stores the latest expected vault state in the OS Credential Store."""

    def get_latest(self, vault_id: str) -> Optional[AnchorState]:
        raw = keyring.get_password(KEYRING_SERVICE, vault_id)
        if not raw:
            return None
        data = json.loads(raw)
        return AnchorState(seq_num=data["seq_num"], state_hash=data["state_hash"])

    def set_latest(self, vault_id: str, state: AnchorState) -> None:
        payload = json.dumps({"seq_num": state.seq_num, "state_hash": state.state_hash})
        keyring.set_password(KEYRING_SERVICE, vault_id, payload)


class RemoteAnchorClient:
    """Optional external append-only transparency log client (defeats local OS/disk rollback)."""

    def __init__(self, base_url: str, timeout: float = 3.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_latest(self, vault_id: str) -> Optional[AnchorState]:
        resp = httpx.get(f"{self.base_url}/anchor/{vault_id}", timeout=self.timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        return AnchorState(seq_num=data["seq_num"], state_hash=data["state_hash"])

    def set_latest(self, vault_id: str, state: AnchorState) -> None:
        resp = httpx.post(
            f"{self.base_url}/anchor/{vault_id}",
            json={"seq_num": state.seq_num, "state_hash": state.state_hash},
            timeout=self.timeout,
        )
        resp.raise_for_status()


class MemoryAnchor:
    """In-memory anchor for automated pytest runs and Tamper Lab simulations."""

    def __init__(self) -> None:
        self._store: Dict[str, AnchorState] = {}

    def get_latest(self, vault_id: str) -> Optional[AnchorState]:
        return self._store.get(vault_id)

    def set_latest(self, vault_id: str, state: AnchorState) -> None:
        self._store[vault_id] = state


class RollbackGuard:
    """Signs containers with ML-DSA-65 and enforces monotonic state progression."""

    def __init__(
        self,
        local_anchor: Optional[StateAnchor] = None,
        remote_anchor: Optional[StateAnchor] = None,
        strict_local: bool = True,
    ) -> None:
        self.local_anchor = local_anchor or KeyringAnchor()
        self.remote_anchor = remote_anchor
        # Single-device mode: the file must match the anchor exactly (seq AND hash).
        # A higher seq is only legitimate when another device can advance it (remote anchor / sync).
        self.strict_local = strict_local

    @staticmethod
    def generate_signing_keypair() -> Tuple[MLDSA65PrivateKey, MLDSA65PublicKey]:
        priv = MLDSA65PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def compute_state_hash(unsigned_container: bytes) -> bytes:
        if len(unsigned_container) != UNSIGNED_CONTAINER_SIZE:
            raise ValueError(f"Expected {UNSIGNED_CONTAINER_SIZE}-byte unsigned container.")
        return hashlib.sha256(unsigned_container).digest()

    def sign_container(
        self, unsigned_container: bytes, signing_key: MLDSA65PrivateKey
    ) -> bytes:
        """Appends a 3,309-byte ML-DSA-65 signature over SHA-256(Header || Slot 1 || Slot 2)."""
        state_hash = self.compute_state_hash(unsigned_container)
        signature = signing_key.sign(state_hash)
        signed = unsigned_container + signature
        assert len(signed) == SIGNED_CONTAINER_SIZE
        return signed

    def _check_anchor(
        self,
        anchor: StateAnchor,
        vault_id: str,
        seq_num: int,
        state_hash_hex: str,
        label: str,
        exact: bool = False,
    ) -> None:
        expected = anchor.get_latest(vault_id)
        if expected is None:
            return  # TOFU: no anchor yet, any validly signed file is accepted
        if seq_num < expected.seq_num:
            raise RollbackDetectedError(
                f"{label} rollback detected: file seq {seq_num} is behind anchored seq {expected.seq_num}."
            )
        if seq_num == expected.seq_num and state_hash_hex != expected.state_hash:
            raise RollbackDetectedError(
                f"{label} fork/equivocation detected at seq {seq_num}: state hash mismatch."
            )
        if exact and seq_num != expected.seq_num:
            raise RollbackDetectedError(
                f"{label} anchor mismatch: file seq {seq_num} is ahead of anchored seq {expected.seq_num} "
                "but no remote anchor is configured to vouch for it."
            )

    def verify_container(
        self,
        signed_container: bytes,
        verify_key: MLDSA65PublicKey,
        vault_id: str,
    ) -> Tuple[bytes, VaultHeader, bytes]:
        """Verifies ML-DSA-65 signature and checks local + remote anchors for rollback."""
        if len(signed_container) != SIGNED_CONTAINER_SIZE:
            raise SignatureError(
                f"Invalid signed container size: expected {SIGNED_CONTAINER_SIZE} bytes."
            )

        unsigned = signed_container[:UNSIGNED_CONTAINER_SIZE]
        signature = signed_container[UNSIGNED_CONTAINER_SIZE:]
        state_hash = self.compute_state_hash(unsigned)

        try:
            verify_key.verify(signature, state_hash)
        except InvalidSignature as exc:
            raise SignatureError("ML-DSA-65 signature verification failed.") from exc

        header = VaultHeader.from_bytes(unsigned[:HEADER_SIZE])
        state_hash_hex = state_hash.hex()

        exact = self.strict_local and self.remote_anchor is None
        self._check_anchor(self.local_anchor, vault_id, header.seq_num, state_hash_hex, "Local", exact)
        if self.remote_anchor is not None:
            self._check_anchor(self.remote_anchor, vault_id, header.seq_num, state_hash_hex, "Remote")

        return unsigned, header, state_hash

    def commit_state(self, vault_id: str, seq_num: int, state_hash: bytes) -> None:
        """Anchors the newly saved vault state to local (and optional remote) witnesses."""
        state = AnchorState(seq_num=seq_num, state_hash=state_hash.hex())
        self.local_anchor.set_latest(vault_id, state)
        if self.remote_anchor is not None:
            self.remote_anchor.set_latest(vault_id, state)