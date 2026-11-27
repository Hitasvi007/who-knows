import base64
import os
import struct
import time
from pathlib import Path

import pytest

# Use fast Argon2id parameters for automated test runs
os.environ["TESTING"] = "1"

from backend.crypto.container import (
    HEADER_SIZE,
    SLOT_SIZE,
    UNSIGNED_CONTAINER_SIZE,
    VaultContainer,
)
from backend.crypto.engine import CryptoEngine, DecryptionError
from backend.crypto.pqc_share import HybridKeypair, HybridShareEngine
from backend.crypto.rollback import (
    SIGNED_CONTAINER_SIZE,
    MemoryAnchor,
    RollbackDetectedError,
    RollbackGuard,
    SignatureError,
)
from backend.crypto.timing import benchmark_unlock_timing
from backend.storage.vault_manager import VaultManager


def _flip_bit(data: bytes, byte_index: int) -> bytes:
    buf = bytearray(data)
    buf[byte_index] ^= 0x01
    return bytes(buf)


# --- 1. AEAD & Container Integrity ---


def test_ciphertext_bit_flip_rejected():
    """Flipping a single bit inside Slot 1 ciphertext must fail Poly1305 authentication."""
    container = VaultContainer()
    blob = container.build("master_pw", b"top_secret_credentials")

    # Flip a bit deep inside Slot 1 payload ciphertext
    tampered = _flip_bit(blob, HEADER_SIZE + 200)
    with pytest.raises(DecryptionError):
        container.unlock("master_pw", tampered)


def test_header_aad_tampering_rejected():
    """Modifying plaintext header metadata (seq_num) must break AAD binding."""
    container = VaultContainer()
    blob = container.build("master_pw", b"top_secret_credentials", seq_num=1)

    # Mutate seq_num at offset 22..30 in the 64-byte header without touching Slot 1
    buf = bytearray(blob)
    buf[22:30] = struct.pack(">Q", 99)

    with pytest.raises(DecryptionError):
        container.unlock("master_pw", bytes(buf))


# --- 2. ML-DSA-65 Signatures, Rollback & Fork Attacks ---


def test_mldsa_signature_tampering_rejected(tmp_path: Path):
    """Flipping a bit in the ML-DSA-65 signature must fail before Argon2id runs."""
    vault_path = tmp_path / "sig.vault"
    guard = RollbackGuard(local_anchor=MemoryAnchor())
    vm = VaultManager(vault_path, guard=guard)
    vm.create_vault("real_pw")
    vm.lock()

    # Corrupt the last byte of the 3,309-byte ML-DSA-65 signature
    raw = vault_path.read_bytes()
    assert len(raw) == SIGNED_CONTAINER_SIZE
    vault_path.write_bytes(_flip_bit(raw, len(raw) - 1))

    with pytest.raises(SignatureError):
        vm.unlock("real_pw")


def test_rollback_attack_detected(tmp_path: Path):
    """Restoring a valid older .vault backup (seq 1) after seq 2 is anchored must fail."""
    vault_path = tmp_path / "rollback.vault"
    guard = RollbackGuard(local_anchor=MemoryAnchor())
    vm = VaultManager(vault_path, guard=guard)

    vm.create_vault("real_pw")
    v1_backup = vault_path.read_bytes()

    vm.db.add_entry("Bank", "user", "new_password")
    assert vm.save() == 2
    vm.lock()

    # Attacker overwrites disk with valid, signed v1 backup
    vault_path.write_bytes(v1_backup)

    with pytest.raises(RollbackDetectedError, match="rollback detected"):
        vm.unlock("real_pw")


def test_fork_equivocation_attack_detected(tmp_path: Path):
    """Two different valid signed states claiming the same seq_num must trigger fork detection."""
    vault_path = tmp_path / "fork.vault"
    anchor = MemoryAnchor()
    guard = RollbackGuard(local_anchor=anchor)
    vm = VaultManager(vault_path, guard=guard)

    vm.create_vault("real_pw")
    v1_bytes = vault_path.read_bytes()
    v1_pub = Path(f"{vault_path}.pub").read_bytes()

    # Branch A: save seq 2 (anchored)
    vm.db.add_entry("Entry A", "alice", "passA")
    assert vm.save() == 2
    vm.lock()

    # Branch B: attacker forks from v1 on a separate machine with its own anchor to produce a valid seq 2
    fork_path = tmp_path / "fork_b.vault"
    fork_path.write_bytes(v1_bytes)
    Path(f"{fork_path}.pub").write_bytes(v1_pub)
    vm_fork = VaultManager(fork_path, guard=RollbackGuard(local_anchor=MemoryAnchor()))
    vm_fork.unlock("real_pw")
    vm_fork.db.add_entry("Entry B", "mallory", "passB")
    assert vm_fork.save() == 2
    vm_fork.lock()

    # Attacker swaps Branch B's seq 2 onto the victim's disk
    vault_path.write_bytes(fork_path.read_bytes())

    with pytest.raises(RollbackDetectedError, match="fork/equivocation"):
        vm.unlock("real_pw")


@pytest.mark.parametrize("strict", [True, False])
def test_unanchored_forward_seq_rejected_in_strict_mode(tmp_path: Path, strict: bool):
    """A validly signed seq N+1 written without updating the anchor is rejected in strict mode."""
    vault_path = tmp_path / "forward.vault"
    anchor = MemoryAnchor()
    vm = VaultManager(vault_path, guard=RollbackGuard(local_anchor=anchor, strict_local=strict))
    vm.create_vault("real_pw")
    vm.lock()

    # Attacker (or another process) with the key advances the file using a separate anchor
    other = VaultManager(vault_path, vault_id=vm.vault_id, guard=RollbackGuard(local_anchor=MemoryAnchor()))
    other.unlock("real_pw")
    other.db.add_entry("Injected", "x", "y")
    assert other.save() == 2
    other.lock()
    assert anchor.get_latest(vm.vault_id).seq_num == 1

    if strict:
        with pytest.raises(RollbackDetectedError, match="anchor mismatch"):
            vm.unlock("real_pw")
    else:
        assert vm.unlock("real_pw") == "real"


# --- 3. Plausible Deniability & Constant-Time Duress ---


def test_duress_fixed_size_and_ephemeral_writes(tmp_path: Path):
    """Container size is identical with/without Duress Mode, and decoy edits never alter disk."""
    p_no_duress = tmp_path / "single.vault"
    p_duress = tmp_path / "dual.vault"

    vm1 = VaultManager(p_no_duress, guard=RollbackGuard(local_anchor=MemoryAnchor()))
    vm1.create_vault("real_pw")
    vm1.lock()

    vm2 = VaultManager(p_duress, guard=RollbackGuard(local_anchor=MemoryAnchor()))
    vm2.create_vault("real_pw", duress_password="decoy_pw")
    vm2.lock()

    assert len(p_no_duress.read_bytes()) == len(p_duress.read_bytes()) == SIGNED_CONTAINER_SIZE

    # Unlock in Duress Mode, add an entry, and save -> disk bytes must remain untouched
    before_bytes = p_duress.read_bytes()
    assert vm2.unlock("decoy_pw") == "decoy"
    vm2.db.add_entry("Fake Note", "guest", "1234")
    vm2.save()
    vm2.lock()

    assert p_duress.read_bytes() == before_bytes


def test_duress_unlock_single_kdf_pass():
    """Real, decoy and wrong-password unlocks must have medians within 10% (one Argon2id pass each)."""
    engine = CryptoEngine()
    engine.memory_cost = 8192  # 8 MiB: big enough that OS jitter is small next to the KDF, still fast
    result = benchmark_unlock_timing(n=30, container=VaultContainer(engine))
    assert result["constant_time_pass"] is True, result


# --- 4. Hybrid Post-Quantum Sharing (X25519 + ML-KEM-768) ---


def test_hybrid_pqc_ciphertext_tampering_rejected():
    """Tampering with either the ML-KEM ciphertext or ephemeral X25519 key breaks HKDF + AAD."""
    bob = HybridKeypair.generate()
    engine = HybridShareEngine()
    envelope = engine.encrypt_share(bob.export_public_bundle(), b"prod_db_password")

    # 1. Flip a bit in the ML-KEM-768 ciphertext
    bad_mlkem = dict(envelope)
    ct_bytes = base64.b64decode(bad_mlkem["mlkem_ciphertext"])
    bad_mlkem["mlkem_ciphertext"] = base64.b64encode(_flip_bit(ct_bytes, 10)).decode("ascii")
    with pytest.raises(DecryptionError):
        engine.decrypt_share(bob, bad_mlkem)

    # 2. Flip a bit in the ephemeral X25519 public key
    bad_x25519 = dict(envelope)
    x_bytes = base64.b64decode(bad_x25519["ephemeral_x25519_pub"])
    bad_x25519["ephemeral_x25519_pub"] = base64.b64encode(_flip_bit(x_bytes, 5)).decode("ascii")
    with pytest.raises(DecryptionError):
        engine.decrypt_share(bob, bad_x25519)