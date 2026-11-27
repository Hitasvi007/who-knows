import base64
import os

# Fast Argon2id parameters; set here so this file does not depend on test collection order
os.environ["TESTING"] = "1"

import pytest
from hypothesis import given, settings, strategies as st

from backend.crypto.container import (
    HEADER_SIZE,
    SLOT_SIZE,
    UNSIGNED_CONTAINER_SIZE,
    VaultContainer,
)
from backend.crypto.engine import DecryptionError
from backend.crypto.pqc_share import (
    MLKEM768_PUB_SIZE,
    PUB_PREFIX,
    X25519_PUB_SIZE,
    HybridKeypair,
    HybridShareEngine,
)
from backend.crypto.rollback import (
    SIGNED_CONTAINER_SIZE,
    MemoryAnchor,
    RollbackGuard,
    SignatureError,
)

# Build one valid container once so mutation fuzzing doesn't re-run Argon2id on setup
_CONTAINER = VaultContainer()
assert _CONTAINER.engine.memory_cost == 1024, "fuzz suite must run with TESTING Argon2id params"
_VALID_PASSWORD = "Fuzz-Test-Master-Password-2026!"
_VALID_BLOB = _CONTAINER.build(_VALID_PASSWORD, b"fuzz_secret_payload")

_GUARD = RollbackGuard(local_anchor=MemoryAnchor())
_SK, _PK = _GUARD.generate_signing_keypair()
_SIGNED_BLOB = _GUARD.sign_container(_VALID_BLOB, _SK)

_SHARE = HybridShareEngine()
_RECIPIENT = HybridKeypair.generate()
_VALID_ENVELOPE = _SHARE.encrypt_share(_RECIPIENT.export_public_bundle(), b"fuzz_share")


# --- 1. VaultContainer.unlock ---


@settings(max_examples=1000, deadline=None)
@given(raw=st.binary(min_size=0, max_size=70000))
def test_fuzz_unlock_arbitrary_bytes(raw: bytes) -> None:
    """Arbitrary byte streams must never cause unhandled parser crashes."""
    with pytest.raises((ValueError, DecryptionError)):
        _CONTAINER.unlock(_VALID_PASSWORD, raw)


@settings(max_examples=500, deadline=None)
@given(
    header=st.binary(min_size=HEADER_SIZE, max_size=HEADER_SIZE),
    body_chunk=st.binary(min_size=64, max_size=64),
)
def test_fuzz_unlock_exact_size_garbage(header: bytes, body_chunk: bytes) -> None:
    """Exact-size random blobs must be cleanly rejected."""
    body_len = UNSIGNED_CONTAINER_SIZE - HEADER_SIZE
    body = (body_chunk * ((body_len // len(body_chunk)) + 1))[:body_len]
    raw = header + body
    assert len(raw) == UNSIGNED_CONTAINER_SIZE
    with pytest.raises((ValueError, DecryptionError)):
        _CONTAINER.unlock(_VALID_PASSWORD, raw)


@settings(max_examples=300, deadline=None)
@given(
    offset=st.integers(min_value=0, max_value=HEADER_SIZE + SLOT_SIZE - 1),
    xor_mask=st.integers(min_value=1, max_value=255),
)
def test_fuzz_mutated_valid_container(offset: int, xor_mask: int) -> None:
    """Any single-byte mutation in Header or Slot 1 must be caught cleanly."""
    mutated = bytearray(_VALID_BLOB)
    mutated[offset] ^= xor_mask
    with pytest.raises((ValueError, DecryptionError)):
        _CONTAINER.unlock(_VALID_PASSWORD, bytes(mutated))


# --- 2. RollbackGuard.verify_container ---

_VERIFY_ERRORS = (SignatureError, ValueError, DecryptionError)


@settings(max_examples=300, deadline=None)
@given(raw=st.binary(min_size=0, max_size=SIGNED_CONTAINER_SIZE + 64))
def test_fuzz_verify_arbitrary_bytes(raw: bytes) -> None:
    with pytest.raises(_VERIFY_ERRORS):
        _GUARD.verify_container(raw, _PK, "fuzz_vault")


@settings(max_examples=200, deadline=None)
@given(chunk=st.binary(min_size=64, max_size=64))
def test_fuzz_verify_exact_size_garbage(chunk: bytes) -> None:
    raw = (chunk * (SIGNED_CONTAINER_SIZE // 64 + 1))[:SIGNED_CONTAINER_SIZE]
    with pytest.raises(_VERIFY_ERRORS):
        _GUARD.verify_container(raw, _PK, "fuzz_vault")


@settings(max_examples=300, deadline=None)
@given(
    offset=st.integers(min_value=0, max_value=SIGNED_CONTAINER_SIZE - 1),
    xor_mask=st.integers(min_value=1, max_value=255),
)
def test_fuzz_verify_mutated_signed_container(offset: int, xor_mask: int) -> None:
    """Any single-byte mutation anywhere in a signed container fails the signature."""
    mutated = bytearray(_SIGNED_BLOB)
    mutated[offset] ^= xor_mask
    with pytest.raises(SignatureError):
        _GUARD.verify_container(bytes(mutated), _PK, "fuzz_vault")


# --- 3. HybridShareEngine.decrypt_share ---

_b64 = st.binary(max_size=1200).map(lambda b: base64.b64encode(b).decode("ascii"))
_field = st.one_of(_b64, st.text(max_size=64), st.integers(), st.none(), st.lists(st.integers(), max_size=3))
_ENVELOPE_KEYS = list(_VALID_ENVELOPE)


@settings(max_examples=300, deadline=None)
@given(
    envelope=st.one_of(
        st.dictionaries(st.sampled_from(_ENVELOPE_KEYS), _field),
        st.fixed_dictionaries({k: _field for k in _ENVELOPE_KEYS}),
        st.dictionaries(st.text(max_size=20), _field, max_size=6),
        st.text(max_size=100),
        st.lists(st.text(max_size=10), max_size=4),
        st.none(),
    )
)
def test_fuzz_decrypt_share_arbitrary_envelopes(envelope) -> None:
    with pytest.raises(DecryptionError):
        _SHARE.decrypt_share(_RECIPIENT, envelope)


@settings(max_examples=200, deadline=None)
@given(key=st.sampled_from(_ENVELOPE_KEYS), value=_field)
def test_fuzz_decrypt_share_one_field_replaced(key: str, value) -> None:
    """A valid envelope with any single field replaced must fail cleanly."""
    envelope = dict(_VALID_ENVELOPE, **{key: value})
    if envelope == _VALID_ENVELOPE:
        return
    try:
        _SHARE.decrypt_share(_RECIPIENT, envelope)
    except DecryptionError:
        return
    # Only metadata fields (version/alg) are not cryptographically bound
    assert key in {"version", "alg"}


# --- 4. HybridShareEngine._parse_public_bundle ---


@settings(max_examples=300, deadline=None)
@given(
    bundle=st.one_of(
        st.text(max_size=200),
        st.text(max_size=200).map(lambda t: PUB_PREFIX + t),
        st.binary(max_size=1300).map(lambda b: PUB_PREFIX + base64.urlsafe_b64encode(b).decode("ascii")),
        st.binary(min_size=X25519_PUB_SIZE + MLKEM768_PUB_SIZE, max_size=X25519_PUB_SIZE + MLKEM768_PUB_SIZE).map(
            lambda b: PUB_PREFIX + base64.urlsafe_b64encode(b).decode("ascii")
        ),
    )
)
def test_fuzz_parse_public_bundle(bundle: str) -> None:
    """Malformed bundles raise ValueError only; exact-length random bundles may parse."""
    try:
        HybridShareEngine._parse_public_bundle(bundle)
    except ValueError:
        pass
