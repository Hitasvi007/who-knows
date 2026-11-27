import pytest
from hypothesis import given, settings, strategies as st

from backend.crypto.container import (
    HEADER_SIZE,
    SLOT_SIZE,
    UNSIGNED_CONTAINER_SIZE,
    VaultContainer,
)
from backend.crypto.engine import DecryptionError

# Build one valid container once so mutation fuzzing doesn't re-run Argon2id on setup
_CONTAINER = VaultContainer()
_VALID_PASSWORD = "Fuzz-Test-Master-Password-2026!"
_VALID_BLOB = _CONTAINER.build(_VALID_PASSWORD, b"fuzz_secret_payload")


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

@settings(max_examples=20, deadline=None)
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