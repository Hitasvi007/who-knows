import secrets  
import math
import os
import struct
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.crypto.container import (
    HEADER_SIZE,
    SLOT_SIZE,
    UNSIGNED_CONTAINER_SIZE,
    VaultContainer,
    VaultHeader,
)
from backend.crypto.engine import DecryptionError
from backend.crypto.pqc_share import HybridKeypair, HybridShareEngine
from backend.crypto.rollback import (
    MLDSA65_SIG_SIZE,
    SIGNED_CONTAINER_SIZE,
    MemoryAnchor,
    RollbackDetectedError,
    RollbackGuard,
    SignatureError,
)
from backend.storage.vault_manager import VaultExistsError, VaultLockedError, VaultManager


VAULT_PATH = Path(os.environ.get("WHOKNOWS_VAULT_PATH", "whoknows.vault"))
SESSION_TOKEN = os.environ.get("WHOKNOWS_SESSION_TOKEN") or secrets.token_hex(32)

ALLOWED_HOSTS = {
    "127.0.0.1:8000",
    "localhost:8000",
    "127.0.0.1",
    "localhost",
}

vm = VaultManager(VAULT_PATH)
pqc_engine = HybridShareEngine()
session_pqc_keypair = HybridKeypair.generate()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # In local dev, sync the ephemeral session token to Vite's gitignored .env.local
    env_local = Path("frontend/.env.local")
    if env_local.parent.exists() and not os.environ.get("PYTEST_CURRENT_TEST"):
        env_local.write_text(f"VITE_VAULT_TOKEN={SESSION_TOKEN}\n", encoding="utf-8")
    yield
    # Wipe in-memory SQLite DB and keys on server shutdown
    vm.lock()


app = FastAPI(
    title="whoknows Local Vault API",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def localhost_security_middleware(request: Request, call_next):
    # 1. DNS Rebinding Defense: strictly validate Host header
    host = (request.headers.get("host") or "").lower()
    allowed = ALLOWED_HOSTS | ({"testserver"} if os.environ.get("PYTEST_CURRENT_TEST") else set())
    if host not in allowed:
        return JSONResponse(
            status_code=403,
            content={"detail": f"Forbidden Host header '{host}' (DNS rebinding protection)."},
        )

    # Allow CORS preflight requests through to CORSMiddleware
    if request.method == "OPTIONS":
        return await call_next(request)

    # 2. Local Process / CSRF Defense: constant-time session token check
    provided_token = request.headers.get("x-vault-token", "")
    if not secrets.compare_digest(provided_token, SESSION_TOKEN):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing or invalid X-Vault-Token."},
        )

    return await call_next(request)


# CORSMiddleware must be registered AFTER localhost_security_middleware
# so it wraps outermost and attaches CORS headers even on 401/403 responses.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Vault-Token"],
)

# --- Exception Handlers ---


@app.exception_handler(VaultLockedError)
async def locked_handler(_: Request, exc: VaultLockedError):
    return JSONResponse(status_code=423, content={"detail": str(exc)})


@app.exception_handler(VaultExistsError)
async def exists_handler(_: Request, exc: VaultExistsError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(DecryptionError)
async def decryption_handler(_: Request, exc: DecryptionError):
    return JSONResponse(status_code=401, content={"detail": str(exc)})


@app.exception_handler(SignatureError)
async def signature_handler(_: Request, exc: SignatureError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(RollbackDetectedError)
async def rollback_handler(_: Request, exc: RollbackDetectedError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


# --- Dependencies & Helpers ---


def require_unlocked() -> VaultManager:
    if not vm.is_unlocked or vm.db is None:
        raise VaultLockedError("Vault is locked. Unlock it first.")
    return vm


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


def _flip_bit(data: bytes, idx: int) -> bytes:
    buf = bytearray(data)
    buf[idx] ^= 0x01
    return bytes(buf)


# --- Pydantic Schemas ---


class VaultInitRequest(BaseModel):
    real_password: str = Field(..., min_length=1)
    duress_password: Optional[str] = None


class VaultUnlockRequest(BaseModel):
    password: str = Field(..., min_length=1)


class EntryCreateRequest(BaseModel):
    title: str = Field(..., min_length=1)
    username: str = ""
    password: str = ""
    url: str = ""
    totp_secret: str = ""
    notes: str = ""


class EntryUpdateRequest(BaseModel):
    title: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    totp_secret: Optional[str] = None
    notes: Optional[str] = None


class PQCEncryptRequest(BaseModel):
    recipient_bundle: str
    payload: str


class PQCDecryptRequest(BaseModel):
    envelope: Dict[str, str]


class BitFlipRequest(BaseModel):
    offset: int = Field(default=HEADER_SIZE + 200, ge=0, lt=SIGNED_CONTAINER_SIZE)


# --- 1. Vault Lifecycle (/api/vault) ---


@app.get("/api/vault/status")
def vault_status() -> Dict[str, Any]:
    return {
        "exists": vm.vault_path.exists(),
        "unlocked": vm.is_unlocked,
        "mode": vm.mode,
        "seq_num": vm._seq_num if vm.is_unlocked else 0,
    }


@app.post("/api/vault/init")
def vault_init(req: VaultInitRequest) -> Dict[str, Any]:
    with vm.mutex:
        vm.create_vault(req.real_password, duress_password=req.duress_password)
        return {
            "status": "created",
            "seq_num": vm._seq_num,
            "size_bytes": vm.vault_path.stat().st_size,
        }


@app.post("/api/vault/unlock")
def vault_unlock(req: VaultUnlockRequest) -> Dict[str, Any]:
    t0 = time.perf_counter()
    mode = vm.unlock(req.password)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "status": "unlocked",
        "mode": mode,
        "seq_num": vm._seq_num,
        "unlock_ms": elapsed_ms,
    }


@app.post("/api/vault/lock")
def vault_lock() -> Dict[str, str]:
    vm.lock()
    return {"status": "locked"}


# --- 2. Credential CRUD (/api/entries) ---


@app.get("/api/entries")
def list_entries(q: Optional[str] = None, manager: VaultManager = Depends(require_unlocked)) -> List[Dict[str, Any]]:
    with manager.mutex:
        require_unlocked()
        return [e.to_dict() for e in manager.db.list_entries(query=q)]


@app.post("/api/entries", status_code=201)
def create_entry(req: EntryCreateRequest, manager: VaultManager = Depends(require_unlocked)) -> Dict[str, Any]:
    with manager.mutex:  # DB mutation + save must be atomic together
        require_unlocked()
        entry = manager.db.add_entry(
            title=req.title,
            username=req.username,
            password=req.password,
            url=req.url,
            totp_secret=req.totp_secret,
            notes=req.notes,
        )
        seq_num = manager.save()
    return {"entry": entry.to_dict(), "seq_num": seq_num}


@app.patch("/api/entries/{entry_id}")
def update_entry(
    entry_id: str,
    req: EntryUpdateRequest,
    manager: VaultManager = Depends(require_unlocked),
) -> Dict[str, Any]:
    with manager.mutex:
        require_unlocked()
        updated = manager.db.update_entry(entry_id, **req.model_dump(exclude_unset=True))
        if not updated:
            raise HTTPException(status_code=404, detail="Entry not found.")
        seq_num = manager.save()
    return {"entry": updated.to_dict(), "seq_num": seq_num}


@app.delete("/api/entries/{entry_id}")
def delete_entry(entry_id: str, manager: VaultManager = Depends(require_unlocked)) -> Dict[str, Any]:
    with manager.mutex:
        require_unlocked()
        deleted = manager.db.delete_entry(entry_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Entry not found.")
        seq_num = manager.save()
    return {"deleted": True, "seq_num": seq_num}


# --- 3. Hybrid Post-Quantum Sharing (/api/pqc) ---


@app.get("/api/pqc/public-key")
def get_pqc_public_key() -> Dict[str, Any]:
    return {
        "public_bundle": session_pqc_keypair.export_public_bundle(),
        "size_bytes": len(session_pqc_keypair.public_bundle_bytes()),
    }


@app.post("/api/pqc/encrypt")
def pqc_encrypt(req: PQCEncryptRequest) -> Dict[str, Any]:
    envelope = pqc_engine.encrypt_share(req.recipient_bundle, req.payload.encode("utf-8"))
    return {"envelope": envelope}


@app.post("/api/pqc/decrypt")
def pqc_decrypt(req: PQCDecryptRequest) -> Dict[str, str]:
    plaintext = pqc_engine.decrypt_share(session_pqc_keypair, req.envelope)
    return {"plaintext": plaintext.decode("utf-8")}


# --- 4. Interactive Tamper Lab (/api/tamper) ---


@app.get("/api/tamper/inspect")
def tamper_inspect() -> Dict[str, Any]:
    if not vm.vault_path.exists():
        raise HTTPException(status_code=404, detail="No vault file on disk yet.")
    raw = vm.vault_path.read_bytes()
    header_bytes = raw[:HEADER_SIZE]
    header = VaultHeader.from_bytes(header_bytes)
    slot_1 = raw[HEADER_SIZE : HEADER_SIZE + SLOT_SIZE]
    slot_2 = raw[HEADER_SIZE + SLOT_SIZE : UNSIGNED_CONTAINER_SIZE]

    return {
        "total_bytes": len(raw),
        "header_hex": header_bytes.hex(),
        "seq_num": header.seq_num,
        "prev_hash": header.prev_hash.hex(),
        "slot1_entropy": _shannon_entropy(slot_1),
        "slot2_entropy": _shannon_entropy(slot_2),
        "sig_bytes": MLDSA65_SIG_SIZE,
    }

@app.post("/api/tamper/bit-flip")
def tamper_bit_flip(req: BitFlipRequest) -> Dict[str, Any]:
    c = VaultContainer()
    blob = c.build("lab_pw", b"tamper_lab_secret")

    # Header + Slot 1: isolate XChaCha20-Poly1305 AEAD layer
    if req.offset < HEADER_SIZE + SLOT_SIZE:
        tampered = _flip_bit(blob, req.offset)
        try:
            c.unlock("lab_pw", tampered)
            return {"attack": "ciphertext_bit_flip", "caught": False, "offset": req.offset}
        except DecryptionError as exc:
            return {
                "attack": "ciphertext_bit_flip",
                "caught": True,
                "layer": "XChaCha20-Poly1305",
                "offset": req.offset,
                "error": str(exc),
            }

    # Slot 2 + Signature region: caught at container boundary by ML-DSA-65 before KDF
    guard = RollbackGuard(local_anchor=MemoryAnchor())
    sk, pk = guard.generate_signing_keypair()
    signed_blob = guard.sign_container(blob, sk)
    tampered_signed = _flip_bit(signed_blob, req.offset)
    try:
        guard.verify_container(tampered_signed, pk, "tamper_lab")
        return {"attack": "ciphertext_bit_flip", "caught": False, "offset": req.offset}
    except SignatureError as exc:
        return {
            "attack": "ciphertext_bit_flip",
            "caught": True,
            "layer": "ML-DSA-65 (FIPS 204)",
            "rejected_before_kdf": True,
            "offset": req.offset,
            "error": str(exc),
        }


@app.post("/api/tamper/header-aad")
def tamper_header_aad() -> Dict[str, Any]:
    c = VaultContainer()
    blob = c.build("lab_pw", b"tamper_lab_secret", seq_num=1)
    buf = bytearray(blob)
    buf[22:30] = struct.pack(">Q", 99)
    try:
        c.unlock("lab_pw", bytes(buf))
        return {"attack": "header_aad_tamper", "caught": False}
    except DecryptionError as exc:
        return {
            "attack": "header_aad_tamper",
            "caught": True,
            "layer": "AEAD AAD Binding",
            "error": str(exc),
        }


@app.post("/api/tamper/signature")
def tamper_signature() -> Dict[str, Any]:
    c = VaultContainer()
    g = RollbackGuard(local_anchor=MemoryAnchor())
    sk, pk = g.generate_signing_keypair()
    signed = g.sign_container(c.build("lab_pw", b"lab_secret"), sk)
    tampered = _flip_bit(signed, SIGNED_CONTAINER_SIZE - 1)
    try:
        g.verify_container(tampered, pk, "lab_vault")
        return {"attack": "mldsa_sig_forge", "caught": False}
    except SignatureError as exc:
        return {
            "attack": "mldsa_sig_forge",
            "caught": True,
            "layer": "ML-DSA-65 (FIPS 204)",
            "rejected_before_kdf": True,
            "error": str(exc),
        }


@app.post("/api/tamper/rollback")
def tamper_rollback() -> Dict[str, Any]:
    c = VaultContainer()
    g = RollbackGuard(local_anchor=MemoryAnchor())
    sk, pk = g.generate_signing_keypair()

    v1 = g.sign_container(c.build("lab_pw", b"v1", seq_num=1), sk)
    h1 = g.compute_state_hash(v1[:UNSIGNED_CONTAINER_SIZE])
    v2 = g.sign_container(c.build("lab_pw", b"v2", seq_num=2, prev_hash=h1), sk)
    _, _, h2 = g.verify_container(v2, pk, "lab_vault")
    g.commit_state("lab_vault", 2, h2)

    try:
        g.verify_container(v1, pk, "lab_vault")
        return {"attack": "rollback_replay", "caught": False}
    except RollbackDetectedError as exc:
        return {
            "attack": "rollback_replay",
            "caught": True,
            "layer": "RollbackGuard",
            "error": str(exc),
        }


@app.post("/api/tamper/duress-timing")
def tamper_duress_timing() -> Dict[str, Any]:
    c = VaultContainer()
    blob = c.build("real_pw", b"real", duress_password="decoy_pw", decoy_data=b"decoy")

    t0 = time.perf_counter()
    c.unlock("real_pw", blob)
    real_ms = round((time.perf_counter() - t0) * 1000, 2)

    t1 = time.perf_counter()
    c.unlock("decoy_pw", blob)
    decoy_ms = round((time.perf_counter() - t1) * 1000, 2)

    ratio = round(decoy_ms / max(real_ms, 0.01), 2)
    return {
        "real_ms": real_ms,
        "decoy_ms": decoy_ms,
        "ratio": ratio,
        "constant_time_pass": ratio < 1.8,
    }