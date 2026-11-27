import asyncio
import secrets
import math
import os
import struct
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.crypto.container import (
    HEADER_SIZE,
    SLOT_SIZE,
    UNSIGNED_CONTAINER_SIZE,
    VaultContainer,
    VaultHeader,
)
from backend.crypto.engine import DecryptionError
from backend.crypto.pqc_share import HybridShareEngine
from backend.crypto.timing import benchmark_unlock_timing
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
# One-time code printed at startup; exchanged once for an HttpOnly session cookie.
LAUNCH_CODE: Optional[str] = secrets.token_urlsafe(24)
SESSION_COOKIE = "wk_session"
# Dev mode (Vite on :5173) accepts the X-Vault-Token header, which is compiled into the dev JS bundle.
DEV_MODE = os.environ.get("WHOKNOWS_DEV") == "1"
IDLE_LOCK_SECONDS = float(os.environ.get("WHOKNOWS_IDLE_LOCK_SECONDS", "300"))
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

APP_ORIGINS = {"http://127.0.0.1:8000", "http://localhost:8000"}
DEV_ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}

ALLOWED_HOSTS = {
    "127.0.0.1:8000",
    "localhost:8000",
    "127.0.0.1",
    "localhost",
}

vm = VaultManager(VAULT_PATH)
pqc_engine = HybridShareEngine()


def weak_kdf_warning() -> Optional[str]:
    engine = vm.container.engine
    if not engine.weak_params:
        return None
    bar = "!" * 72
    return "\n".join([
        "",
        bar,
        f"  WARNING: weak Argon2id parameters active ({engine.memory_cost // 1024} MiB, t={engine.iterations}).",
        "  TESTING=1 is set. Vaults created now are cheap to brute-force. Unset TESTING.",
        bar,
        "",
    ])


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        warning = weak_kdf_warning()
        if warning:
            print(warning, flush=True)
        print(f"\n  whoknows: open http://127.0.0.1:8000/?launch={LAUNCH_CODE}  (one-time link)\n", flush=True)
        if DEV_MODE:
            # Dev only: sync the session token to Vite's gitignored .env.local (exposed to local processes)
            Path("frontend/.env.local").write_text(f"VITE_VAULT_TOKEN={SESSION_TOKEN}\n", encoding="utf-8")
            print("  whoknows: WHOKNOWS_DEV=1, the session token is exposed via the Vite dev server.\n", flush=True)
    async def idle_watchdog():
        while True:
            await asyncio.sleep(15)
            vm.lock_if_idle(IDLE_LOCK_SECONDS)

    watchdog = asyncio.create_task(idle_watchdog())
    yield
    watchdog.cancel()
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

    # 2. Local Process / CSRF Defense: constant-time session check on every API call.
    # HttpOnly + SameSite=Strict cookie; the header is only honoured in dev mode.
    if request.url.path.startswith("/api/"):
        # Browsers treat every localhost port as "same site", so SameSite alone would let a page
        # on another port send bodiless POSTs (lock, tamper probes) with our cookie.
        origin = request.headers.get("origin")
        if origin is not None and origin not in APP_ORIGINS | (DEV_ORIGINS if DEV_MODE else set()):
            return JSONResponse(status_code=403, content={"detail": f"Forbidden Origin '{origin}'."})
        provided = request.cookies.get(SESSION_COOKIE) or (
            request.headers.get("x-vault-token", "") if DEV_MODE else ""
        )
        if not secrets.compare_digest(provided, SESSION_TOKEN):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid session. Open the launch URL printed by the daemon."},
            )
        # Idle auto-lock: lock first if the session expired, then count this call as activity.
        # Passive status checks do not keep the vault unlocked.
        vm.lock_if_idle(IDLE_LOCK_SECONDS)
        if request.url.path != "/api/vault/status":
            vm.touch()
        return await call_next(request)

    # 3. One-time launch code -> session cookie, then strip the code from the URL
    code = request.query_params.get("launch")
    if code is not None:
        global LAUNCH_CODE
        if LAUNCH_CODE is None or not secrets.compare_digest(code, LAUNCH_CODE):
            return JSONResponse(status_code=401, content={"detail": "Launch code invalid or already used."})
        LAUNCH_CODE = None
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(SESSION_COOKIE, SESSION_TOKEN, httponly=True, samesite="strict", path="/")
        return resp

    return await call_next(request)  # static UI files hold no secrets


# CORS is only needed for the Vite dev server; the production UI is same-origin.
# CORSMiddleware must be registered AFTER localhost_security_middleware
# so it wraps outermost and attaches CORS headers even on 401/403 responses.
if DEV_MODE:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(DEV_ORIGINS),
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


class VaultUnlockRequest(BaseModel):
    password: str = Field(..., min_length=1)


class EntryCreateRequest(BaseModel):
    title: str = Field(..., min_length=1)
    username: str = ""
    password: str = ""
    url: str = ""
    totp_secret: str = ""
    notes: str = ""


class VaultInitRequest(BaseModel):
    real_password: str = Field(..., min_length=1)
    duress_password: Optional[str] = None
    # Optional user-chosen decoy entries; a randomized plausible set is generated otherwise.
    decoy_entries: Optional[List[EntryCreateRequest]] = None


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
    # "vault": in-memory copy of the real vault file (rejected by ML-DSA-65 before any KDF).
    # "synthetic": throwaway lab container, so header/Slot 1 flips reach the AEAD layer.
    target: Literal["vault", "synthetic"] = "vault"


# --- 1. Vault Lifecycle (/api/vault) ---


@app.get("/api/vault/status")
def vault_status() -> Dict[str, Any]:
    return {
        "exists": vm.vault_path.exists(),
        "unlocked": vm.is_unlocked,
        "seq_num": vm._seq_num if vm.is_unlocked else 0,
    }


@app.post("/api/vault/init")
def vault_init(req: VaultInitRequest) -> Dict[str, Any]:
    with vm.mutex:
        decoys = [e.model_dump() for e in req.decoy_entries] if req.decoy_entries is not None else None
        vm.create_vault(req.real_password, duress_password=req.duress_password, decoy_entries=decoys)
        return {
            "status": "created",
            "seq_num": vm._seq_num,
            "size_bytes": vm.vault_path.stat().st_size,
        }


@app.post("/api/vault/unlock")
def vault_unlock(req: VaultUnlockRequest) -> Dict[str, Any]:
    t0 = time.perf_counter()
    vm.unlock(req.password)  # mode stays server-side; never returned to the client
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "status": "unlocked",
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
def get_pqc_public_key(manager: VaultManager = Depends(require_unlocked)) -> Dict[str, Any]:
    kp = manager.pqc_keypair
    return {
        "public_bundle": kp.export_public_bundle(),
        "size_bytes": len(kp.public_bundle_bytes()),
    }


@app.post("/api/pqc/encrypt")
def pqc_encrypt(req: PQCEncryptRequest, _: VaultManager = Depends(require_unlocked)) -> Dict[str, Any]:
    try:
        envelope = pqc_engine.encrypt_share(req.recipient_bundle, req.payload.encode("utf-8"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid recipient public key: {exc}") from exc
    return {"envelope": envelope}


@app.post("/api/pqc/decrypt")
def pqc_decrypt(req: PQCDecryptRequest, manager: VaultManager = Depends(require_unlocked)) -> Dict[str, str]:
    plaintext = pqc_engine.decrypt_share(manager.pqc_keypair, req.envelope)
    try:
        return {"plaintext": plaintext.decode("utf-8")}
    except UnicodeDecodeError as exc:
        raise DecryptionError("Shared payload is not valid UTF-8.") from exc


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

def _real_vault_copy() -> tuple[bytes, MLDSA65PublicKey, RollbackGuard]:
    """Reads the real vault into memory with a guard whose anchor mirrors the real one. Never writes."""
    if not vm.vault_path.exists() or not vm.pub_path.exists():
        raise HTTPException(status_code=404, detail="No vault file on disk yet.")
    signed = vm.vault_path.read_bytes()
    verify_key = MLDSA65PublicKey.from_public_bytes(vm.pub_path.read_bytes())
    anchor = MemoryAnchor()
    latest = vm.guard.local_anchor.get_latest(vm.vault_id)
    if latest is not None:
        anchor.set_latest(vm.vault_id, latest)
    return signed, verify_key, RollbackGuard(local_anchor=anchor)


def _verify_tampered_vault(attack: str, tampered: bytes, verify_key, guard: RollbackGuard, **extra) -> Dict[str, Any]:
    try:
        guard.verify_container(tampered, verify_key, vm.vault_id)
        return {"attack": attack, "caught": False, "target": "vault", **extra}
    except SignatureError as exc:
        return {
            "attack": attack,
            "caught": True,
            "layer": "ML-DSA-65 (FIPS 204)",
            "rejected_before_kdf": True,
            "target": "vault",
            "error": str(exc),
            **extra,
        }


@app.post("/api/tamper/bit-flip")
def tamper_bit_flip(req: BitFlipRequest) -> Dict[str, Any]:
    if req.target == "vault":
        signed, verify_key, guard = _real_vault_copy()
        return _verify_tampered_vault(
            "ciphertext_bit_flip", _flip_bit(signed, req.offset), verify_key, guard, offset=req.offset
        )

    c = VaultContainer()
    blob = c.build("lab_pw", b"tamper_lab_secret")

    # Header + Slot 1: isolate XChaCha20-Poly1305 AEAD layer
    if req.offset < HEADER_SIZE + SLOT_SIZE:
        tampered = _flip_bit(blob, req.offset)
        try:
            c.unlock("lab_pw", tampered)
            return {"attack": "ciphertext_bit_flip", "caught": False, "target": "synthetic", "offset": req.offset}
        except DecryptionError as exc:
            return {
                "attack": "ciphertext_bit_flip",
                "caught": True,
                "target": "synthetic",
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
        return {"attack": "ciphertext_bit_flip", "caught": False, "target": "synthetic", "offset": req.offset}
    except SignatureError as exc:
        return {
            "attack": "ciphertext_bit_flip",
            "caught": True,
            "target": "synthetic",
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
        return {"attack": "header_aad_tamper", "caught": False, "target": "synthetic"}
    except DecryptionError as exc:
        return {
            "attack": "header_aad_tamper",
            "caught": True,
            "target": "synthetic",
            "layer": "AEAD AAD Binding",
            "error": str(exc),
        }


@app.post("/api/tamper/signature")
def tamper_signature() -> Dict[str, Any]:
    signed, verify_key, guard = _real_vault_copy()
    return _verify_tampered_vault(
        "mldsa_sig_forge", _flip_bit(signed, SIGNED_CONTAINER_SIZE - 1), verify_key, guard
    )


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
        return {"attack": "rollback_replay", "caught": False, "target": "synthetic"}
    except RollbackDetectedError as exc:
        return {
            "attack": "rollback_replay",
            "caught": True,
            "target": "synthetic",
            "layer": "RollbackGuard",
            "error": str(exc),
        }


class DuressTimingRequest(BaseModel):
    trials: int = Field(default=30, ge=5, le=100)


@app.post("/api/tamper/duress-timing")
def tamper_duress_timing(req: DuressTimingRequest = DuressTimingRequest()) -> Dict[str, Any]:
    return {"target": "synthetic", **benchmark_unlock_timing(req.trials)}


# Built frontend served same-origin. Mounted last so /api routes take precedence.
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="ui")
