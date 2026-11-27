# whoknows

[![CI](https://github.com/Hitasvi007/who-knows/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Hitasvi007/who-knows/actions/workflows/ci.yml)

An offline, local-only password manager paired with an **Interactive Tamper Lab**—a built-in adversarial console that fires live cryptographic attacks (bit-flipping, header AAD mutation, ML-DSA-65 signature forgery, rollback replays, and timing probes). Bit-flip and signature attacks run against an in-memory copy of your real vault file; demos that need a password or file history (AEAD layer, header AAD, rollback, timing) use a synthetic lab container and are labelled as such.

> **Status:** Unaudited security engineering project built for learning and adversarial testing. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for trust anchors, attacker boundaries, and known limitations.

<!-- Replace with a 30-second screen recording of the Tamper Lab in action -->
<!-- ![whoknows Interactive Tamper Lab Demo](docs/tamper-lab-demo.gif) -->

---

## Why This Exists

Most portfolio password managers stop at basic CRUD over AES. `whoknows` is designed around **verifiable failure modes**:

- **Interactive Tamper Lab:** Inspect the live 68,909-byte container layout, measure Slot 1 vs. Slot 2 Shannon entropy, flip any single bit across the container, and watch `XChaCha20-Poly1305`, `ML-DSA-65`, or `RollbackGuard` reject the attack in real time.
- **Verify-Before-Decrypt:** a tampered, replayed, or forward-dated vault file is rejected by the ML-DSA-65 signature and the rollback anchor before any Argon2id run.
- **Fixed-Size Length-Hiding Container:** Every vault is padded to exactly `68,909` bytes (64B header + two 32 KB slots + 3,309B signature) to hide entry count and vault growth.
- **Hybrid Post-Quantum Sharing:** Uses `X25519 + ML-KEM-768` hybrid key encapsulation for offline credential sharing—targeting the *harvest-now, decrypt-later* threat where PQ actually matters.
- **Hardened Localhost Daemon:** Defends `127.0.0.1:8000` against DNS rebinding (`Host` header allowlist) and unauthorized callers (one-time launch link exchanged for a per-session 256-bit `HttpOnly; SameSite=Strict` cookie, verified in constant time).
- **Fuzzed Parsers:** Property-based fuzzing with `hypothesis` of `VaultContainer.unlock` (arbitrary, exact-size, and single-byte-mutated Header/Slot 1 input), `RollbackGuard.verify_container` (arbitrary, exact-size, and mutated signed containers), `HybridShareEngine.decrypt_share` (arbitrary envelope shapes and field values), and `_parse_public_bundle`. Each is asserted to raise only its documented error types.

---

## Architecture

- **Backend (`backend/`):** Python 3.11 + FastAPI (`127.0.0.1:8000`), in-memory SQLite, atomic disk writes (`.tmp` → `fsync` → `replace`).
- **Cryptography:** `cryptography` >= 48 (Argon2id, X25519, ML-DSA-65, ML-KEM-768, HKDF-SHA256), `PyNaCl` (XChaCha20-Poly1305).
- **Frontend (`frontend/`):** React, TypeScript, Vite, Tailwind CSS, Framer Motion. Built to `frontend/dist` and served by the daemon; Vite on `127.0.0.1:5173` in dev mode only.

For detailed trust boundaries and limitations (including Python RAM hygiene and ephemeral duress limits), read [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## Quickstart

### 1. Build the Frontend

```powershell
cd frontend
npm install
npm run build
cd ..
```

### 2. Run the Daemon

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

The daemon serves the built UI on the same origin and prints a one-time link, `http://127.0.0.1:8000/?launch=...`. Open it. The first request exchanges the code for an `HttpOnly` session cookie, and the code then stops working.

### Dev Mode (Vite Hot Reload)

```powershell
$env:WHOKNOWS_DEV = "1"
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Then run `npm run dev` in `frontend/` and open `http://127.0.0.1:5173`. In dev mode the daemon writes the session token to `frontend/.env.local` and accepts it as an `X-Vault-Token` header. Vite compiles it into the JavaScript it serves, so **any local process can read it**. Use dev mode for development only.

### 3. Run Tests & Container Fuzzer

```powershell
pytest -v
```