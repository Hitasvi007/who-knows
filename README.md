# whoknows

An offline, local-only password manager paired with an **Interactive Tamper Lab**—a built-in adversarial console that fires live cryptographic attacks (bit-flipping, header AAD mutation, ML-DSA-65 signature forgery, rollback replays, and timing probes) against an in-memory clone of your vault container.

> **Status:** Unaudited security engineering project built for learning and adversarial testing. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for trust anchors, attacker boundaries, and known limitations.

<!-- Replace with a 30-second screen recording of the Tamper Lab in action -->
<!-- ![whoknows Interactive Tamper Lab Demo](docs/tamper-lab-demo.gif) -->

---

## Why This Exists

Most portfolio password managers stop at basic CRUD over AES. `whoknows` is designed around **verifiable failure modes**:

- **Interactive Tamper Lab:** Inspect the live 68,909-byte container layout, measure Slot 1 vs. Slot 2 Shannon entropy, flip any single bit across the container, and watch `XChaCha20-Poly1305`, `ML-DSA-65`, or `RollbackGuard` reject the attack in real time.
- **Verify-Before-Decrypt:** Validates the `ML-DSA-65` signature and monotonic `seq_num` before invoking `Argon2id`, neutralizing cryptographic DoS and untrusted-input oracles.
- **Fixed-Size Length-Hiding Container:** Every vault is padded to exactly `68,909` bytes (64B header + two 32 KB slots + 3,309B signature) to hide entry count and vault growth.
- **Hybrid Post-Quantum Sharing:** Uses `X25519 + ML-KEM-768` hybrid key encapsulation for offline credential sharing—targeting the *harvest-now, decrypt-later* threat where PQ actually matters.
- **Hardened Localhost Daemon:** Defends `127.0.0.1:8000` against DNS rebinding (`Host` header allowlist) and unauthorized callers (per-session 256-bit `X-Vault-Token` verified in constant time).
- **Fuzzed Binary Parser:** Property-based fuzzing with `hypothesis` across arbitrary, exact-size, and mutated byte streams with zero unhandled crashes.

---

## Architecture

- **Backend (`backend/`):** Python 3.11 + FastAPI (`127.0.0.1:8000`), in-memory SQLite, atomic disk writes (`.tmp` → `fsync` → `replace`).
- **Cryptography:** `argon2-cffi` (Argon2id), `cryptography` / `PyNaCl` (XChaCha20-Poly1305, X25519), `liboqs` (ML-DSA-65, ML-KEM-768).
- **Frontend (`frontend/`):** React, TypeScript, Vite, Tailwind CSS, Framer Motion (`127.0.0.1:5173`).

For detailed trust boundaries and limitations (including Python RAM hygiene and ephemeral duress limits), read [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## Quickstart

### 1. Backend Daemon

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
```

On startup, the daemon generates an ephemeral 256-bit session token and writes it to `frontend/.env.local` (gitignored).

### 2. Frontend UI

```powershell
cd frontend
npm install
npm run dev
```

Open **`http://127.0.0.1:5173`**.

### 3. Run Tests & Container Fuzzer

```powershell
pytest -v
```