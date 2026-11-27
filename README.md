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

## What the Tamper Lab Proves

Each row is one attack, the layer that stops it, and the test that fails if that layer breaks. "Your vault copy" means the attack runs on an in-memory copy of the real `.vault` file. "Synthetic" means a throwaway lab container, used where the attack needs a password or file history.

| Attack | Target | Region / offset | Layer that rejects it | Rejected before Argon2id? | Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1-bit flip | Your vault copy | Header (offset 10) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_real_vault_copy[10]` |
| 1-bit flip | Your vault copy | Slot 1 (offset 250) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_real_vault_copy[250]` |
| 1-bit flip | Your vault copy | Slot 2 (offset 40,000) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_real_vault_copy[40000]` |
| 1-bit flip | Your vault copy | Signature (offset 68,000) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_real_vault_copy[68000]` |
| 1-bit flip | Synthetic | Header (offset 10, Argon2id salt) | XChaCha20-Poly1305 (wrong KEK, DEK unwrap fails) | No | `tests/test_api.py::test_tamper_bit_flip_every_region_synthetic[header]` |
| 1-bit flip | Synthetic | Slot 1 (offset 250) | XChaCha20-Poly1305 (Poly1305 tag) | No | `tests/test_api.py::test_tamper_bit_flip_every_region_synthetic[slot1]` |
| 1-bit flip | Synthetic | Slot 2 (offset 40,000) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_every_region_synthetic[slot2]` |
| 1-bit flip | Synthetic | Signature (offset 68,000) | ML-DSA-65 signature | Yes | `tests/test_api.py::test_tamper_bit_flip_every_region_synthetic[signature]` |
| Header AAD mutation | Synthetic | `seq_num` field (bytes 22–29) | AEAD AAD binding (header bound to both slots) | No | `tests/test_adversarial.py::test_header_aad_tampering_rejected` |
| Signature forgery | Your vault copy | Last signature byte | ML-DSA-65 signature | Yes | `tests/test_adversarial.py::test_mldsa_signature_tampering_rejected` |
| Rollback replay | Synthetic | Whole file (older signed seq) | Rollback anchor (`seq_num` behind anchor) | Yes | `tests/test_adversarial.py::test_rollback_attack_detected` |
| Fork / equivocation | Not in the Lab (test only) | Whole file (different signed state, same seq) | Rollback anchor (state-hash mismatch) | Yes | `tests/test_adversarial.py::test_fork_equivocation_attack_detected` |
| Forward-dated file | Not in the Lab (test only) | Whole file (validly signed, seq ahead, not chained) | Rollback anchor, exact match in `strict_local` mode | Yes | `tests/test_adversarial.py::test_unanchored_forward_seq_rejected_in_strict_mode[True]` |
| Duress timing probe | Synthetic | — | One Argon2id pass per unlock + dummy slot decrypt on wrong password | n/a (medians within 10%) | `tests/test_adversarial.py::test_duress_unlock_single_kdf_pass` |

The Lab's one-click buttons (Header AAD, Forge Sig, Rollback, timing probe) are also exercised end to end through the API by `tests/test_api.py::test_tamper_lab_endpoints`.

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