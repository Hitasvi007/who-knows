# Threat Model — `whoknows`

> **Disclaimer:** `whoknows` is an unaudited security engineering project built for cryptographic study and adversarial testing. Do not use it to store production credentials.

## 1. Security Goals & Cryptographic Primitives

| Layer | Primitive / Mechanism | Library | Purpose |
| :--- | :--- | :--- | :--- |
| **Key Derivation** | Argon2id | `cryptography` | Memory-hard password stretching against offline GPU/ASIC brute force. |
| **Vault Encryption** | XChaCha20-Poly1305 (256-bit) | `PyNaCl` | Authenticated encryption (AEAD) with 192-bit nonces and header AAD binding. |
| **Length Hiding** | Fixed 68,909-byte container | Custom (`container.py`) | Dual 32 KB padded slots hide entry count and vault growth on disk. |
| **Container Integrity** | ML-DSA-65 (FIPS 204) | `cryptography` | Verify-before-decrypt signature check to reject tampered containers before Argon2id runs. |
| **Rollback Protection** | Monotonic `seq_num` + `prev_hash` | Custom (`rollback.py`) | Detects stale container replays against a locally pinned anchor. |
| **Offline Sharing** | X25519 + ML-KEM-768 | `cryptography` | Hybrid key encapsulation protecting shared secrets against *harvest-now, decrypt-later* attacks. |
| **Local API Boundary** | `Host` check + one-time launch code + `HttpOnly; SameSite=Strict` session cookie | FastAPI | Blocks DNS rebinding and unauthorized local processes from calling `127.0.0.1:8000`. |

### What ML-DSA-65 Adds Over the Rollback Anchor
The ML-DSA signature is groundwork for multi-device sync. In single-device mode the private signing key (inside the encrypted vault) and `.vault.pub` sit next to the vault, and the **anchor equality check is the primary pre-KDF gate**: with `strict_local` (the default) and no remote anchor, the file's `seq_num` *and* state hash must equal the anchored values exactly, so any tampered, replayed, or forward-dated file is rejected before Argon2id. One exception keeps an interrupted save from locking the user out: a file exactly one `seq_num` ahead whose `prev_hash` equals the anchored hash is accepted, and the anchor is updated after a successful unlock. Producing such a file needs the signing key, which is stored inside the encrypted vault. A higher `seq_num` than the anchor is accepted only when a remote anchor is configured, the sync case where another device may legitimately have advanced the vault.

**TOFU gap:** If the OS keyring entry is missing (first run, keyring wiped, or vault copied to a new machine), there is nothing to compare against, and any validly signed file is accepted and becomes the new anchor.

### Where Post-Quantum Cryptography Actually Applies
A single-user vault encrypted with 256-bit `XChaCha20-Poly1305` already retains ~128 bits of effective security against Grover's algorithm. Post-quantum resistance is specifically critical in **Hybrid PQ Share (`X25519 + ML-KEM-768`)**, where an adversary can record classical key exchanges today and decrypt them once a cryptographically relevant quantum computer exists.

---

## 2. Attacker Model & Trust Anchors

| Attacker Capability | Defense | Trust Anchor / Condition |
| :--- | :--- | :--- |
| **Untrusted Storage / Sync Tampering** (modifies `.vault` in transit or on cloud storage) | ML-DSA-65 signature + XChaCha20-Poly1305 AEAD + `RollbackGuard` | **Requires out-of-band pinning:** The `.vault.pub` verification key and rollback anchor must remain trusted on the local device. If an attacker has full local disk write access, they can replace both the container and the anchor. |
| **Cryptographic DoS** (feeds forged containers to exhaust CPU/RAM) | Verify-before-decrypt | ML-DSA-65 verification runs and rejects invalid containers **before** Argon2id key derivation is invoked. |
| **Malicious Browser Tab (CSRF / DNS Rebinding)** | Strict `Host` header allowlist (`127.0.0.1:8000`, `localhost:8000`) + `SameSite=Strict` session cookie, same-origin UI | Rejects non-localhost `Host` headers (`403`) and missing/invalid sessions (`401`); cross-site requests never carry the cookie. Because browsers count every `localhost` port as the same site, API requests with any `Origin` other than the daemon's own (or Vite's in dev mode) are also rejected (`403`). Session checked using constant-time comparison (`secrets.compare_digest`). |
| **Unauthorized Local Process** | Per-session 256-bit random token in an `HttpOnly` cookie, issued once via a launch code printed to the daemon's console | Blocks local scripts that never saw the launch link. Does *not* stop a process that can read the daemon's console output, the browser's cookie store, or process memory (same user or root). **Dev mode (`WHOKNOWS_DEV=1`) is weaker:** the token is written to `frontend/.env.local` and compiled into the JavaScript the Vite dev server serves on `:5173`, so any local process, including other OS users, can fetch it. |
| **Single-Session Coercion** | Ephemeral Duress Mode (Slot 2) | Entering the duress password opens an in-memory decoy vault without decrypting or modifying Slot 1 on disk. |
| **Malformed Binary Input** | Strict bounds checking + Hypothesis fuzzing | Container unlock, signed-container verification, PQ share envelope decryption, and public-bundle parsing are fuzzed with arbitrary, exact-size, and mutated inputs; each may raise only its documented error types (`ValueError`, `DecryptionError`, `SignatureError`). Fuzzing does not prove the absence of bugs. |

---

## 3. Explicit Out-of-Scope & Known Limitations

1. **Compromised Host / Local Root:** If malware or a privileged attacker controls the host OS, they can keylog the master password, read the session cookie, or dump Python process memory. Localhost encryption cannot defend against a compromised endpoint.
2. **Python Memory Hygiene:** Decrypted credentials live in an in-memory SQLite database so no plaintext is written to disk. However, Python strings are immutable, the garbage collector copies objects, and `mlock`/guaranteed zeroization is not enforced. **This project does not claim forensic RAM immunity.**
3. **Active Multi-Session Coercion:** Duress mode is strictly ephemeral (changes in the decoy session are not persisted to disk so Slot 1 and `seq_num` remain untouched). An active coercer who adds a decoy entry, locks the vault, and unlocks it again will observe that the entry disappeared—exposing the duress password.
4. **Same-Disk Trust Anchor:** In default local development, `.vault.pub` and the rollback anchor reside on the same filesystem as `.vault`. In a real deployment, the verification key and rollback state must be pinned in an OS keystore or hardware-backed storage.
5. **PQ Share Has No Key or Sender Authentication:** The hybrid KEM provides confidentiality only. Nothing binds a `wk_pub_` bundle to a person, and envelopes are not signed, so a man-in-the-middle can swap the recipient's public bundle (and read the share), and anyone holding the recipient's public bundle can forge an envelope to them. The UI shows a short SHA-256 fingerprint of both bundles; users must compare it out of band (in person or by phone) before sharing.

### Known Duress-Mode Tells

The API never returns which slot was opened, decoy saves advance an in-memory sequence counter, and decoy entries are either user-supplied at init or drawn at random from a template pool (so no single fixed decoy fingerprint exists in the public source). The following tells remain:

- **Shared header sequence number:** Slot 1 and Slot 2 share the plaintext header, so the on-disk `seq_num` reflects every *real* save. A decoy vault with a handful of entries sitting on a container at `seq_num` 400 suggests a second, busier slot exists.
- **Multi-session coercion:** Decoy changes are RAM-only. An observer who adds an entry, locks, and unlocks again sees the entry (and the advanced sequence number) disappear. See item 3 above.
- **Randomized-pool decoys:** If the user does not supply their own decoy entries, the generated set is plausible but generic. An observer who knows the template pool can recognize it.
