# whoknows — Cryptographic Specification (v1.0)

## 1. Cryptographic Primitives

| Component | Algorithm | Parameters / Output Size | Purpose |
| :--- | :--- | :--- | :--- |
| **KDF** | Argon2id | 64 MiB RAM, 3 iterations, 4 lanes, 16B salt → 32B KEK | GPU/ASIC-resistant master key derivation |
| **AEAD** | XChaCha20-Poly1305 | 256-bit key, 192-bit (24B) nonce, 128-bit (16B) MAC | Envelope wrapping & vault slot encryption |
| **PQ Key Exchange** | Hybrid X25519 + ML-KEM-768 | X25519 (32B) + ML-KEM-768 (1,184B pk / 1,088B ct) + HKDF-SHA256 | Zero-knowledge one-time credential sharing |
| **PQ Signatures** | ML-DSA-65 (FIPS 204) | 1,952B pk, 3,309B signature | Tamper-evident hash chain & rollback detection |
| **State Hashing** | SHA-256 | 32B digest | Chaining vault states & external anchoring |

## 2. Binary Container Layout (`.vault`)

Total fixed container size: **68,909 bytes** (64B Header + 32,768B Slot 1 + 32,768B Slot 2 + 3,309B Signature).

```text
Offset      Length    Field
------------------------------------------------------------------------
0           4 B       Magic bytes: b"WKN1"
4           2 B       Format version (uint16, big-endian): 0x0001
6           16 B      Shared Argon2id salt (single KDF pass for both slots)
22          8 B       Monotonic sequence number (uint64, big-endian)
30          32 B      SHA-256 hash of previous vault state (all zeros on init)
62          2 B       Reserved (0x0000)
------------------------------------------------------------------------
64          32,768 B  Slot 1 (Real Vault)
                      ├─    DEK Wrap Nonce (24B)
                      ├─   Wrapped 32B DEK + 16B Poly1305 MAC (48B)
                      ├─   Payload Nonce (24B)
                      └─ [96:32768] Encrypted [4B len || SQLite dump || random pad] + 16B MAC
------------------------------------------------------------------------
32,832      32,768 B  Slot 2 (Decoy Vault — identical layout; os.urandom if disabled)
------------------------------------------------------------------------
65,600      3,309 B   ML-DSA-65 Signature over SHA-256(bytes[0:65600])
## 3. Planned: v2 Header With Stored KDF Parameters (design note, not implemented)

**Problem:** v1 never stores the Argon2id parameters. They are hardcoded in `CryptoEngine`, so they can never be raised without breaking every existing vault, and a vault built with `TESTING=1` parameters is indistinguishable on disk from a production one.

**Proposal:** Bump `VERSION` to `2` and reuse the 2-byte reserved field plus 8 new bytes. The header grows from 64B to 72B, so the container grows to 68,917 bytes:

```text
Offset  Length  Field
0       4 B     Magic b"WKN1"
4       2 B     Version 0x0002
6       16 B    Salt
22      8 B     seq_num
30      32 B    prev_hash
62      4 B     Argon2id memory cost, KiB (uint32 BE)
66      2 B     Argon2id iterations (uint16 BE)
68      2 B     Argon2id lanes (uint16 BE)
70      2 B     Reserved
```

- The parameters sit in the header, so they are covered by the AEAD AAD and the ML-DSA signature. An attacker can't downgrade them without detection.
- On unlock, reject parameters below a floor (for example 19 MiB, t=2, the OWASP minimum) **before** running the KDF. This stops a forged header from forcing a trivially cheap KDF, or an enormous memory cost as a DoS.
- On save, re-encrypt with the current default parameters, so vaults upgrade transparently after a successful unlock.
- Readers keep v1 support (hardcoded 64 MiB / t=3 / p=4) and write v2 on the next save. This needs a one-time `seq_num` advance, which the anchor accepts normally.
