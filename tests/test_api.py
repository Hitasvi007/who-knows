import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["TESTING"] = "1"

import backend.api.main as api_main
from backend.crypto.rollback import SIGNED_CONTAINER_SIZE, MemoryAnchor, RollbackGuard
from backend.storage.vault_manager import VaultManager
from backend.api.main import SESSION_TOKEN, app

@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Provides a TestClient wired to an isolated temp vault and in-memory rollback anchor."""
    vault_path = tmp_path / "api_test.vault"
    isolated_vm = VaultManager(
        vault_path=vault_path,
        vault_id="api_test_vault",
        guard=RollbackGuard(local_anchor=MemoryAnchor()),
    )
    monkeypatch.setattr(api_main, "vm", isolated_vm)
    with TestClient(
        api_main.app, headers={"X-Vault-Token": api_main.SESSION_TOKEN}
    ) as test_client:
        yield test_client

# --- 1. Vault Lifecycle & Status Codes ---


def test_locked_vault_returns_423(client: TestClient):
    status = client.get("/api/vault/status").json()
    assert status["exists"] is False
    assert status["unlocked"] is False

    resp = client.get("/api/entries")
    assert resp.status_code == 423


def test_vault_init_lock_unlock_and_wrong_password(client: TestClient):
    init_resp = client.post(
        "/api/vault/init",
        json={"real_password": "real_pw", "duress_password": "decoy_pw"},
    )
    assert init_resp.status_code == 200
    assert init_resp.json()["size_bytes"] == SIGNED_CONTAINER_SIZE
    assert init_resp.json()["seq_num"] == 1

    assert client.post("/api/vault/lock").status_code == 200
    assert client.get("/api/vault/status").json()["unlocked"] is False

    # Wrong password -> 401 Unauthorized (DecryptionError)
    bad_resp = client.post("/api/vault/unlock", json={"password": "wrong_pw"})
    assert bad_resp.status_code == 401

    # Real password -> 200 OK
    real_resp = client.post("/api/vault/unlock", json={"password": "real_pw"})
    assert real_resp.status_code == 200
    assert real_resp.json()["mode"] == "real"


def test_vault_init_twice_returns_409_and_keeps_vault(client: TestClient):
    assert client.post("/api/vault/init", json={"real_password": "real_pw"}).status_code == 200
    before = api_main.vm.vault_path.read_bytes()
    before_pub = api_main.vm.pub_path.read_bytes()

    resp = client.post("/api/vault/init", json={"real_password": "other_pw"})
    assert resp.status_code == 409
    assert api_main.vm.vault_path.read_bytes() == before
    assert api_main.vm.pub_path.read_bytes() == before_pub


# --- 2. Credential CRUD & Duress Mode ---


def test_entries_crud_and_search(client: TestClient):
    client.post("/api/vault/init", json={"real_password": "real_pw"})

    # Create
    create_resp = client.post(
        "/api/entries",
        json={
            "title": "GitHub",
            "username": "hitasvi",
            "password": "pqc-password-123",
            "url": "https://github.com",
        },
    )
    assert create_resp.status_code == 201
    entry_id = create_resp.json()["entry"]["id"]
    assert create_resp.json()["seq_num"] == 2

    # List & search
    assert len(client.get("/api/entries").json()) == 1
    assert len(client.get("/api/entries?q=Git").json()) == 1
    assert len(client.get("/api/entries?q=nonexistent").json()) == 0

    # Update
    patch_resp = client.patch(
        f"/api/entries/{entry_id}",
        json={"password": "rotated-password-456"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["entry"]["password"] == "rotated-password-456"
    assert patch_resp.json()["seq_num"] == 3

    # Delete
    del_resp = client.delete(f"/api/entries/{entry_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True
    assert client.get("/api/entries").json() == []

    # 404 on missing entry
    assert client.delete(f"/api/entries/{entry_id}").status_code == 404


def test_duress_mode_via_api_is_ephemeral(client: TestClient):
    client.post(
        "/api/vault/init",
        json={"real_password": "real_pw", "duress_password": "decoy_pw"},
    )
    client.post("/api/vault/lock")

    unlock = client.post("/api/vault/unlock", json={"password": "decoy_pw"})
    assert unlock.status_code == 200
    assert unlock.json()["mode"] == "decoy"

    entries = client.get("/api/entries").json()
    assert len(entries) == 1
    assert entries[0]["title"] == "Local Wi-Fi"

    # Adding an entry in Duress Mode must not increment seq_num on disk
    add_resp = client.post("/api/entries", json={"title": "Fake", "password": "123"})
    assert add_resp.status_code == 201
    assert add_resp.json()["seq_num"] == 1


def test_concurrent_saves_do_not_fork_vault(client: TestClient):
    from concurrent.futures import ThreadPoolExecutor

    client.post("/api/vault/init", json={"real_password": "real_pw"})

    def create(i: int) -> int:
        return client.post("/api/entries", json={"title": f"Entry {i}", "password": "x"}).status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        assert list(pool.map(create, range(10))) == [201] * 10

    client.post("/api/vault/lock")
    unlock = client.post("/api/vault/unlock", json={"password": "real_pw"})
    assert unlock.status_code == 200, unlock.text
    assert unlock.json()["seq_num"] == 11
    assert len(client.get("/api/entries").json()) == 10


# --- 3. Security Exception Mapping (403 Signature / 409 Rollback) ---


def test_signature_error_returns_403(client: TestClient):
    client.post("/api/vault/init", json={"real_password": "real_pw"})
    client.post("/api/vault/lock")

    # Corrupt last byte of ML-DSA-65 signature on disk
    raw = bytearray(api_main.vm.vault_path.read_bytes())
    raw[-1] ^= 0x01
    api_main.vm.vault_path.write_bytes(bytes(raw))

    resp = client.post("/api/vault/unlock", json={"password": "real_pw"})
    assert resp.status_code == 403


def test_rollback_error_returns_409(client: TestClient):
    client.post("/api/vault/init", json={"real_password": "real_pw"})
    v1_backup = api_main.vm.vault_path.read_bytes()

    # Advance to seq 2
    client.post("/api/entries", json={"title": "Bank", "password": "secret"})
    client.post("/api/vault/lock")

    # Overwrite disk with older signed v1 backup
    api_main.vm.vault_path.write_bytes(v1_backup)

    resp = client.post("/api/vault/unlock", json={"password": "real_pw"})
    assert resp.status_code == 409


# --- 4. Hybrid Post-Quantum Sharing ---


def test_pqc_share_roundtrip(client: TestClient):
    pub = client.get("/api/pqc/public-key").json()
    assert pub["size_bytes"] == 1216
    assert pub["public_bundle"].startswith("wk_pub_")

    enc = client.post(
        "/api/pqc/encrypt",
        json={"recipient_bundle": pub["public_bundle"], "payload": "db_root_secret"},
    )
    assert enc.status_code == 200
    envelope = enc.json()["envelope"]

    dec = client.post("/api/pqc/decrypt", json={"envelope": envelope})
    assert dec.status_code == 200
    assert dec.json()["plaintext"] == "db_root_secret"


# --- 5. Interactive Tamper Lab Endpoints ---


def test_tamper_lab_endpoints(client: TestClient):
    client.post(
        "/api/vault/init",
        json={"real_password": "real_pw", "duress_password": "decoy_pw"},
    )

    inspect = client.get("/api/tamper/inspect").json()
    assert inspect["total_bytes"] == SIGNED_CONTAINER_SIZE
    assert inspect["slot1_entropy"] > 7.9
    assert inspect["slot2_entropy"] > 7.9

    assert client.post("/api/tamper/header-aad").json()["caught"] is True
    assert client.post("/api/tamper/signature").json()["caught"] is True
    assert client.post("/api/tamper/rollback").json()["caught"] is True

    timing = client.post("/api/tamper/duress-timing").json()
    assert timing["constant_time_pass"] is True


@pytest.mark.parametrize(
    "offset,layer",
    [
        (10, "XChaCha20-Poly1305"),  # header
        (250, "XChaCha20-Poly1305"),  # slot 1
        (40000, "ML-DSA-65 (FIPS 204)"),  # slot 2
        (68000, "ML-DSA-65 (FIPS 204)"),  # signature
    ],
)
def test_tamper_bit_flip_every_region(client: TestClient, offset: int, layer: str):
    resp = client.post("/api/tamper/bit-flip", json={"offset": offset})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["caught"] is True
    assert body["layer"] == layer


def test_tamper_bit_flip_out_of_range(client: TestClient):
    assert client.post("/api/tamper/bit-flip", json={"offset": SIGNED_CONTAINER_SIZE}).status_code == 422


def test_dns_rebinding_rejected():
    raw_client = TestClient(app)
    res = raw_client.get(
        "/api/vault/status",
        headers={"Host": "evil.com:8000", "X-Vault-Token": SESSION_TOKEN},
    )
    assert res.status_code == 403
    assert "DNS rebinding" in res.json()["detail"]


def test_missing_session_token_rejected():
    raw_client = TestClient(app)
    res = raw_client.get("/api/vault/status")
    assert res.status_code == 401
    assert "X-Vault-Token" in res.json()["detail"]