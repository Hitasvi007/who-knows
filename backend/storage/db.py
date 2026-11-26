import sqlite3
import time
import uuid
import zlib
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    totp_secret TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
"""


@dataclass
class VaultEntry:
    id: str
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    totp_secret: str = ""
    notes: str = ""
    created_at: int = 0
    updated_at: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VaultDB:
    """Zero-disk in-memory SQLite vault with compressed binary serialization."""

    def __init__(self, conn: Optional[sqlite3.Connection] = None) -> None:
        if conn is None:
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(SCHEMA_SQL)
            self.conn.commit()
        else:
            self.conn = conn
            self.conn.row_factory = sqlite3.Row

    # --- Binary Serialization (for VaultContainer slots) ---

    def export_bytes(self) -> bytes:
        """Serializes the in-memory SQLite DB to compressed bytes for slot encryption."""
        self.conn.commit()
        raw_db = self.conn.serialize()
        return zlib.compress(raw_db, level=6)

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultDB":
        """Rehydrates an in-memory SQLite DB from decrypted slot bytes."""
        raw_db = zlib.decompress(data)
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.deserialize(raw_db)
        return cls(conn=conn)

    # --- Credential CRUD ---

    def add_entry(
        self,
        title: str,
        username: str = "",
        password: str = "",
        url: str = "",
        totp_secret: str = "",
        notes: str = "",
    ) -> VaultEntry:
        now = int(time.time())
        entry = VaultEntry(
            id=str(uuid.uuid4()),
            title=title,
            username=username,
            password=password,
            url=url,
            totp_secret=totp_secret,
            notes=notes,
            created_at=now,
            updated_at=now,
        )
        self.conn.execute(
            """
            INSERT INTO entries (id, title, username, password, url, totp_secret, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.totp_secret,
                entry.notes,
                entry.created_at,
                entry.updated_at,
            ),
        )
        self.conn.commit()
        return entry

    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        row = self.conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return VaultEntry(**dict(row)) if row else None

    def list_entries(self, query: Optional[str] = None) -> List[VaultEntry]:
        if query:
            pattern = f"%{query}%"
            rows = self.conn.execute(
                "SELECT * FROM entries WHERE title LIKE ? OR username LIKE ? OR url LIKE ? ORDER BY title ASC",
                (pattern, pattern, pattern),
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM entries ORDER BY title ASC").fetchall()
        return [VaultEntry(**dict(r)) for r in rows]

    def update_entry(self, entry_id: str, **fields: Any) -> Optional[VaultEntry]:
        allowed = {"title", "username", "password", "url", "totp_secret", "notes"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_entry(entry_id)

        updates["updated_at"] = int(time.time())
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        values = list(updates.values()) + [entry_id]

        cur = self.conn.execute(f"UPDATE entries SET {set_clause} WHERE id = ?", values)
        self.conn.commit()
        return self.get_entry(entry_id) if cur.rowcount > 0 else None

    def delete_entry(self, entry_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # --- Internal Vault Metadata (e.g., Hybrid PQC Keypair, Vault ID) ---

    def set_meta(self, key: str, value: bytes) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[bytes]:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return bytes(row["value"]) if row else None

    def close(self) -> None:
        self.conn.close()