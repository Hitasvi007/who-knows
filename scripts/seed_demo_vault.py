"""Creates a believable demo vault for recording the README GIF.

Usage (from the repo root):
    python scripts/seed_demo_vault.py [--path demo.vault]

All entries are fictional services with obviously fake passwords.
"""

import argparse
import os
import sys
from pathlib import Path

# KDF parameters are not stored in the header, so a vault seeded with TESTING=1 parameters
# would not unlock on a normal daemon. Always seed with production parameters.
os.environ.pop("TESTING", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.storage.vault_manager import VaultExistsError, VaultManager  # noqa: E402

MASTER_PASSWORD = "demo-master-password-2026"
DURESS_PASSWORD = "demo-duress-2026"

DEMO_ENTRIES = [
    {"title": "Northwind Bank", "username": "alex.demo", "password": "FAKE-demo-bank-pass-01", "url": "https://bank.northwind.example", "notes": "Demo entry, not a real account"},
    {"title": "Contoso Mail", "username": "alex.demo@contoso.example", "password": "FAKE-demo-mail-pass-02", "url": "https://mail.contoso.example"},
    {"title": "Fabrikam Cloud Console", "username": "alex-ops", "password": "FAKE-demo-cloud-pass-03", "url": "https://console.fabrikam.example", "notes": "Prod account (demo)"},
    {"title": "Tailspin Git Hosting", "username": "alexdemo", "password": "FAKE-demo-git-pass-04", "url": "https://git.tailspin.example"},
    {"title": "Woodgrove Health Portal", "username": "alex.d", "password": "FAKE-demo-health-pass-05", "url": "https://portal.woodgrove.example"},
    {"title": "Adatum Home Router", "username": "admin", "password": "FAKE-demo-router-pass-06", "url": "http://192.0.2.1", "notes": "Documentation-range IP, not a real device"},
    {"title": "Litware Streaming", "username": "alex.demo@contoso.example", "password": "FAKE-demo-stream-pass-07", "url": "https://watch.litware.example"},
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", default="demo.vault", help="vault file to create (default: demo.vault)")
    args = parser.parse_args()
    path = Path(args.path)

    vm = VaultManager(path)
    try:
        vm.create_vault(MASTER_PASSWORD, duress_password=DURESS_PASSWORD)
    except VaultExistsError:
        print(f"Refusing to overwrite existing {path} (or {path}.pub). Delete it first.", file=sys.stderr)
        return 1

    for entry in DEMO_ENTRIES:
        vm.db.add_entry(**entry)
    seq = vm.save()
    vm.lock()

    print(f"Created {path} ({len(DEMO_ENTRIES)} entries, seq {seq}).")
    print(f"  master password: {MASTER_PASSWORD}")
    print(f"  duress password: {DURESS_PASSWORD}")
    print("\nStart the daemon against it:")
    print(f'  PowerShell: $env:WHOKNOWS_VAULT_PATH = "{path}"; uvicorn backend.api.main:app --host 127.0.0.1 --port 8000')
    print(f"  bash:       WHOKNOWS_VAULT_PATH={path} uvicorn backend.api.main:app --host 127.0.0.1 --port 8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
