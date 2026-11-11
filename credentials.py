import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


_KEY_CHECK = b"password-manager AES-GCM vault v1"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_KDF_MEMORY_KIB = 64 * 1024
_KDF_ITERATIONS = 3
_KDF_LANES = 4

# SQLite credential storage with AES-256-GCM for the password manager.

class VaultUnlockError(ValueError):
    "The master password or vault metadata could not unlock the vault"


def _cipher_for(master_password: str, salt: bytes) -> AESGCM:
    kdf = Argon2id(salt=salt, length=32, iterations=_KDF_ITERATIONS, lanes=_KDF_LANES, memory_cost=_KDF_MEMORY_KIB)
    key = kdf.derive(master_password.encode("utf-8"))
    return AESGCM(key)

def _encrypt(cipher: AESGCM, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(_NONCE_SIZE)
    return nonce + cipher.encrypt(nonce, plaintext, None)

def _decrypt(cipher: AESGCM, encrypted: bytes) -> bytes:
    if len(encrypted) < _NONCE_SIZE + _TAG_SIZE:
        raise InvalidTag("The encrypted record is truncated")
    nonce = encrypted[:_NONCE_SIZE]
    return cipher.decrypt(nonce, encrypted[_NONCE_SIZE:], None)

class CredentialVault:
    "An unlocked credential store scoped to one authenticated user"

    def __init__(self, database_path: str | Path, user_id: str, master_password: str):
        if not user_id:
            raise ValueError("A stable user ID is required")
        self._database_path = database_path
        self._user_id = user_id

        with closing(sqlite3.connect(database_path)) as db, db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS vaults (
                    user_id TEXT PRIMARY KEY NOT NULL,
                    salt BLOB NOT NULL,
                    key_check BLOB NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    encrypted_entry BLOB NOT NULL
                )
            """)
            select_vault = "SELECT salt, key_check FROM vaults WHERE user_id = ?"
            stored_vault = db.execute(select_vault, (user_id,)).fetchone()
            if stored_vault is None:
                salt = secrets.token_bytes(16)
                cipher = _cipher_for(master_password, salt)
                inserted = db.execute(
                    """
                    INSERT INTO vaults (user_id, salt, key_check)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id) DO NOTHING
                    """,
                    (user_id, salt, _encrypt(cipher, _KEY_CHECK)),
                )
                if inserted.rowcount == 1:
                    self._cipher = cipher
                    return
                stored_vault = db.execute(select_vault, (user_id,)).fetchone()

        salt, key_check = stored_vault
        self._cipher = _cipher_for(master_password, salt)
        try:
            marker = _decrypt(self._cipher, key_check)
        except InvalidTag as error:
            raise VaultUnlockError("Could not unlock the credential vault") from error
        if marker != _KEY_CHECK:
            raise VaultUnlockError("Could not unlock the credential vault")

    def add_credential(self, service: str, username: str, password: str) -> int:
        "Encrypt and save an entry, returning its database ID"
        if not service.strip() or not username.strip() or not password:
            raise ValueError("Service, username and password are required")
        entry = {"service": service, "username": username, "password": password}
        encrypted_entry = _encrypt(self._cipher, json.dumps(entry).encode("utf-8"))
        with closing(sqlite3.connect(self._database_path)) as db, db:
            cursor = db.execute(
                "INSERT INTO credentials (user_id, encrypted_entry) VALUES (?, ?)",
                (self._user_id, encrypted_entry),
            )
            return cursor.lastrowid
        
    def get_credential(self, credential_id: int) -> dict[str, str]:
        "Retrieve and decrypt an entry owned by this user"
        with closing(sqlite3.connect(self._database_path)) as db:
            row = db.execute(
                "SELECT encrypted_entry FROM credentials WHERE user_id = ? AND id = ?",
                (self._user_id, credential_id),
            ).fetchone()

        if row is None:
            raise KeyError(credential_id)

        return json.loads(_decrypt(self._cipher, row[0]))    