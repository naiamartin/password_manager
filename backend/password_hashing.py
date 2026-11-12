from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

#Reference:
#pytest documentation, "Argon2 in Python: Password Hashing Guide"
#https://mojoauth.com/security-guides/argon2-in-python 
#Accessed: 6th November 2026

PASSWORD_HASHER = PasswordHasher() if PasswordHasher is not None else None
MIN_PASSWORD_LENGTH = 12


def _require_password_hasher():
    if PASSWORD_HASHER is None:
        raise RuntimeError("argon2-cffi is required to hash passwords. Install it with: pip install argon2-cffi")
    return PASSWORD_HASHER


def hash_master_password(password):
    if not basic_security_check(password):
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    hasher = _require_password_hasher()
    # Hash the master password using Argon2Id
    stored = hasher.hash(password)
    return stored


def login_master_password(input_password: str, stored_hash: str):
    hasher = _require_password_hasher()
    # Verify the input password with the stored hash
    try:
        hasher.verify(stored_hash, input_password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None

    # In case Argon2 config changes
    if hasher.check_needs_rehash(stored_hash):
        # Rehash the password the user had stored
        # (e.g. user.password_hash when User exists)
        replace_hash = hasher.hash(input_password)
        return True, replace_hash

    return True, None


def basic_security_check(password):
    # Check if the password meets the minimum length requirement
    return len(password) >= MIN_PASSWORD_LENGTH
