from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

#Reference:
#pytest documentation, "Argon2 in Python: Password Hashing Guide"
#https://mojoauth.com/security-guides/argon2-in-python 
#Accessed: 6th November 2026

PASSWORD_HASHER = PasswordHasher()
MIN_PASSWORD_LENGTH = 12


def hash_master_password(password):
    if not basic_security_check(password):
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    # Hash the master password using Argon2Id
    stored = PASSWORD_HASHER.hash(password)
    return stored


def login_master_password(input_password: str, stored_hash: str):
    # Verify the input password with the stored hash
    try:
        PASSWORD_HASHER.verify(stored_hash, input_password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None

    # In case Argon2 config changes
    if PASSWORD_HASHER.check_needs_rehash(stored_hash):
        # Rehash the password the user had stored
        # (e.g. user.password_hash when User exists)
        replace_hash = PASSWORD_HASHER.hash(input_password)
        return True, replace_hash

    return True, None


def basic_security_check(password):
    # Check if the password meets the minimum length requirement
    return len(password) >= MIN_PASSWORD_LENGTH
