from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# TODO when User is created hash their stored password with these functions and store the hash in the database. 
# When they log in, verify their password with the stored hash.

# TODO consider changing method name to apply to all passwords, not just master password

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
        return False
    # If Argon2 configuration were to change, a check_needs_rehash() call would be needed here
    # to rehash the password with the new configuration, but for this prototype it's not needed
    return True

def basic_security_check(password):
    # Check if the password meets the minimum length requirement
    return len(password) >= MIN_PASSWORD_LENGTH

