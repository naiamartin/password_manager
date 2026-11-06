# Password Manager
A Python password manager that allows users to add, view, edit and delete saved login details. The application will use a master password to control access and encryption to protect stored account information.

The current prototype includes master password hashing and verification with Argon2

## Setup

From the project root (password_manager), install the dependencies:

```bash
pip install -r requirements.txt
```

Run the tests from the project root:

```bash
pytest tests.py
```

## Password hashing

Use `hash_master_password` to create a hash and store the returned value, not a plaintext password. Argon2 generates a random salt automatically and includes it in the encoded hash.

`login_master_password` returns a boolean to verify whether the password matches the stored password.
