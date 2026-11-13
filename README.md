# Password Manager
A Python password manager that allows users to add, view, edit and delete saved details. The application will use a master password to control access and encryption to protect stored account information.


## Setup

From the `password_manager` directory, install the dependencies:

```bash
pip install -r requirements.txt
```

Start the demo from the same directory:

```bash
uvicorn main:app --reload
```
Start the FastAPI server:
python -m uvicorn backend.main:app --reload


Then open http://127.0.0.1:8000.

Run the backend tests from the tests directory in backend:

```bash
pytest test_account_setup.py tests_hashing.py
```

## Password hashing

Use `hash_master_password` to create a hash and store the returned value, not a plaintext password. Argon2 generates a random salt automatically and includes it in the encoded hash.

`login_master_password` returns a boolean to verify whether the password matches the stored password, and the rehashed password in the case that Argon2 configuration changes.

## Credential vault

After a successful login, create a `CredentialVault` with the path to
`vault.db`, the authenticated user's ID, and their master password.
Keep the vault instance for the session and discard it on logout.

- `add_credential(service, username, password)` encrypts and saves an
  entry, then returns its ID.
- `get_credential(credential_id)` retrieves and decrypts an entry
  owned by the authenticated user.