# Password Manager
A Python password manager that allows users to create an account, log in, and add, view, edit and delete saved account details. A master password controls access, and encryption protects the saved details.


## Setup

From the `password_manager` directory, install the dependencies:

```bash
pip install -r requirements.txt
```

Start the demo from the same directory:

```bash
uvicorn backend.main:app --reload
```

Then open http://127.0.0.1:8000.

The app uses `users.db` in the `password_manager` directory for user and vault data.

Run the backend tests from the `password_manager` directory:

```bash
python -m pytest backend/tests/test_account_setup.py backend/tests/tests_hashing.py
```

## Libraries used

- `argon2-cffi` for hashing the master password.
- `pytest` runs the tests
- `cryptography` used to encrypt and decrypt saved account details
- `fastapi` used to create the app (connects backend with frontend)
- `uvicorn` runs the app on a local server
- `python-multipart` used to read data from the forms
- `jinja2` used to show the HTML pages and messages
- `flake8` used for python styling
- `UUID` used for providing unique username identifiers

## Password hashing

`hash_master_password` creates a hash and stores the returned value, not a plaintext password. Argon2 generates a random salt automatically and includes it in the encoded hash.

`login_master_password` returns whether the password matches and a new hash if the Argon2 settings have changed.

The master password must be at least 12 characters long.

## Credential vault

After a successful login a `CredentialVault` is created using `users.db`,
the authenticated user's ID, and their master password. The vault uses Argon2id
to provide a key and AES-GCM to encrypt account details.

- `add_credential(platform_name, username, password)` encrypts and saves an
  entry then returns its ID.
- `get_credential(credential_id)` retrieves and decrypts an entry
  owned by the authenticated user.
- `show_credentials()` shows the saved account names and usernames.
- `edit_credential(credential_id, platform_name, username, password)` updates an entry.
- `delete_credential(credential_id)` deletes an entry.

The app keeps the vault for the logged-in session.
