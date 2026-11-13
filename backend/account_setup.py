# How this will work
# User enters a username
# Checks if the username already exists
# User enters a master password
# Password is hashed
# Stored

# imports
import sqlite3  # local database storage
import uuid  # unique user IDs
# import existing functions
from .password_hashing import (
    hash_master_password,
    login_master_password,
    basic_security_check
)
from .credentials import CredentialVault

# Session handling
current_user_id = None  # make sure the user id is set to none upon each session, clear storage


# Initialise database to store data locally
def initialise_database(database_path):
    with sqlite3.connect(database_path) as db:  # connect to it
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


# To Register a new user
def register_user(database_path, username, master_password):  # take in the username and master password
    username = username.strip()  # get rid of whitespace
    # if username is blank
    if not username:
        return False, "Please enter a username."
    # if the password doesn't meet security check function
    if not basic_security_check(master_password):
        return False, "Master password is not suitable. Please try again."

    with sqlite3.connect(database_path) as db:
        existing_user = db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        # if the username already exists
        if existing_user:
            return False, "User already exists."

        password_hash = hash_master_password(master_password)

        user_id = str(uuid.uuid4())

        db.execute(
            """
            INSERT INTO users (user_id, username, password_hash)
            VALUES (?, ?, ?)
            """,
            (user_id, username, password_hash)
        )

    return True, "Password management account created successfully."


# To login
def login_user(database_path, username, master_password):  # opens database: username + master password
    global current_user_id  # global variable to control sessions

    username = username.strip()  # get rid of whitespace
    # If there's no username or password
    if not username or not master_password:
        return False, "Please enter a username and password."

    with sqlite3.connect(database_path) as db:
        user = db.execute(
            "SELECT user_id, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()  # fetch the match
        # If there's not user
        if user is None:
            return False, "Invalid username or password."

        user_id, stored_hash = user
        # Verify the hashed password
        success, replacement_hash = login_master_password(
            master_password, stored_hash
        )
        # If it's not successful
        if not success:
            return False, "Invalid username or password."

        if replacement_hash:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (replacement_hash, user_id)
            )

        current_user_id = user_id  # setting the current user id to the user id

    return True, user_id  # return the info


# Open the user vault
def open_user_vault(database_path, master_password):
    if current_user_id is None:  # if there's no current user id
        raise ValueError("Please log in first.")
    # return the values
    return CredentialVault(
        database_path,
        current_user_id,
        master_password
    )


# Log out functionality
def logout_user():
    global current_user_id  # global variable

    current_user_id = None  # resetting it

    return "Successfully logged out."
