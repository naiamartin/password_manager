#imports
import pytest
import account_setup #what i need for the tests

#Reference:
#pytest documentation, "How to use fixtures"
#https://docs.pytest.org/en/stable/how-to/fixtures.html
#Accessed: 10th November 2026

@pytest.fixture
#something my tests can use
def database_path(tmp_path): #provided by pytest
    """Create a separate test database for each test to provent issues."""
    path = tmp_path / "test_accounts.db"
    account_setup.initialise_database(path)
    account_setup.current_user_id = None
    return str(path)

#Create new user
def test_register_new_user(database_path):
    success, message = account_setup.register_user(
        database_path, "john", "SecurePassword123!"
    )

    assert success is True

#Test a user that already exists
def test_register_duplicate_user(database_path):
    account_setup.register_user(
        database_path, "john", "SecurePassword123!"
    )

    success, message = account_setup.register_user(
        database_path, "john", "AnotherPassword123!"
    )

    assert success is False

#A unknown username
def test_login_unknown_username(database_path):
    success, message = account_setup.login_user(
        database_path, "unknown_user", "SecurePassword123!"
    )

    assert success is False
    assert message == "Invalid username or password."

#A blank username
def test_register_empty_username(database_path):
    success, message = account_setup.register_user(
        database_path, "   ", "SecurePassword123!"
    )

    assert success is False
    assert message == "Please enter a username."

#Password too short
def test_register_short_password(database_path):
    success, message = account_setup.register_user(
        database_path, "john", "short"
    )

    assert success is False

#Correct password
def test_login_correct_password(database_path):
    account_setup.register_user(
        database_path, "john", "SecurePassword123!"
    )

    success, user_id = account_setup.login_user(
        database_path, "john", "SecurePassword123!"
    )

    assert success is True
    assert account_setup.current_user_id == user_id

#Incorrect password
def test_login_incorrect_password(database_path):
    account_setup.register_user(
        database_path, "john", "SecurePassword123!"
    )

    success, message = account_setup.login_user(
        database_path, "john", "WrongPassword123!"
    )

    assert success is False

#Log out functionality
def test_logout(database_path):
    account_setup.register_user(
        database_path, "john", "SecurePassword123!"
    )

    account_setup.login_user(
        database_path, "john", "SecurePassword123!"
    )

    account_setup.logout_user()

    assert account_setup.current_user_id is None