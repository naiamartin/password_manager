from backend.password_hashing import hash_master_password, login_master_password


def test_master_password_hashing():
    password = "masterPassword@3x4ml3."
    hashed = hash_master_password(password)

    # Updated: login checks a second input to see if it needs renewal
    valid, _ = login_master_password(password, hashed)
    invalid, _ = login_master_password("wrong_password", hashed)

    assert valid is True
    assert invalid is False
