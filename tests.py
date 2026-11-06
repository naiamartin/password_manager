from password_hashing import hash_master_password, login_master_password

def test_master_password_hashing():
    password = "masterPassword@3x4ml3."
    hashed = hash_master_password(password)

    assert login_master_password(password, hashed) is True
    assert login_master_password("wrong_password", hashed) is False
