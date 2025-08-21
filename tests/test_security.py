import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from security import encrypt_data, decrypt_data


def test_encrypt_decrypt_roundtrip():
    data = b"super secret"
    password = "mypassword"
    token = encrypt_data(data, password)
    assert token != data
    result = decrypt_data(token, password)
    assert result == data
