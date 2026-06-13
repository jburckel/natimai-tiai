import uuid

from app.core import security


def test_agent_token_hash_roundtrip():
    """A generated agent token verifies against its stored hash."""
    token = security.generate_token()
    token_hash = security.hash_token(token)
    assert security.verify_token(token, token_hash)
    assert not security.verify_token("some-other-token", token_hash)


def test_agent_token_is_random():
    """Two generated tokens differ."""
    assert security.generate_token() != security.generate_token()


def test_password_hash_roundtrip():
    """A bcrypt-hashed password verifies, a wrong one does not."""
    hashed = security.get_password_hash("s3cret-passw0rd")
    assert security.verify_password("s3cret-passw0rd", hashed)
    assert not security.verify_password("wrong", hashed)


def test_jwt_roundtrip():
    """A created access token decodes back to its subject."""
    user_id = uuid.uuid4()
    token = security.create_access_token(user_id)
    payload = security.decode_access_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"
