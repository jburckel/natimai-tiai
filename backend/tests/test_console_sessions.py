"""Console sessions: short access token, rotating refresh cookie, lockout
(require TIAI_TEST_DATABASE_URL)."""

from app.core.config import settings

ADMIN = "admin@test.local"
PASSWORD = "an-admin-password-long-enough"


async def _admin(db_session, email: str = ADMIN, role: str = "admin"):
    from app.features.user import crud
    from app.features.user.models import Role

    return await crud.create_user(
        db_session, email=email, password=PASSWORD, role=Role(role)
    )


async def _login(client, email: str = ADMIN, password: str = PASSWORD):
    return await client.post(
        "/api/v1/auth/login", data={"username": email, "password": password}
    )


def _bearer(resp) -> dict[str, str]:
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def test_login_sets_an_httponly_refresh_cookie_on_the_auth_path(
    client, db_session
):
    await _admin(db_session)
    resp = await _login(client)
    assert resp.status_code == 200
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith(f"{settings.REFRESH_COOKIE_NAME}=")
    assert "HttpOnly" in cookie
    assert "Path=/api/v1/auth" in cookie
    assert "SameSite=strict" in cookie
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(resp))
    ).status_code == 200


async def test_refresh_rotates_and_a_replayed_cookie_ends_the_family(
    client, db_session, monkeypatch
):
    await _admin(db_session)
    await _login(client)
    stolen = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    renewed = await client.post("/api/v1/auth/refresh")
    assert renewed.status_code == 200
    assert client.cookies.get(settings.REFRESH_COOKIE_NAME) != stolen

    # Within the grace window, the stale cookie is a race between two tabs:
    # told to retry, nothing revoked.
    raced = await client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: stolen}
    )
    assert raced.status_code == 409
    assert raced.json()["error"]["code"] == "auth.refresh.superseded"

    # Past it, the same replay is a copy: the whole family goes, the owner's
    # current cookie included.
    monkeypatch.setattr(settings, "REFRESH_REUSE_GRACE_SECONDS", -1)
    replay = await client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: stolen}
    )
    assert replay.status_code == 401
    current = await client.post("/api/v1/auth/refresh")
    assert current.status_code == 401


async def test_logout_revokes_the_refresh_cookie(client, db_session):
    await _admin(db_session)
    await _login(client)
    cookie = client.cookies.get(settings.REFRESH_COOKIE_NAME)
    assert (await client.post("/api/v1/auth/logout")).status_code == 204
    after = await client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: cookie}
    )
    assert after.status_code == 401


async def test_login_is_case_insensitive_on_the_email(client, db_session):
    await _admin(db_session, email="Mixed.Case@Test.Local")
    resp = await _login(client, email="MIXED.case@test.local")
    assert resp.status_code == 200


async def test_unknown_email_and_wrong_password_answer_alike(client, db_session):
    await _admin(db_session)
    unknown = await _login(client, email="nobody@test.local")
    wrong = await _login(client, password="not-the-password")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["error"]["code"] == wrong.json()["error"]["code"]


async def test_account_locks_after_repeated_failures(client, db_session):
    await _admin(db_session)
    for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS - 1):
        assert (await _login(client, password="wrong-password")).status_code == 401
    locking = await _login(client, password="wrong-password")
    assert locking.status_code == 423
    assert locking.json()["error"]["code"] == "auth.account.locked"
    assert "locked_until" in locking.json()["error"]["details"]

    # Locked: even the right password is refused until it lifts.
    assert (await _login(client)).status_code == 423


async def test_admin_password_reset_lifts_a_lock_and_audits_it(client, db_session):
    await _admin(db_session)
    await _admin(db_session, email="operator@test.local", role="readonly")
    for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS):
        await _login(client, email="operator@test.local", password="wrong-password")
    assert (await _login(client, email="operator@test.local")).status_code == 423

    admin = _bearer(await _login(client))
    users = (await client.get("/api/v1/users", headers=admin)).json()["items"]
    operator = next(u for u in users if u["email"] == "operator@test.local")
    assert operator["locked_until"] is not None
    reset = await client.post(
        f"/api/v1/users/{operator['id']}/reset-password",
        headers=admin,
        json={"password": "a-brand-new-password-1"},
    )
    assert reset.status_code == 200
    relogin = await _login(
        client, email="operator@test.local", password="a-brand-new-password-1"
    )
    assert relogin.status_code == 200

    log = (await client.get("/api/v1/audit", headers=admin)).json()["items"]
    actions = [e["action"] for e in log]
    assert "user.locked" in actions
    assert "user.reset_password" in actions


async def test_a_role_change_ends_the_accounts_sessions(client, db_session):
    await _admin(db_session)
    await _admin(db_session, email="second@test.local")
    admin = _bearer(await _login(client))
    second_login = await _login(client, email="second@test.local")
    second = _bearer(second_login)
    second_cookie = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    users = (await client.get("/api/v1/users", headers=admin)).json()["items"]
    target = next(u for u in users if u["email"] == "second@test.local")
    changed = await client.patch(
        f"/api/v1/users/{target['id']}", headers=admin, json={"role": "readonly"}
    )
    assert changed.status_code == 200

    # Both halves of the old session are dead: the access token and the cookie.
    assert (await client.get("/api/v1/auth/me", headers=second)).status_code == 401
    refresh = await client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: second_cookie}
    )
    assert refresh.status_code == 401


async def test_a_password_change_ends_the_refresh_cookie_too(client, db_session):
    await _admin(db_session)
    session = _bearer(await _login(client))
    cookie = client.cookies.get(settings.REFRESH_COOKIE_NAME)
    changed = await client.post(
        "/api/v1/auth/password",
        headers=session,
        json={"current_password": PASSWORD, "new_password": "another-long-password-2"},
    )
    assert changed.status_code == 204
    refresh = await client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: cookie}
    )
    assert refresh.status_code == 401
