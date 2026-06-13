"""Agent endpoint integration tests (require TIAI_TEST_DATABASE_URL)."""


async def test_enroll_then_heartbeat(client):
    """A machine enrolls with the shared secret, then heartbeats with its token."""
    from app.core.config import settings

    enroll = await client.post(
        "/api/v1/agent/enroll",
        headers={"X-Enrollment-Secret": settings.ENROLLMENT_SECRET},
        json={"machine_uuid": "machine-1", "fingerprint": {"smbios_uuid": "smbios-1"}},
    )
    assert enroll.status_code == 200
    token = enroll.json()["token"]
    assert token

    hb = await client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"agent_version": "test", "fingerprint": {"smbios_uuid": "smbios-1"}},
    )
    assert hb.status_code == 200
    assert hb.json()["commands"] == []


async def test_enroll_rejects_bad_secret(client):
    """Enrollment fails without the correct shared secret."""
    resp = await client.post(
        "/api/v1/agent/enroll",
        headers={"X-Enrollment-Secret": "wrong"},
        json={"machine_uuid": "machine-2"},
    )
    assert resp.status_code == 401


async def test_heartbeat_requires_token(client):
    """Heartbeat without a bearer token is rejected."""
    resp = await client.post("/api/v1/agent/heartbeat", json={"agent_version": "x"})
    assert resp.status_code == 401
