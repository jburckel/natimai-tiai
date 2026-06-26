"""Console endpoint integration tests (require TIAI_TEST_DATABASE_URL).

Covers M3: broadcast commands, command expiry, is_up_to_date computation, stats
overview, machine status filtering, threat listing, and token revocation.
"""

from datetime import timedelta


async def _admin_headers(client, db_session) -> dict[str, str]:
    from app.features.user import crud
    from app.features.user.models import Role

    await crud.create_user(
        db_session, email="admin@test.local", password="pw", role=Role.ADMIN
    )
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin@test.local", "password": "pw"},
    )
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _readonly_headers(client, db_session) -> dict[str, str]:
    from app.features.user import crud
    from app.features.user.models import Role

    await crud.create_user(
        db_session, email="ro@test.local", password="pw", role=Role.READONLY
    )
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "ro@test.local", "password": "pw"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _enroll(client, machine_uuid: str, **fields) -> dict:
    from app.core.config import settings

    resp = await client.post(
        "/api/v1/agent/enroll",
        headers={"X-Enrollment-Secret": settings.ENROLLMENT_SECRET},
        json={"machine_uuid": machine_uuid, **fields},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _heartbeat(client, token: str, **body):
    return await client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )


# --- Broadcast commands ----------------------------------------------------


async def test_broadcast_targets_all_machines(client, db_session):
    headers = await _admin_headers(client, db_session)
    await _enroll(client, "m-all-1")
    await _enroll(client, "m-all-2")

    resp = await client.post(
        "/api/v1/commands",
        headers=headers,
        json={"type": "quick_scan", "target_all": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["count"] == 2


async def test_broadcast_by_domain(client, db_session):
    headers = await _admin_headers(client, db_session)
    await _enroll(client, "m-dom-1", domain="CORP")
    await _enroll(client, "m-dom-2", domain="OTHER")

    resp = await client.post(
        "/api/v1/commands",
        headers=headers,
        json={"type": "full_scan", "target_domain": "CORP"},
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


async def test_create_requires_exactly_one_target(client, db_session):
    headers = await _admin_headers(client, db_session)
    resp = await client.post(
        "/api/v1/commands",
        headers=headers,
        json={"type": "quick_scan"},  # no target
    )
    assert resp.status_code == 422


async def test_create_command_forbidden_for_readonly(client, db_session):
    headers = await _readonly_headers(client, db_session)
    resp = await client.post(
        "/api/v1/commands",
        headers=headers,
        json={"type": "quick_scan", "target_all": True},
    )
    assert resp.status_code == 403


# --- Command expiry --------------------------------------------------------


async def test_mark_expired_sweeps_stale_pending(client, db_session):
    from sqlmodel import select

    from app.features.base import utcnow
    from app.features.command import crud
    from app.features.command.models import Command, CommandStatus
    from app.features.machine.models import Machine

    machine = Machine(machine_uuid="m-expire")
    db_session.add(machine)
    await db_session.commit()
    await db_session.refresh(machine)

    stale = Command(
        machine_id=machine.id,
        type="quick_scan",
        expires_at=utcnow() - timedelta(minutes=5),
    )
    stale_id = stale.id  # capture before commit expires the instance attributes
    db_session.add(stale)
    await db_session.commit()

    n = await crud.mark_expired(db_session)
    await db_session.commit()
    assert n == 1

    refreshed = (
        await db_session.exec(select(Command).where(Command.id == stale_id))
    ).one()
    assert refreshed.status == CommandStatus.EXPIRED


# --- Freshness + stats -----------------------------------------------------


async def test_heartbeat_computes_is_up_to_date(client, db_session):
    headers = await _admin_headers(client, db_session)
    enrolled = await _enroll(client, "m-fresh")
    token = enrolled["token"]
    machine_id = enrolled["machine_id"]

    # Protected + fresh signatures → up to date.
    await _heartbeat(
        client,
        token,
        defender={
            "av_enabled": True,
            "rtp_enabled": True,
            "signature_age_days": 1,
        },
    )
    resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert resp.json()["is_up_to_date"] is True

    # Stale signatures (older than the 3-day default) → not up to date.
    await _heartbeat(
        client,
        token,
        defender={
            "av_enabled": True,
            "rtp_enabled": True,
            "signature_age_days": 30,
        },
    )
    resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert resp.json()["is_up_to_date"] is False


async def test_stats_overview_and_status_filter(client, db_session):
    headers = await _admin_headers(client, db_session)

    fresh = await _enroll(client, "m-stat-fresh")
    await _heartbeat(
        client,
        fresh["token"],
        defender={"av_enabled": True, "rtp_enabled": True, "signature_age_days": 1},
        threats=[{"detection_id": "DET-A", "threat_name": "X", "status": "active"}],
    )

    stale = await _enroll(client, "m-stat-stale")
    await _heartbeat(
        client,
        stale["token"],
        defender={"av_enabled": False, "rtp_enabled": False},
    )

    resp = await client.get("/api/v1/stats/overview", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["up_to_date"] == 1
    assert body["outdated"] == 1
    assert body["with_active_threats"] == 1

    # Status filter on the machine list.
    up = await client.get("/api/v1/machines?status=up_to_date", headers=headers)
    assert [m["machine_uuid"] for m in up.json()["items"]] == ["m-stat-fresh"]

    outdated = await client.get("/api/v1/machines?status=outdated", headers=headers)
    assert [m["machine_uuid"] for m in outdated.json()["items"]] == ["m-stat-stale"]


# --- Threats listing -------------------------------------------------------


async def test_threats_listing_and_severity_filter(client, db_session):
    headers = await _admin_headers(client, db_session)
    enrolled = await _enroll(client, "m-threats")
    await _heartbeat(
        client,
        enrolled["token"],
        threats=[
            {
                "detection_id": "T-1",
                "threat_name": "EICAR",
                "severity": "high",
                "status": "active",
            },
            {
                "detection_id": "T-2",
                "threat_name": "Low",
                "severity": "low",
                "status": "removed",
            },
        ],
    )

    resp = await client.get("/api/v1/threats", headers=headers)
    assert resp.json()["total"] == 2

    high = await client.get("/api/v1/threats?severity=high", headers=headers)
    items = high.json()["items"]
    assert len(items) == 1 and items[0]["detection_id"] == "T-1"


# --- Token revocation ------------------------------------------------------


async def test_revoke_token_blocks_agent(client, db_session):
    headers = await _admin_headers(client, db_session)
    enrolled = await _enroll(client, "m-revoke")
    token = enrolled["token"]

    # Token works before revocation.
    assert (await _heartbeat(client, token)).status_code == 200

    resp = await client.post(
        f"/api/v1/machines/{enrolled['machine_id']}/revoke-token", headers=headers
    )
    assert resp.status_code == 200

    # Rejected after revocation.
    assert (await _heartbeat(client, token)).status_code == 401

    # Re-enrollment issues a fresh token and clears the flag.
    re = await _enroll(client, "m-revoke")
    assert (await _heartbeat(client, re["token"])).status_code == 200
