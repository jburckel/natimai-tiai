"""Every administrative write leaves its trace, with its source address
(require TIAI_TEST_DATABASE_URL)."""

from tests.test_api_console import _admin_headers, _enroll


async def _log(client, headers) -> list[dict]:
    return (await client.get("/api/v1/audit", headers=headers)).json()["items"]


async def test_account_management_is_traced(client, db_session):
    headers = await _admin_headers(client, db_session)
    created = await client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "New.Operator@Test.Local",
            "password": "a-long-enough-password",
            "role": "readonly",
        },
    )
    assert created.status_code == 201, created.text
    user = created.json()
    # Stored lower-case, whatever the case it was typed in.
    assert user["email"] == "new.operator@test.local"

    await client.patch(
        f"/api/v1/users/{user['id']}", headers=headers, json={"role": "admin"}
    )
    await client.delete(f"/api/v1/users/{user['id']}", headers=headers)

    log = await _log(client, headers)
    by_action = {e["action"]: e for e in log}
    assert by_action["user.create"]["details"]["email"] == "new.operator@test.local"
    assert by_action["user.update"]["details"]["changes"] == {
        "role": {"from": "readonly", "to": "admin"}
    }
    assert by_action["user.delete"]["resource_id"] == user["id"]
    assert all(e["ip"] for e in log)
    # The password never reaches the trail.
    assert "a-long-enough-password" not in str(log)


async def test_an_update_that_changes_nothing_leaves_no_entry(client, db_session):
    headers = await _admin_headers(client, db_session)
    me = (await client.get("/api/v1/auth/me", headers=headers)).json()
    await client.patch(
        f"/api/v1/users/{me['id']}", headers=headers, json={"full_name": None}
    )
    assert not [e for e in await _log(client, headers) if e["action"] == "user.update"]


async def test_a_merge_is_traced_with_the_source_it_deleted(client, db_session):
    headers = await _admin_headers(client, db_session)
    kept = await _enroll(client, "m-merge-kept", hostname="PC-KEPT")
    gone = await _enroll(client, "m-merge-gone", hostname="PC-GONE")
    merged = await client.post(
        f"/api/v1/machines/{kept['machine_id']}/merge",
        headers=headers,
        json={"source_id": gone["machine_id"]},
    )
    assert merged.status_code == 200, merged.text

    entry = next(
        e for e in await _log(client, headers) if e["action"] == "machine.merge"
    )
    assert entry["resource_id"] == kept["machine_id"]
    assert entry["details"]["source_hostname"] == "PC-GONE"
    assert entry["details"]["source_machine_uuid"] == "m-merge-gone"
    assert entry["ip"]
