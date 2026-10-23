"""What an agent reports is bounded before it reaches a column (no database)."""

import pytest
from pydantic import ValidationError

from app.api.routes.agent import (
    MACHINE_UUID_MAX,
    MAX_THREATS,
    TEXT_MAX,
    EnrollRequest,
    HeartbeatRequest,
)
from app.features.threat.schemas import EXTRA_MAX_BYTES, ThreatReport


def test_heartbeat_strings_are_cut_not_refused():
    """A hostile hostname costs its tail, never the heartbeat."""
    report = HeartbeatRequest.model_validate(
        {
            "hostname": "H" * 10_000,
            "session": {"user_present": True, "username": "u" * 10_000},
            "defender": {"running_mode": "m" * 10_000},
            "fingerprint": {"smbios_uuid": "s" * 10_000},
        }
    )
    assert report.hostname == "H" * TEXT_MAX
    assert report.session is not None and len(report.session.username or "") == TEXT_MAX
    assert report.defender is not None
    assert len(report.defender.running_mode or "") == TEXT_MAX
    assert report.fingerprint is not None
    assert len(report.fingerprint.smbios_uuid or "") == TEXT_MAX


def test_heartbeat_keeps_at_most_max_threats():
    """The excess is dropped; the rest of the heartbeat still lands."""
    threats = [{"detection_id": str(i)} for i in range(MAX_THREATS + 50)]
    report = HeartbeatRequest.model_validate({"hostname": "PC", "threats": threats})
    assert len(report.threats) == MAX_THREATS
    assert report.hostname == "PC"


def test_threat_extras_are_kept_within_budget_and_dropped_beyond():
    """Unknown fields survive into ``raw`` — up to their budget."""
    small = ThreatReport.model_validate({"detection_id": "1", "process": "a.exe"})
    assert small.model_dump()["process"] == "a.exe"

    big = ThreatReport.model_validate(
        {"detection_id": "2", "threat_name": "T" * 500, "blob": "x" * EXTRA_MAX_BYTES}
    )
    dumped = big.model_dump()
    assert "blob" not in dumped
    assert dumped["detection_id"] == "2"
    assert len(dumped["threat_name"]) == 200


def test_enroll_refuses_an_oversized_machine_uuid():
    """The identity key is refused rather than cut: two cut keys could collide."""
    with pytest.raises(ValidationError):
        EnrollRequest.model_validate({"machine_uuid": "u" * (MACHINE_UUID_MAX + 1)})
    with pytest.raises(ValidationError):
        EnrollRequest.model_validate({"machine_uuid": ""})
