"""Unit tests for the up-to-date computation (no database)."""

from app.features.machine.status import compute_is_up_to_date

MAX_AGE = 3


def test_protected_with_fresh_signatures_is_up_to_date():
    assert compute_is_up_to_date(
        av_enabled=True, rtp_enabled=True, signature_age_days=1, max_age_days=MAX_AGE
    )


def test_boundary_age_is_up_to_date():
    assert compute_is_up_to_date(
        av_enabled=True,
        rtp_enabled=True,
        signature_age_days=MAX_AGE,
        max_age_days=MAX_AGE,
    )


def test_stale_signatures_not_up_to_date():
    assert not compute_is_up_to_date(
        av_enabled=True, rtp_enabled=True, signature_age_days=10, max_age_days=MAX_AGE
    )


def test_protection_off_not_up_to_date():
    assert not compute_is_up_to_date(
        av_enabled=False, rtp_enabled=True, signature_age_days=0, max_age_days=MAX_AGE
    )
    assert not compute_is_up_to_date(
        av_enabled=True, rtp_enabled=False, signature_age_days=0, max_age_days=MAX_AGE
    )


def test_unknown_data_not_up_to_date():
    assert not compute_is_up_to_date(
        av_enabled=None, rtp_enabled=None, signature_age_days=None, max_age_days=MAX_AGE
    )
    assert not compute_is_up_to_date(
        av_enabled=True, rtp_enabled=True, signature_age_days=None, max_age_days=MAX_AGE
    )
