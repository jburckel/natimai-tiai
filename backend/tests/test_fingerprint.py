from app.features.machine.fingerprint import is_suspicious_change, store_fingerprint
from app.features.machine.models import Machine


def _machine(**kwargs) -> Machine:
    return Machine(machine_uuid="machine-1", **kwargs)


def test_first_fingerprint_is_not_suspicious():
    """A machine with no stored anchor accepts its first fingerprint."""
    m = _machine()
    assert not is_suspicious_change(m, smbios_uuid="smbios-a", tpm_ek_hash=None)


def test_identical_anchor_is_not_suspicious():
    m = _machine(smbios_uuid="smbios-a", tpm_ek_hash="tpm-a")
    assert not is_suspicious_change(m, smbios_uuid="smbios-a", tpm_ek_hash="tpm-a")


def test_smbios_change_is_suspicious():
    """A changed SMBIOS anchor signals a hardware swap / clone."""
    m = _machine(smbios_uuid="smbios-a")
    assert is_suspicious_change(m, smbios_uuid="smbios-b", tpm_ek_hash=None)


def test_tpm_change_is_suspicious():
    m = _machine(tpm_ek_hash="tpm-a")
    assert is_suspicious_change(m, smbios_uuid=None, tpm_ek_hash="tpm-b")


def test_store_updates_only_provided_components():
    """store_fingerprint leaves unprovided (None) components untouched."""
    m = _machine(machine_guid="guid-1", smbios_uuid="smbios-1")
    store_fingerprint(m, machine_guid=None, smbios_uuid="smbios-2", tpm_ek_hash="tpm-1")
    assert m.machine_guid == "guid-1"  # not overwritten by None
    assert m.smbios_uuid == "smbios-2"
    assert m.tpm_ek_hash == "tpm-1"


def test_store_sets_all_provided_components():
    m = _machine()
    store_fingerprint(
        m, machine_guid="guid-9", smbios_uuid="smbios-9", tpm_ek_hash="tpm-9"
    )
    assert m.machine_guid == "guid-9"
    assert m.smbios_uuid == "smbios-9"
    assert m.tpm_ek_hash == "tpm-9"
