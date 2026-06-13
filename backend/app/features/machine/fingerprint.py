"""Identity fingerprint diffing.

The machine is looked up by its stable identity (machine_uuid / token). The
fingerprint *components* are stored separately so we can apply per-attribute
rules rather than a binary hash:

- hostname / domain / machine_guid drift  -> benign (rename, OS re-image), update silently
- smbios_uuid or tpm_ek_hash drift         -> suspicious (hardware swap, clone, token theft)

A suspicious delta sets ``needs_verification`` (sticky until an admin clears it).
"""

from app.features.machine.models import Machine


def is_suspicious_change(
    machine: Machine, *, smbios_uuid: str | None, tpm_ek_hash: str | None
) -> bool:
    """Whether the reported anchor differs from what was recorded."""
    if machine.smbios_uuid and smbios_uuid and machine.smbios_uuid != smbios_uuid:
        return True
    if machine.tpm_ek_hash and tpm_ek_hash and machine.tpm_ek_hash != tpm_ek_hash:
        return True
    return False


def store_fingerprint(
    machine: Machine,
    *,
    machine_guid: str | None,
    smbios_uuid: str | None,
    tpm_ek_hash: str | None,
) -> None:
    """Update the stored fingerprint components with the latest reported values."""
    if machine_guid is not None:
        machine.machine_guid = machine_guid
    if smbios_uuid is not None:
        machine.smbios_uuid = smbios_uuid
    if tpm_ek_hash is not None:
        machine.tpm_ek_hash = tpm_ek_hash
