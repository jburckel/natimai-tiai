import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# Bounds on what one reported detection can write to its columns and to the
# console. A threat name ("Trojan:Win32/Wacatac.B!ml") runs to ~40 characters.
TEXT_MAX = 200
# Budget for the fields this schema does not know, kept in the ``raw`` JSONB
# column. A real detection carries a few hundred bytes of extras (resources,
# process name); past this budget they are dropped, the known fields kept.
EXTRA_MAX_BYTES = 8 * 1024


class ThreatReport(BaseModel):
    """A Defender detection as reported by the agent on a heartbeat.

    Unknown fields are preserved (``extra='allow'``) and kept in the row's
    ``raw`` JSONB column, within ``EXTRA_MAX_BYTES``.
    """

    model_config = ConfigDict(extra="allow")

    detection_id: str | None = None
    threat_name: str | None = None
    severity: str | None = None
    category: str | None = None
    status: str | None = None
    action_taken: str | None = None
    detected_at: datetime | None = None

    @field_validator(
        "detection_id", "threat_name", "severity", "category", "status", "action_taken"
    )
    @classmethod
    def _bound_text(cls, value: str | None) -> str | None:
        """Cap a reported string — never 422: one long field must not cost the
        detection, nor the heartbeat it rides in."""
        if value is None:
            return None
        return value[:TEXT_MAX]

    @model_validator(mode="after")
    def _bound_extras(self) -> "ThreatReport":
        """Drop the unknown fields when they outgrow their budget."""
        extra: dict[str, Any] | None = self.__pydantic_extra__
        if extra and len(json.dumps(extra, default=str)) > EXTRA_MAX_BYTES:
            extra.clear()
        return self
