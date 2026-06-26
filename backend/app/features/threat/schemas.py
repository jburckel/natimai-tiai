from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ThreatReport(BaseModel):
    """A Defender detection as reported by the agent on a heartbeat.

    Unknown fields are preserved (``extra='allow'``) and kept in the row's
    ``raw`` JSONB column.
    """

    model_config = ConfigDict(extra="allow")

    detection_id: str | None = None
    threat_name: str | None = None
    severity: str | None = None
    category: str | None = None
    status: str | None = None
    action_taken: str | None = None
    detected_at: datetime | None = None
