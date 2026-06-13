"""Minimal Mailgun client for alert e-mails (first alert channel)."""

import httpx

from app.core.config import settings


async def send_email(subject: str, text: str, to: list[str] | None = None) -> bool:
    """Send a plain-text e-mail via the Mailgun API.

    Returns False (no-op) when Mailgun is not configured.
    """
    if not settings.alerts_enabled:
        return False

    recipients = to or list(settings.ALERT_RECIPIENTS)
    if not recipients:
        return False

    from_name = settings.MAILGUN_FROM_NAME or settings.PROJECT_NAME
    sender = f"{from_name} <{settings.MAILGUN_FROM_EMAIL}>"
    url = f"{settings.MAILGUN_API_BASE_URL}/{settings.MAILGUN_DOMAIN}/messages"

    async with httpx.AsyncClient(timeout=settings.MAILGUN_TIMEOUT_SECONDS) as client:
        resp = await client.post(
            url,
            auth=("api", settings.MAILGUN_API_KEY or ""),
            data={
                "from": sender,
                "to": recipients,
                "subject": subject,
                "text": text,
            },
        )
        resp.raise_for_status()
    return True
