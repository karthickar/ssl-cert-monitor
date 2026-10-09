import logging
import smtplib
from email.message import EmailMessage

import httpx

from src.config import get_settings

logger = logging.getLogger(__name__)


def send_webhook_alert(webhook_url: str | None, payload: dict) -> bool:
    """Deliver an alert webhook; with no URL, log it for local development."""
    if not webhook_url:
        logger.warning("SSL certificate alert (no webhook configured): %s", payload)
        return False
    try:
        response = httpx.post(webhook_url, json=payload, timeout=5.0)
        response.raise_for_status()
        return True
    except httpx.HTTPError as error:
        logger.error("Could not deliver alert webhook: %s", error)
        return False


def send_email_alert(recipient_emails: list[str], payload: dict) -> bool:
    """Send an expiry alert through configured SMTP; credentials remain in environment variables."""
    settings = get_settings()
    if not recipient_emails:
        return False
    if not settings.smtp_host or not settings.smtp_from_email:
        logger.warning("Email recipients are configured but SMTP_HOST or SMTP_FROM_EMAIL is missing")
        return False
    message = EmailMessage()
    message["Subject"] = f"SSL alert: {payload['name']} expires in {payload['days_remaining']} day(s)"
    message["From"] = settings.smtp_from_email
    message["To"] = ", ".join(recipient_emails)
    message.set_content(
        f"The certificate for {payload['name']} ({payload.get('hostname') or 'uploaded certificate'}) "
        f"expires at {payload['expires_at']} ({payload['days_remaining']} day(s) remaining)."
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
            if settings.smtp_use_tls:
                client.starttls()
            if settings.smtp_username and settings.smtp_password:
                client.login(settings.smtp_username, settings.smtp_password)
            client.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as error:
        logger.error("Could not deliver alert email: %s", error)
        return False


def send_alerts(webhook_url: str | None, recipient_emails: list[str], payload: dict) -> dict[str, bool]:
    """Deliver the same alert to every configured destination."""
    return {
        "webhook": send_webhook_alert(webhook_url, payload) if webhook_url else False,
        "email": send_email_alert(recipient_emails, payload),
    }
