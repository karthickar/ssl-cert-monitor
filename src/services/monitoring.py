import logging
import ssl
from datetime import datetime

from sqlalchemy.orm import Session

from src.config import get_settings
from src.database import SessionLocal
from src.libutil.alerts import send_alerts
from src.libutil.certificates import CertificateDetails, fetch_server_certificate, inspect_pem_certificate
from src.models import AlertConfig, Monitor, User
from src.schemas import MonitorResponse

logger = logging.getLogger(__name__)


def get_alert_config(db: Session) -> AlertConfig:
    config = db.get(AlertConfig, 1)
    if not config:
        config = AlertConfig(id=1, expiration_threshold_days=get_settings().default_expiry_threshold_days,
                            webhook_url=get_settings().default_webhook_url)
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def recipient_emails(config: AlertConfig) -> list[str]:
    return [email for email in config.recipient_emails.split(",") if email]


def alert_milestones(threshold: int | None) -> set[int]:
    """Notify when remaining days match the saved threshold, plus 7 days and 1 day before expiry."""
    points = {1, 7}
    if threshold and threshold > 0:
        points.add(threshold)
    return points


def should_send_expiry_alert(days_remaining: int, threshold: int | None, last_alerted_days: int | None) -> bool:
    """Send once for each milestone: configured threshold, 7 days, and 1 day remaining."""
    if days_remaining < 0:
        return last_alerted_days != -1
    if days_remaining in alert_milestones(threshold):
        return last_alerted_days != days_remaining
    return False


def _apply_details(monitor: Monitor, details: CertificateDetails) -> None:
    monitor.subject = details.subject
    monitor.issuer = details.issuer
    monitor.serial_number = details.serial_number
    monitor.expires_at = details.expires_at
    monitor.days_remaining = details.days_remaining
    monitor.last_checked_at = datetime.utcnow()
    monitor.last_error = None
    monitor.status = "expired" if details.days_remaining < 0 else "healthy"


def check_monitor(db: Session, monitor: Monitor) -> Monitor:
    """Inspect the target and persist its latest outcome. Network failures do not delete monitors."""
    try:
        if monitor.kind == "url":
            details = fetch_server_certificate(monitor.hostname or "", monitor.port or 443,
                                               get_settings().check_timeout_seconds)
        else:
            _, details = inspect_pem_certificate((monitor.certificate_pem or "").encode())
        _apply_details(monitor, details)
        threshold = monitor.alert_threshold_days or get_alert_config(db).expiration_threshold_days
        if details.days_remaining <= threshold:
            monitor.status = "expiring_soon" if details.days_remaining >= 0 else "expired"
        if monitor.alert_enabled and should_send_expiry_alert(details.days_remaining, threshold, monitor.last_alerted_days):
            emails = [email for email in (monitor.alert_recipient_emails or "").split(",") if email]
            webhook = monitor.alert_webhook_url
            if not emails or not webhook:
                fallback = get_alert_config(db)
                emails = emails or recipient_emails(fallback)
                webhook = webhook or fallback.webhook_url
            payload = {
                "event": "certificate_expiring",
                "monitor_id": monitor.id,
                "name": monitor.name,
                "hostname": monitor.hostname,
                "kind": monitor.kind,
                "expires_at": details.expires_at.isoformat(),
                "days_remaining": details.days_remaining,
                "alert_threshold_days": threshold,
                "validity_days": details.days_remaining,
            }
            delivered = send_alerts(webhook, emails, payload)
            monitor.last_alerted_days = -1 if details.days_remaining < 0 else details.days_remaining
            logger.info("Expiry alert sent for monitor %s at %s days remaining (email=%s webhook=%s)",
                        monitor.id, details.days_remaining, delivered["email"], delivered["webhook"])
    except (OSError, ValueError, ssl.SSLError) as error:  # type: ignore[name-defined]
        logger.info("Certificate check failed for monitor %s: %s", monitor.id, error)
        monitor.status = "error"
        monitor.last_error = str(error)
        monitor.last_checked_at = datetime.utcnow()
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor


def check_all_monitors() -> int:
    """Refresh every stored monitor so dashboard validity stays current."""
    db = SessionLocal()
    try:
        monitors = db.query(Monitor).order_by(Monitor.id.asc()).all()
        for monitor in monitors:
            check_monitor(db, monitor)
        logger.info("Daily certificate refresh completed for %s monitors", len(monitors))
        return len(monitors)
    finally:
        db.close()


def can_manage_monitor(monitor: Monitor, user: User | None) -> bool:
    return True


def serialize_monitor(monitor: Monitor, user: User | None = None) -> MonitorResponse:
    return MonitorResponse.model_validate(monitor).model_copy(update={
        "owner_email": get_settings().default_monitor_owner,
        "can_manage": True,
    })
