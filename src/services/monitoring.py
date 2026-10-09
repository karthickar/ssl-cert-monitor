import logging
import ssl
from datetime import datetime

from sqlalchemy.orm import Session

from src.config import get_settings
from src.libutil.alerts import send_alerts
from src.libutil.certificates import CertificateDetails, fetch_server_certificate, inspect_pem_certificate
from src.models import AlertConfig, Monitor

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
        config = get_alert_config(db)
        if monitor.alert_enabled and details.days_remaining <= config.expiration_threshold_days:
            monitor.status = "expiring_soon" if details.days_remaining >= 0 else "expired"
            send_alerts(config.webhook_url, recipient_emails(config), {
                "event": "certificate_expiring",
                "monitor_id": monitor.id,
                "name": monitor.name,
                "hostname": monitor.hostname,
                "expires_at": details.expires_at.isoformat(),
                "days_remaining": details.days_remaining,
            })
    except (OSError, ValueError, ssl.SSLError) as error:  # type: ignore[name-defined]
        logger.info("Certificate check failed for monitor %s: %s", monitor.id, error)
        monitor.status = "error"
        monitor.last_error = str(error)
        monitor.last_checked_at = datetime.utcnow()
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor
