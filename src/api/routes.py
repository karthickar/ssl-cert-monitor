import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.libutil.alerts import send_alerts
from src.libutil.certificates import inspect_pem_certificate
from src.libutil.urls import parse_target
from src.models import AlertConfig, Monitor
from src.schemas import AlertConfigResponse, AlertConfigUpdate, MonitorAlertUpdate, MonitorResponse, URLMonitorCreate
from src.services.monitoring import check_monitor, get_alert_config, recipient_emails

router = APIRouter(prefix="/api/v1")
logger = logging.getLogger(__name__)


def _monitor_or_404(monitor_id: int, db: Session) -> Monitor:
    monitor = db.get(Monitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return monitor


@router.post("/monitors/url", response_model=MonitorResponse, status_code=status.HTTP_201_CREATED)
def create_url_monitor(payload: URLMonitorCreate, db: Session = Depends(get_db)):
    try:
        hostname, port = parse_target(payload.url, payload.port)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    monitor = Monitor(name=payload.name, kind="url", hostname=hostname, port=port,
                      location=payload.location, alert_enabled=payload.alert_enabled)
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return check_monitor(db, monitor)


@router.post("/monitors/certificate", response_model=MonitorResponse, status_code=status.HTTP_201_CREATED)
async def upload_certificate_monitor(name: str, location: str | None = None, alert_enabled: bool = True,
                                     certificate: UploadFile = File(...), db: Session = Depends(get_db)):
    if not certificate.filename:
        raise HTTPException(status_code=422, detail="A certificate file is required")
    content = await certificate.read()
    if len(content) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Certificate file must be at most 1 MB")
    try:
        pem, _ = inspect_pem_certificate(content)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    monitor = Monitor(name=name, kind="uploaded_certificate", certificate_pem=pem,
                      location=location, alert_enabled=alert_enabled)
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return check_monitor(db, monitor)


@router.get("/monitors", response_model=list[MonitorResponse])
def list_monitors(db: Session = Depends(get_db)):
    return db.query(Monitor).order_by(Monitor.id.desc()).all()


@router.get("/monitors/{monitor_id}", response_model=MonitorResponse)
def get_monitor(monitor_id: int, db: Session = Depends(get_db)):
    return _monitor_or_404(monitor_id, db)


@router.post("/monitors/{monitor_id}/check", response_model=MonitorResponse)
def check_single_monitor(monitor_id: int, db: Session = Depends(get_db)):
    return check_monitor(db, _monitor_or_404(monitor_id, db))


@router.patch("/monitors/{monitor_id}/alert", response_model=MonitorResponse)
def update_monitor_alert(monitor_id: int, payload: MonitorAlertUpdate, db: Session = Depends(get_db)):
    monitor = _monitor_or_404(monitor_id, db)
    monitor.alert_enabled = payload.alert_enabled
    db.commit()
    db.refresh(monitor)
    return monitor


@router.delete("/monitors/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_monitor(monitor_id: int, db: Session = Depends(get_db)):
    db.delete(_monitor_or_404(monitor_id, db))
    db.commit()


@router.get("/alert-config", response_model=AlertConfigResponse)
def read_alert_config(db: Session = Depends(get_db)):
    config = get_alert_config(db)
    return AlertConfigResponse(expiration_threshold_days=config.expiration_threshold_days,
                               webhook_url=config.webhook_url, recipient_emails=recipient_emails(config))


@router.put("/alert-config", response_model=AlertConfigResponse)
def update_alert_config(payload: AlertConfigUpdate, db: Session = Depends(get_db)):
    config = get_alert_config(db)
    config.expiration_threshold_days = payload.expiration_threshold_days
    config.webhook_url = str(payload.webhook_url) if payload.webhook_url else None
    config.recipient_emails = ",".join(payload.recipient_emails)
    db.commit()
    db.refresh(config)
    return AlertConfigResponse(expiration_threshold_days=config.expiration_threshold_days,
                               webhook_url=config.webhook_url, recipient_emails=recipient_emails(config))


@router.post("/alert-config/test")
def test_alert(db: Session = Depends(get_db)):
    config = get_alert_config(db)
    delivered = send_alerts(config.webhook_url, recipient_emails(config), {
        "event": "ssl_monitor_test", "name": "Test certificate", "hostname": "example.internal",
        "expires_at": "test", "days_remaining": 7,
    })
    return {"delivered": delivered, "message": "Check application logs if no delivery channel is configured"}
